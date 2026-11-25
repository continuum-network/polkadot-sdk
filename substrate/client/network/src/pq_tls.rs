// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! libp2p TLS 1.3 security upgrade restricted to hybrid post-quantum key exchange.
//!
//! The wire protocol (`/tls/1.0.0`, ALPN `libp2p`, one self-signed certificate whose libp2p
//! extension is signed by the node identity key) is the libp2p TLS spec, and the identity
//! binding reuses `libp2p::tls::certificate` unchanged. `libp2p::tls::Config` hard-codes the
//! ring provider with classical key exchange, so the rustls configs are built here instead:
//! the aws-lc-rs (FIPS) provider is passed explicitly, only hybrid ML-KEM groups are offered
//! or accepted, and there is no fallback.

use futures::{future::BoxFuture, AsyncRead, AsyncWrite, FutureExt};
use libp2p::{
	core::{
		upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade},
		UpgradeInfo,
	},
	identity,
	tls::{certificate, TlsStream},
	PeerId,
};
use rustls::{
	client::{
		danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
		Resumption,
	},
	crypto::{aws_lc_rs, CryptoProvider, SupportedKxGroup},
	pki_types::{CertificateDer, PrivateKeyDer, ServerName, UnixTime},
	server::{
		danger::{ClientCertVerified, ClientCertVerifier},
		NoServerSessionStorage,
	},
	sign::{CertifiedKey, SingleCertAndKey},
	CertificateError, ClientConfig, CommonState, DigitallySignedStruct, DistinguishedName,
	OtherError, ServerConfig, SignatureScheme,
};
use std::{
	net::{IpAddr, Ipv4Addr},
	sync::Arc,
};

const LOG_TARGET: &str = "sub-libp2p::tls";

/// The only key exchange groups offered or accepted, in preference order.
pub(crate) static KX_GROUPS: &[&dyn SupportedKxGroup] =
	&[aws_lc_rs::kx_group::X25519MLKEM768, aws_lc_rs::kx_group::SECP256R1MLKEM768];

/// The explicit rustls provider: aws-lc-rs, TLS 1.3 AES-GCM suites, hybrid PQ groups only.
pub(crate) fn provider() -> CryptoProvider {
	CryptoProvider {
		cipher_suites: vec![
			aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384,
			aws_lc_rs::cipher_suite::TLS13_AES_128_GCM_SHA256,
		],
		kx_groups: KX_GROUPS.to_vec(),
		..aws_lc_rs::default_provider()
	}
}

/// Errors of the TLS security upgrade.
#[derive(Debug, thiserror::Error)]
pub enum UpgradeError {
	/// Generating the certificate failed.
	#[error("Failed to generate certificate: {0}")]
	CertificateGeneration(#[from] certificate::GenError),
	/// Building the rustls configuration failed.
	#[error("Failed to build TLS config: {0}")]
	Config(#[from] rustls::Error),
	/// The handshake failed (for instance, the peer offers no hybrid post-quantum group).
	#[error("TLS handshake failed: {0}")]
	Handshake(std::io::Error),
	/// The peer certificate is invalid.
	#[error("Invalid peer certificate: {0}")]
	BadCertificate(#[from] certificate::ParseError),
	/// The negotiated connection does not satisfy the security policy.
	#[error("TLS policy violation: {0}")]
	Policy(&'static str),
}

/// libp2p TLS security upgrade with hybrid post-quantum key exchange.
#[derive(Clone)]
pub struct Config {
	server: Arc<ServerConfig>,
	client: Arc<ClientConfig>,
}

impl Config {
	/// Creates a config whose certificate is bound to `identity`.
	pub fn new(identity: &identity::Keypair) -> Result<Self, UpgradeError> {
		let (cert, key) = certificate::generate(identity)?;
		Ok(Self::with_certificate(cert, key)?)
	}

	/// Creates a config presenting `cert`, which must be a libp2p TLS certificate for `key`.
	pub(crate) fn with_certificate(
		cert: CertificateDer<'static>,
		key: PrivateKeyDer<'static>,
	) -> Result<Self, rustls::Error> {
		Self::with_provider(cert, key, provider())
	}

	fn with_provider(
		cert: CertificateDer<'static>,
		key: PrivateKeyDer<'static>,
		provider: CryptoProvider,
	) -> Result<Self, rustls::Error> {
		let provider = Arc::new(provider);
		let verifier = Arc::new(Libp2pCertificateVerifier);
		// Not `with_single_cert`: webpki rejects the critical libp2p extension.
		let signing_key = provider.key_provider.load_private_key(key)?;
		let resolver = Arc::new(SingleCertAndKey::from(CertifiedKey::new(vec![cert], signing_key)));

		let mut server = ServerConfig::builder_with_provider(provider.clone())
			.with_protocol_versions(&[&rustls::version::TLS13])?
			.with_client_cert_verifier(verifier.clone())
			.with_cert_resolver(resolver.clone());
		server.alpn_protocols = vec![b"libp2p".to_vec()];
		// Always run a full handshake: no tickets, no session cache, no resumption.
		server.send_tls13_tickets = 0;
		server.session_storage = Arc::new(NoServerSessionStorage {});

		let mut client = ClientConfig::builder_with_provider(provider)
			.with_protocol_versions(&[&rustls::version::TLS13])?
			.dangerous()
			.with_custom_certificate_verifier(verifier)
			.with_client_cert_resolver(resolver);
		client.alpn_protocols = vec![b"libp2p".to_vec()];
		client.resumption = Resumption::disabled();

		Ok(Self { server: Arc::new(server), client: Arc::new(client) })
	}
}

impl UpgradeInfo for Config {
	type Info = &'static str;
	type InfoIter = std::iter::Once<Self::Info>;

	fn protocol_info(&self) -> Self::InfoIter {
		std::iter::once("/tls/1.0.0")
	}
}

impl<C> InboundConnectionUpgrade<C> for Config
where
	C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
	type Output = (PeerId, TlsStream<C>);
	type Error = UpgradeError;
	type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

	fn upgrade_inbound(self, socket: C, _: Self::Info) -> Self::Future {
		async move {
			let stream = futures_rustls::TlsAcceptor::from(self.server)
				.accept(socket)
				.await
				.map_err(|e| handshake_failed("inbound", e))?;
			let peer_id = authenticated_peer(stream.get_ref().1)?;
			Ok((peer_id, stream.into()))
		}
		.boxed()
	}
}

impl<C> OutboundConnectionUpgrade<C> for Config
where
	C: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
	type Output = (PeerId, TlsStream<C>);
	type Error = UpgradeError;
	type Future = BoxFuture<'static, Result<Self::Output, Self::Error>>;

	fn upgrade_outbound(self, socket: C, _: Self::Info) -> Self::Future {
		async move {
			// libp2p TLS spec: no SNI. An unspecified IP address disables the extension.
			let name = ServerName::IpAddress(IpAddr::V4(Ipv4Addr::UNSPECIFIED).into());
			let stream = futures_rustls::TlsConnector::from(self.client)
				.connect(name, socket)
				.await
				.map_err(|e| handshake_failed("outbound", e))?;
			let peer_id = authenticated_peer(stream.get_ref().1)?;
			Ok((peer_id, stream.into()))
		}
		.boxed()
	}
}

fn handshake_failed(direction: &str, e: std::io::Error) -> UpgradeError {
	log::debug!(
		target: LOG_TARGET,
		"Rejected {direction} TLS connection: {e} (TLS 1.3 with hybrid post-quantum key \
		 exchange X25519MLKEM768/SECP256R1MLKEM768 and a valid libp2p certificate required)",
	);
	UpgradeError::Handshake(e)
}

/// Returns the peer ID bound to the (already verified) certificate after checking the policy.
fn authenticated_peer(state: &CommonState) -> Result<PeerId, UpgradeError> {
	let group = state
		.negotiated_key_exchange_group()
		.ok_or(UpgradeError::Policy("no key exchange group negotiated"))?
		.name();
	// rustls only negotiates configured groups; re-checked so a config regression fails closed.
	if !KX_GROUPS.iter().any(|g| g.name() == group) {
		return Err(UpgradeError::Policy("non-hybrid key exchange group negotiated"));
	}
	let Some([cert]) = state.peer_certificates() else {
		return Err(UpgradeError::Policy("expected exactly one peer certificate"));
	};
	let peer_id = certificate::parse(cert)?.peer_id();
	log::debug!(target: LOG_TARGET, "TLS handshake with {peer_id} negotiated {group:?}");
	Ok(peer_id)
}

/// Verifies the libp2p TLS certificate of the remote, as `libp2p-tls` does. The expected peer
/// ID is checked by the swarm after the upgrade.
#[derive(Debug)]
struct Libp2pCertificateVerifier;

impl Libp2pCertificateVerifier {
	fn verify_presented_certs(
		end_entity: &CertificateDer,
		intermediates: &[CertificateDer],
	) -> Result<(), rustls::Error> {
		if !intermediates.is_empty() {
			return Err(rustls::Error::General(
				"libp2p-tls requires exactly one certificate".into(),
			));
		}
		// Checks validity, the self-signature and the identity-key signature of the extension.
		certificate::parse(end_entity).map_err(|e| {
			rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(e))))
		})?;
		Ok(())
	}

	fn verify_tls13(
		message: &[u8],
		cert: &CertificateDer,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		certificate::parse(cert)
			.map_err(|e| {
				rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(e))))
			})?
			.verify_signature(dss.scheme, message, dss.signature())
			.map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadSignature))?;
		Ok(HandshakeSignatureValid::assertion())
	}

	fn tls12_rejected() -> Result<HandshakeSignatureValid, rustls::Error> {
		Err(rustls::Error::General("TLS 1.2 is not supported".into()))
	}

	/// `libp2p::tls::certificate::generate` always uses an ECDSA P-256 certificate key.
	fn schemes() -> Vec<SignatureScheme> {
		vec![SignatureScheme::ECDSA_NISTP256_SHA256]
	}
}

impl ServerCertVerifier for Libp2pCertificateVerifier {
	fn verify_server_cert(
		&self,
		end_entity: &CertificateDer,
		intermediates: &[CertificateDer],
		_server_name: &ServerName,
		_ocsp_response: &[u8],
		_now: UnixTime,
	) -> Result<ServerCertVerified, rustls::Error> {
		Self::verify_presented_certs(end_entity, intermediates)?;
		Ok(ServerCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		_: &[u8],
		_: &CertificateDer,
		_: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		Self::tls12_rejected()
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		Self::verify_tls13(message, cert, dss)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		Self::schemes()
	}
}

impl ClientCertVerifier for Libp2pCertificateVerifier {
	fn offer_client_auth(&self) -> bool {
		true
	}

	fn client_auth_mandatory(&self) -> bool {
		true
	}

	fn root_hint_subjects(&self) -> &[DistinguishedName] {
		&[]
	}

	fn verify_client_cert(
		&self,
		end_entity: &CertificateDer,
		intermediates: &[CertificateDer],
		_now: UnixTime,
	) -> Result<ClientCertVerified, rustls::Error> {
		Self::verify_presented_certs(end_entity, intermediates)?;
		Ok(ClientCertVerified::assertion())
	}

	fn verify_tls12_signature(
		&self,
		_: &[u8],
		_: &CertificateDer,
		_: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		Self::tls12_rejected()
	}

	fn verify_tls13_signature(
		&self,
		message: &[u8],
		cert: &CertificateDer,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		Self::verify_tls13(message, cert, dss)
	}

	fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
		Self::schemes()
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::transport::build_transport;
	use libp2p::{
		core::{
			muxing::StreamMuxerBox,
			transport::{Boxed, DialOpts, ListenerId, MemoryTransport, PortUse, TransportEvent},
			upgrade, Endpoint,
		},
		identity::Keypair,
		noise, Multiaddr, Transport,
	};
	use rustls::pki_types::PrivatePkcs8KeyDer;
	use std::pin::Pin;

	const PROTO: &str = "/tls/1.0.0";

	fn mldsa() -> Keypair {
		Keypair::generate_mldsa65()
	}

	/// Runs a server and a client upgrade against each other over a local TCP socket pair.
	async fn handshake<S, C>(
		server: S,
		client: C,
	) -> (Result<S::Output, S::Error>, Result<C::Output, C::Error>)
	where
		S: InboundConnectionUpgrade<libp2p::tcp::tokio::TcpStream, Info = &'static str>,
		C: OutboundConnectionUpgrade<libp2p::tcp::tokio::TcpStream, Info = &'static str>,
	{
		let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
		let addr = listener.local_addr().unwrap();
		let (accepted, dialed) =
			futures::join!(listener.accept(), tokio::net::TcpStream::connect(addr));
		let server_io = libp2p::tcp::tokio::TcpStream(accepted.unwrap().0);
		let client_io = libp2p::tcp::tokio::TcpStream(dialed.unwrap());
		futures::join!(
			server.upgrade_inbound(server_io, PROTO),
			client.upgrade_outbound(client_io, PROTO)
		)
	}

	fn group<C>(stream: &TlsStream<C>) -> &'static str {
		let state: &CommonState = match stream {
			TlsStream::Client(s) => s.get_ref().1,
			TlsStream::Server(s) => s.get_ref().1,
		};
		state.negotiated_key_exchange_group().unwrap().name().as_str().unwrap()
	}

	/// A libp2p TLS certificate claiming `claimed`'s identity, with the extension signed by
	/// `signer` (mirrors `libp2p_tls::certificate::generate`).
	fn certificate(
		claimed: &Keypair,
		signer: &Keypair,
	) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
		let cert_key = rcgen::KeyPair::generate(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
		let mut msg = b"libp2p-tls-handshake:".to_vec();
		msg.extend(cert_key.public_key_der());
		let content =
			yasna::encode_der(&(claimed.public().encode_protobuf(), signer.sign(&msg).unwrap()));
		let mut ext =
			rcgen::CustomExtension::from_oid_content(&[1, 3, 6, 1, 4, 1, 53594, 1, 1], content);
		ext.set_criticality(true);
		let key = PrivatePkcs8KeyDer::from(cert_key.serialize_der()).into();
		let mut params = rcgen::CertificateParams::new(vec![]);
		params.distinguished_name = rcgen::DistinguishedName::new();
		params.custom_extensions.push(ext);
		params.alg = &rcgen::PKCS_ECDSA_P256_SHA256;
		params.key_pair = Some(cert_key);
		let cert = rcgen::Certificate::from_params(params).unwrap();
		(cert.serialize_der().unwrap().into(), key)
	}

	fn classical_x25519(identity: &Keypair) -> Config {
		let (cert, key) = certificate::generate(identity).unwrap();
		let provider =
			CryptoProvider { kx_groups: vec![aws_lc_rs::kx_group::X25519], ..provider() };
		Config::with_provider(cert, key, provider).unwrap()
	}

	#[tokio::test]
	async fn handshake_negotiates_hybrid_group_and_binds_mldsa_identity() {
		sp_tracing::try_init_simple();
		let (server_id, client_id) = (mldsa(), mldsa());
		let (s, c) =
			handshake(Config::new(&server_id).unwrap(), Config::new(&client_id).unwrap()).await;
		let ((peer_seen_by_server, s), (peer_seen_by_client, c)) = (s.unwrap(), c.unwrap());
		assert_eq!(peer_seen_by_server, client_id.public().to_peer_id());
		assert_eq!(peer_seen_by_client, server_id.public().to_peer_id());
		assert_eq!(group(&s), "X25519MLKEM768");
		assert_eq!(group(&c), "X25519MLKEM768");
	}

	#[tokio::test]
	async fn classical_x25519_peer_is_rejected() {
		sp_tracing::try_init_simple();
		let (s, c) = handshake(Config::new(&mldsa()).unwrap(), classical_x25519(&mldsa())).await;
		assert!(matches!(s, Err(UpgradeError::Handshake(_))), "server accepted classical client");
		assert!(c.is_err(), "classical client connected");

		let (s, c) = handshake(classical_x25519(&mldsa()), Config::new(&mldsa()).unwrap()).await;
		assert!(s.is_err(), "classical server accepted");
		assert!(matches!(c, Err(UpgradeError::Handshake(_))), "client accepted classical server");
	}

	#[tokio::test]
	async fn stock_libp2p_tls_peer_is_rejected() {
		// Upstream libp2p-tls: ring provider, classical groups only.
		let (s, c) =
			handshake(Config::new(&mldsa()).unwrap(), libp2p::tls::Config::new(&mldsa()).unwrap())
				.await;
		assert!(matches!(s, Err(UpgradeError::Handshake(_))));
		assert!(c.is_err());

		let (s, c) =
			handshake(libp2p::tls::Config::new(&mldsa()).unwrap(), Config::new(&mldsa()).unwrap())
				.await;
		assert!(s.is_err());
		assert!(matches!(c, Err(UpgradeError::Handshake(_))));
	}

	#[tokio::test]
	async fn tampered_identity_is_rejected() {
		let (claimed, attacker) = (mldsa(), mldsa());

		// Control: a hand-built certificate signed by the claimed key is accepted.
		let (cert, key) = certificate(&claimed, &claimed);
		let (s, c) =
			handshake(Config::new(&mldsa()).unwrap(), Config::with_certificate(cert, key).unwrap())
				.await;
		assert_eq!(s.unwrap().0, claimed.public().to_peer_id());
		c.unwrap();

		// Extension claims `claimed` but is signed by `attacker`: rejected in both directions.
		let (cert, key) = certificate(&claimed, &attacker);
		let tampered = Config::with_certificate(cert, key).unwrap();
		// TLS 1.3: the client is done before the server checks its certificate, so only the
		// server side observes this rejection (it aborts the connection with an alert).
		let (s, _) = handshake(Config::new(&mldsa()).unwrap(), tampered.clone()).await;
		assert!(matches!(s, Err(UpgradeError::Handshake(_))), "server accepted tampered client");
		let (s, c) = handshake(tampered, Config::new(&mldsa()).unwrap()).await;
		assert!(s.is_err());
		assert!(matches!(c, Err(UpgradeError::Handshake(_))), "client accepted tampered server");
	}

	type Node = Boxed<(PeerId, StreamMuxerBox)>;

	async fn next_event(
		node: &mut Node,
	) -> TransportEvent<<Node as Transport>::ListenerUpgrade, <Node as Transport>::Error> {
		futures::future::poll_fn(|cx| Pin::new(&mut *node).poll(cx)).await
	}

	/// Dials `listener` from `dialer` over the memory transport and returns the peer ID the
	/// dialer authenticated. The listener side is driven until the dial completes; with
	/// `V1Lazy` its yamux negotiation waits for application data, so it is not awaited.
	async fn connect(mut listener: Node, mut dialer: Node) -> Result<PeerId, String> {
		let addr: Multiaddr = format!("/memory/{}", rand::random::<u64>()).parse().unwrap();
		listener.listen_on(ListenerId::next(), addr.clone()).unwrap();
		assert!(matches!(next_event(&mut listener).await, TransportEvent::NewAddress { .. }));
		let dial = dialer
			.dial(addr, DialOpts { role: Endpoint::Dialer, port_use: PortUse::New })
			.unwrap();
		let accept = async {
			if let TransportEvent::Incoming { upgrade, .. } = next_event(&mut listener).await {
				let _ = upgrade.await;
			}
		};
		let dial = async { dial.await.map(|(peer, _)| peer).map_err(|e| e.to_string()) };
		match futures::future::select(Box::pin(dial), Box::pin(accept)).await {
			futures::future::Either::Left((dialed, _)) => dialed,
			futures::future::Either::Right(((), dial)) => dial.await,
		}
	}

	#[tokio::test]
	async fn full_transport_connects_mldsa_nodes() {
		let (a, b) = (mldsa(), mldsa());
		let dialed = connect(build_transport(a.clone(), true).0, build_transport(b, true).0).await;
		assert_eq!(dialed.unwrap(), a.public().to_peer_id());
	}

	#[tokio::test]
	async fn noise_only_peer_is_rejected() {
		let noise_node = |key: &Keypair| -> Node {
			MemoryTransport::default()
				.upgrade(upgrade::Version::V1Lazy)
				.authenticate(noise::Config::new(key).unwrap())
				.multiplex(libp2p::yamux::Config::default())
				.boxed()
		};
		let dialed = connect(build_transport(mldsa(), true).0, noise_node(&mldsa())).await;
		assert!(dialed.is_err(), "Noise dialer connected to TLS node");
		let dialed = connect(noise_node(&mldsa()), build_transport(mldsa(), true).0).await;
		assert!(dialed.is_err(), "TLS dialer connected to Noise node");
	}

	#[test]
	fn fips_provider_and_aws_lc_version() {
		::aws_lc_rs::fips_mode();
		assert!(provider().fips(), "provider must be FIPS-mode aws-lc-rs");
		let version = unsafe {
			// SAFETY: `OpenSSL_version` returns a static NUL-terminated string.
			std::ffi::CStr::from_ptr(aws_lc_fips_sys::OpenSSL_version(0))
		};
		println!("aws_lc_rs::fips_mode() ok; provider fips = true; {version:?}");
	}
}
