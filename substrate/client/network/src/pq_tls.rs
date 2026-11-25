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

//! libp2p TLS 1.3 security upgrade with post-quantum key exchange and authentication.
//!
//! - Key exchange: only the hybrid ML-KEM groups X25519MLKEM768 / SECP256R1MLKEM768.
//! - Authentication: only ML-DSA-65 (TLS `SignatureScheme` 0x0905). The node's ML-DSA-65 identity
//!   key is the certificate key: each side presents a minimal self-signed X.509 certificate whose
//!   subject public key IS the identity key, and proves possession by signing CertificateVerify
//!   with it. The peer ID is derived from that public key, so no libp2p certificate extension is
//!   needed. Certificates or handshake signatures of any other algorithm are rejected.
//! - All TLS cryptography runs in aws-lc-rs (FIPS build), passed explicitly to rustls. There is no
//!   classical fallback, and the upgrade is not interoperable with stock libp2p-tls or Noise.

use ::aws_lc_rs::signature::{
	KeyPair as _, PqdsaKeyPair, UnparsedPublicKey, ML_DSA_65, ML_DSA_65_SIGNING,
};
use futures::{future::BoxFuture, AsyncRead, AsyncWrite, FutureExt};
use futures_rustls::TlsStream;
use libp2p::{
	core::{
		upgrade::{InboundConnectionUpgrade, OutboundConnectionUpgrade},
		UpgradeInfo,
	},
	identity, PeerId,
};
use rustls::{
	client::{
		danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
		Resumption,
	},
	crypto::{aws_lc_rs, CryptoProvider, SupportedKxGroup},
	pki_types::{CertificateDer, ServerName, UnixTime},
	server::{
		danger::{ClientCertVerified, ClientCertVerifier},
		NoServerSessionStorage,
	},
	sign::{CertifiedKey, Signer, SigningKey, SingleCertAndKey},
	CertificateError, ClientConfig, CommonState, DigitallySignedStruct, DistinguishedName,
	OtherError, ServerConfig, SignatureAlgorithm, SignatureScheme,
};
use std::{
	net::{IpAddr, Ipv4Addr},
	sync::Arc,
};
use x509_parser::der_parser::oid::Oid;

const LOG_TARGET: &str = "sub-libp2p::tls";

/// The only key exchange groups offered or accepted, in preference order.
pub(crate) static KX_GROUPS: &[&dyn SupportedKxGroup] =
	&[aws_lc_rs::kx_group::X25519MLKEM768, aws_lc_rs::kx_group::SECP256R1MLKEM768];

/// The only handshake signature scheme offered or accepted.
const SCHEME: SignatureScheme = SignatureScheme::ML_DSA_65;
/// id-ml-dsa-65 (FIPS 204, RFC 9881), with absent parameters.
const ID_ML_DSA_65: [u64; 9] = [2, 16, 840, 1, 101, 3, 4, 3, 18];
const PUBLIC_KEY_LEN: usize = 1952;
const SIGNATURE_LEN: usize = 3309;
/// Upper bound on a peer certificate; ours are about 5.3 KB.
const MAX_CERTIFICATE_LEN: usize = 8 * 1024;
/// UTCTime 1970-01-01 and GeneralizedTime 9999-12-31 ("no expiration", RFC 5280 4.1.2.5).
const NOT_BEFORE: &[u8] = b"\x17\x0d700101000000Z";
const NOT_AFTER: &[u8] = b"\x18\x0f99991231235959Z";

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
	/// Building the rustls configuration failed.
	#[error("Failed to build TLS config: {0}")]
	Config(#[from] rustls::Error),
	/// The handshake failed (for instance, no hybrid group or ML-DSA-65 signature in common).
	#[error("TLS handshake failed: {0}")]
	Handshake(std::io::Error),
	/// The peer certificate or the local identity is not acceptable.
	#[error("Invalid certificate: {0}")]
	BadCertificate(#[from] BadCertificate),
	/// The negotiated connection does not satisfy the security policy.
	#[error("TLS policy violation: {0}")]
	Policy(&'static str),
}

/// A certificate (or identity key) rejected by the ML-DSA-65 policy.
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub struct BadCertificate(&'static str);

/// libp2p TLS security upgrade with hybrid PQ key exchange and ML-DSA-65 authentication.
#[derive(Clone)]
pub struct Config {
	server: Arc<ServerConfig>,
	client: Arc<ClientConfig>,
}

impl Config {
	/// Creates a config authenticating with the ML-DSA-65 node `identity`.
	pub fn new(identity: &identity::Keypair) -> Result<Self, UpgradeError> {
		let key = identity_signing_key(identity)?;
		let cert = self_signed_certificate(&key)?;
		Ok(Self::with_key(cert, Arc::new(key))?)
	}

	/// Creates a config presenting `cert` and signing CertificateVerify with `key`.
	pub(crate) fn with_key(
		cert: CertificateDer<'static>,
		key: Arc<PqdsaKeyPair>,
	) -> Result<Self, rustls::Error> {
		Self::build(provider(), Arc::new(MlDsa65Verifier), Arc::new(MlDsa65Key(key)), cert)
	}

	fn build<V: ServerCertVerifier + ClientCertVerifier + 'static>(
		provider: CryptoProvider,
		verifier: Arc<V>,
		key: Arc<dyn SigningKey>,
		cert: CertificateDer<'static>,
	) -> Result<Self, rustls::Error> {
		let provider = Arc::new(provider);
		// Not `with_single_cert`: that would parse the certificate with webpki.
		let resolver = Arc::new(SingleCertAndKey::from(CertifiedKey::new(vec![cert], key)));

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

/// Loads the ML-DSA-65 identity secret key into aws-lc-rs.
fn identity_signing_key(identity: &identity::Keypair) -> Result<PqdsaKeyPair, BadCertificate> {
	let identity = identity
		.clone()
		.try_into_mldsa65()
		.map_err(|_| BadCertificate("node identity must be ML-DSA-65"))?;
	let secret = identity
		.secret()
		.as_ref()
		.get(..identity::mldsa65::SECRET_KEY_LENGTH)
		.ok_or(BadCertificate("short ML-DSA-65 identity secret key"))?;
	let key = PqdsaKeyPair::from_raw_private_key(&ML_DSA_65_SIGNING, secret)
		.map_err(|_| BadCertificate("aws-lc rejected the ML-DSA-65 identity secret key"))?;
	if key.public_key().as_ref() != identity.public().to_bytes() {
		return Err(BadCertificate("ML-DSA-65 identity public key does not match its secret key"));
	}
	Ok(key)
}

fn sign(key: &PqdsaKeyPair, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
	let mut signature = vec![0; SIGNATURE_LEN];
	match key.sign(message, &mut signature) {
		Ok(SIGNATURE_LEN) => Ok(signature),
		_ => Err(rustls::Error::General("ML-DSA-65 signing failed".into())),
	}
}

fn write_algorithm(writer: yasna::DERWriter) {
	writer.write_sequence(|w| {
		w.next().write_oid(&yasna::models::ObjectIdentifier::from_slice(&ID_ML_DSA_65))
	});
}

/// Builds a minimal self-signed X.509 v1 certificate for the ML-DSA-65 `key`.
pub(crate) fn self_signed_certificate(
	key: &PqdsaKeyPair,
) -> Result<CertificateDer<'static>, rustls::Error> {
	let public_key = key.public_key().as_ref();
	let tbs = yasna::construct_der(|w| {
		w.write_sequence(|w| {
			w.next().write_u8(1); // serialNumber
			write_algorithm(w.next());
			w.next().write_sequence(|_| ()); // issuer: empty Name
			w.next().write_sequence(|w| {
				w.next().write_der(NOT_BEFORE);
				w.next().write_der(NOT_AFTER);
			});
			w.next().write_sequence(|_| ()); // subject: empty Name
			w.next().write_sequence(|w| {
				write_algorithm(w.next());
				w.next().write_bitvec_bytes(public_key, public_key.len() * 8);
			});
		})
	});
	let signature = sign(key, &tbs)?;
	Ok(yasna::construct_der(|w| {
		w.write_sequence(|w| {
			w.next().write_der(&tbs);
			write_algorithm(w.next());
			w.next().write_bitvec_bytes(&signature, signature.len() * 8);
		})
	})
	.into())
}

/// Checks that `der` is a self-signed ML-DSA-65 certificate within the size limits and returns
/// its raw public key.
pub(crate) fn parse_certificate(der: &[u8]) -> Result<Vec<u8>, BadCertificate> {
	if der.len() > MAX_CERTIFICATE_LEN {
		return Err(BadCertificate("certificate too large"));
	}
	let (rest, cert) = x509_parser::parse_x509_certificate(der)
		.map_err(|_| BadCertificate("malformed certificate"))?;
	if !rest.is_empty() {
		return Err(BadCertificate("trailing data after certificate"));
	}
	let ml_dsa_65 = Oid::from(&ID_ML_DSA_65).expect("valid OID; qed");
	let spki = &cert.tbs_certificate.subject_pki;
	for alg in [&cert.signature_algorithm, &cert.tbs_certificate.signature, &spki.algorithm] {
		if alg.algorithm != ml_dsa_65 || alg.parameters.is_some() {
			return Err(BadCertificate("certificate key or signature is not ML-DSA-65"));
		}
	}
	let public_key = spki.subject_public_key.data.as_ref();
	let signature = cert.signature_value.data.as_ref();
	if public_key.len() != PUBLIC_KEY_LEN || signature.len() != SIGNATURE_LEN {
		return Err(BadCertificate("bad ML-DSA-65 key or signature length"));
	}
	if !cert.extensions().is_empty() {
		return Err(BadCertificate("unexpected certificate extensions"));
	}
	if !cert.validity().is_valid() {
		return Err(BadCertificate("certificate not valid now"));
	}
	UnparsedPublicKey::new(&ML_DSA_65, public_key)
		.verify(cert.tbs_certificate.as_ref(), signature)
		.map_err(|_| BadCertificate("bad certificate self-signature"))?;
	Ok(public_key.to_vec())
}

/// The peer ID bound to an ML-DSA-65 certificate public key.
fn peer_id(public_key: &[u8]) -> Result<PeerId, BadCertificate> {
	let key = identity::mldsa65::PublicKey::try_from_bytes(public_key)
		.map_err(|_| BadCertificate("invalid ML-DSA-65 public key"))?;
	Ok(identity::PublicKey::from(key).to_peer_id())
}

/// rustls signing key for the ML-DSA-65 identity: offers only the ML-DSA-65 scheme.
#[derive(Debug)]
struct MlDsa65Key(Arc<PqdsaKeyPair>);

impl SigningKey for MlDsa65Key {
	fn choose_scheme(&self, offered: &[SignatureScheme]) -> Option<Box<dyn Signer>> {
		offered
			.contains(&SCHEME)
			.then(|| Box::new(MlDsa65Key(self.0.clone())) as Box<dyn Signer>)
	}

	fn algorithm(&self) -> SignatureAlgorithm {
		// No TLS 1.2 `SignatureAlgorithm` exists for ML-DSA (rustls uses the same placeholder).
		SignatureAlgorithm::Unknown(0)
	}
}

impl Signer for MlDsa65Key {
	fn sign(&self, message: &[u8]) -> Result<Vec<u8>, rustls::Error> {
		sign(&self.0, message)
	}

	fn scheme(&self) -> SignatureScheme {
		SCHEME
	}
}

#[cfg(test)]
thread_local! {
	/// Test hook: CertificateVerify signatures verified with ML-DSA-65 on this thread.
	pub(crate) static MLDSA65_VERIFICATIONS: std::cell::Cell<usize> = const { std::cell::Cell::new(0) };
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
		 exchange X25519MLKEM768/SECP256R1MLKEM768 and an ML-DSA-65 certificate required)",
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
	let peer_id = peer_id(&parse_certificate(cert)?)?;
	log::debug!(
		target: LOG_TARGET,
		"TLS handshake with {peer_id} negotiated {group:?}, authenticated with ML-DSA-65",
	);
	Ok(peer_id)
}

/// Accepts exactly one self-signed ML-DSA-65 certificate and ML-DSA-65 CertificateVerify
/// signatures by its key. The expected peer ID is checked by the swarm after the upgrade.
#[derive(Debug)]
struct MlDsa65Verifier;

impl MlDsa65Verifier {
	fn verify_presented_certs(
		end_entity: &CertificateDer,
		intermediates: &[CertificateDer],
	) -> Result<(), rustls::Error> {
		if !intermediates.is_empty() {
			return Err(rustls::Error::General("exactly one certificate required".into()));
		}
		parse_certificate(end_entity).map_err(invalid_certificate)?;
		Ok(())
	}

	fn verify_tls13(
		message: &[u8],
		cert: &CertificateDer,
		dss: &DigitallySignedStruct,
	) -> Result<HandshakeSignatureValid, rustls::Error> {
		if dss.scheme != SCHEME {
			return Err(rustls::Error::PeerIncompatible(
				rustls::PeerIncompatible::NoSignatureSchemesInCommon,
			));
		}
		let public_key = parse_certificate(cert).map_err(invalid_certificate)?;
		UnparsedPublicKey::new(&ML_DSA_65, &public_key)
			.verify(message, dss.signature())
			.map_err(|_| rustls::Error::InvalidCertificate(CertificateError::BadSignature))?;
		#[cfg(test)]
		MLDSA65_VERIFICATIONS.with(|c| c.set(c.get() + 1));
		Ok(HandshakeSignatureValid::assertion())
	}

	fn tls12_rejected() -> Result<HandshakeSignatureValid, rustls::Error> {
		Err(rustls::Error::General("TLS 1.2 is not supported".into()))
	}
}

fn invalid_certificate(e: BadCertificate) -> rustls::Error {
	rustls::Error::InvalidCertificate(CertificateError::Other(OtherError(Arc::new(e))))
}

impl ServerCertVerifier for MlDsa65Verifier {
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
		vec![SCHEME]
	}
}

impl ClientCertVerifier for MlDsa65Verifier {
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
		vec![SCHEME]
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
	use rustls::pki_types::PrivateKeyDer;
	use std::pin::Pin;

	const PROTO: &str = "/tls/1.0.0";

	fn mldsa() -> Keypair {
		Keypair::generate_mldsa65()
	}

	/// The certificate and aws-lc signing key `Config::new` would use for `identity`.
	fn credentials(identity: &Keypair) -> (CertificateDer<'static>, Arc<PqdsaKeyPair>) {
		let key = identity_signing_key(identity).unwrap();
		(self_signed_certificate(&key).unwrap(), Arc::new(key))
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

	/// Asserts `honest` rejects `attacker` both as server and as client.
	async fn rejected_both_ways(attacker: Config) {
		let (s, _) = handshake(Config::new(&mldsa()).unwrap(), attacker.clone()).await;
		assert!(matches!(s, Err(UpgradeError::Handshake(_))), "server accepted attacker: {s:?}");
		let (_, c) = handshake(attacker, Config::new(&mldsa()).unwrap()).await;
		assert!(matches!(c, Err(UpgradeError::Handshake(_))), "client accepted attacker: {c:?}");
	}

	fn group<C>(stream: &TlsStream<C>) -> &'static str {
		let state: &CommonState = match stream {
			TlsStream::Client(s) => s.get_ref().1,
			TlsStream::Server(s) => s.get_ref().1,
		};
		state.negotiated_key_exchange_group().unwrap().name().as_str().unwrap()
	}

	/// A misbehaving peer: hybrid key exchange, but it trusts any certificate, offers
	/// `schemes`, and presents `cert` while signing with `key`.
	#[derive(Debug)]
	struct TrustAll(Vec<SignatureScheme>);

	impl ServerCertVerifier for TrustAll {
		fn verify_server_cert(
			&self,
			_: &CertificateDer,
			_: &[CertificateDer],
			_: &ServerName,
			_: &[u8],
			_: UnixTime,
		) -> Result<ServerCertVerified, rustls::Error> {
			Ok(ServerCertVerified::assertion())
		}
		fn verify_tls12_signature(
			&self,
			_: &[u8],
			_: &CertificateDer,
			_: &DigitallySignedStruct,
		) -> Result<HandshakeSignatureValid, rustls::Error> {
			Ok(HandshakeSignatureValid::assertion())
		}
		fn verify_tls13_signature(
			&self,
			_: &[u8],
			_: &CertificateDer,
			_: &DigitallySignedStruct,
		) -> Result<HandshakeSignatureValid, rustls::Error> {
			Ok(HandshakeSignatureValid::assertion())
		}
		fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
			self.0.clone()
		}
	}

	impl ClientCertVerifier for TrustAll {
		fn root_hint_subjects(&self) -> &[DistinguishedName] {
			&[]
		}
		fn verify_client_cert(
			&self,
			_: &CertificateDer,
			_: &[CertificateDer],
			_: UnixTime,
		) -> Result<ClientCertVerified, rustls::Error> {
			Ok(ClientCertVerified::assertion())
		}
		fn verify_tls12_signature(
			&self,
			_: &[u8],
			_: &CertificateDer,
			_: &DigitallySignedStruct,
		) -> Result<HandshakeSignatureValid, rustls::Error> {
			Ok(HandshakeSignatureValid::assertion())
		}
		fn verify_tls13_signature(
			&self,
			_: &[u8],
			_: &CertificateDer,
			_: &DigitallySignedStruct,
		) -> Result<HandshakeSignatureValid, rustls::Error> {
			Ok(HandshakeSignatureValid::assertion())
		}
		fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
			self.0.clone()
		}
	}

	fn attacker(
		cert: CertificateDer<'static>,
		key: Arc<dyn SigningKey>,
		schemes: Vec<SignatureScheme>,
	) -> Config {
		Config::build(provider(), Arc::new(TrustAll(schemes)), key, cert).unwrap()
	}

	fn mldsa_key(key: Arc<PqdsaKeyPair>) -> Arc<dyn SigningKey> {
		Arc::new(MlDsa65Key(key))
	}

	/// Stock libp2p-tls certificate: ephemeral P-256 key, identity in the libp2p extension.
	fn p256_certificate() -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
		libp2p::tls::certificate::generate(&mldsa()).unwrap()
	}

	fn ed25519_certificate() -> CertificateDer<'static> {
		let mut params = rcgen::CertificateParams::new(vec![]);
		params.alg = &rcgen::PKCS_ED25519;
		rcgen::Certificate::from_params(params).unwrap().serialize_der().unwrap().into()
	}

	#[tokio::test]
	async fn handshake_uses_hybrid_group_and_mldsa65_signatures() {
		sp_tracing::try_init_simple();
		let (server_id, client_id) = (mldsa(), mldsa());
		let before = MLDSA65_VERIFICATIONS.with(|c| c.get());
		let (s, c) =
			handshake(Config::new(&server_id).unwrap(), Config::new(&client_id).unwrap()).await;
		let ((peer_seen_by_server, s), (peer_seen_by_client, c)) = (s.unwrap(), c.unwrap());
		assert_eq!(peer_seen_by_server, client_id.public().to_peer_id());
		assert_eq!(peer_seen_by_client, server_id.public().to_peer_id());
		assert_eq!(group(&s), "X25519MLKEM768");
		assert_eq!(group(&c), "X25519MLKEM768");
		// Both CertificateVerify messages were ML-DSA-65 and verified (the verifier refuses any
		// other scheme before counting).
		assert_eq!(MLDSA65_VERIFICATIONS.with(|c| c.get()) - before, 2);
	}

	#[test]
	fn certificate_is_mldsa65_identity_key_within_limits() {
		let id = mldsa();
		let (cert, _) = credentials(&id);
		assert!(cert.len() < MAX_CERTIFICATE_LEN, "{}", cert.len());
		let public_key = parse_certificate(&cert).unwrap();
		assert_eq!(public_key, id.public().try_into_mldsa65().unwrap().to_bytes());
		assert_eq!(peer_id(&public_key).unwrap(), id.public().to_peer_id());
		let mut long = cert.to_vec();
		long.resize(MAX_CERTIFICATE_LEN + 1, 0);
		assert!(parse_certificate(&long).is_err());
		let mut trailing = cert.to_vec();
		trailing.push(0);
		assert!(parse_certificate(&trailing).is_err());
	}

	#[test]
	fn classical_certificates_are_rejected_by_verifier() {
		let p256 = p256_certificate().0;
		let ed25519 = ed25519_certificate();
		for cert in [&p256, &ed25519] {
			assert!(parse_certificate(cert).is_err());
			assert!(MlDsa65Verifier::verify_presented_certs(cert, &[]).is_err());
		}
	}

	#[tokio::test]
	async fn peer_with_p256_or_ed25519_certificate_is_rejected() {
		let (_, mldsa_signer) = credentials(&mldsa());
		for cert in [p256_certificate().0, ed25519_certificate()] {
			// Classical certificate, CertificateVerify signed with ML-DSA-65.
			let all =
				vec![SCHEME, SignatureScheme::ECDSA_NISTP256_SHA256, SignatureScheme::ED25519];
			rejected_both_ways(attacker(cert, mldsa_key(mldsa_signer.clone()), all)).await;
		}
		// Stock libp2p-tls certificate with its own P-256 key and signatures.
		let (cert, key) = p256_certificate();
		let key = provider().key_provider.load_private_key(key).unwrap();
		let schemes = vec![SignatureScheme::ECDSA_NISTP256_SHA256];
		rejected_both_ways(attacker(cert, key, schemes)).await;
	}

	#[tokio::test]
	async fn peer_offering_only_classical_signature_schemes_is_rejected() {
		let (cert, key) = credentials(&mldsa());
		let classical = vec![
			SignatureScheme::ECDSA_NISTP256_SHA256,
			SignatureScheme::ED25519,
			SignatureScheme::RSA_PSS_SHA256,
		];
		let attacker = attacker(cert, mldsa_key(key), classical);
		// As client it offers only classical schemes: the honest server cannot sign and aborts.
		let (s, _) = handshake(Config::new(&mldsa()).unwrap(), attacker.clone()).await;
		assert!(matches!(s, Err(UpgradeError::Handshake(_))), "server accepted attacker: {s:?}");
		// As server it requests classical client signatures: the honest client cannot sign one,
		// sends no certificate, and no connection is established. (The honest client did verify
		// the server's genuine ML-DSA-65 certificate and CertificateVerify.)
		let (s, _) = handshake(attacker, Config::new(&mldsa()).unwrap()).await;
		assert!(s.is_err());
		assert!(MlDsa65Key(credentials(&mldsa()).1)
			.choose_scheme(&[SignatureScheme::ECDSA_NISTP256_SHA256, SignatureScheme::ED25519])
			.is_none());
	}

	#[tokio::test]
	async fn tampered_certificate_is_rejected() {
		let (cert, key) = credentials(&mldsa());
		// Last byte of the self-signature, then a byte inside the TBS (validity).
		for index in [cert.len() - 1, 60] {
			let mut tampered = cert.to_vec();
			tampered[index] ^= 1;
			let tampered = CertificateDer::from(tampered);
			assert!(parse_certificate(&tampered).is_err());
			let config = Config::with_key(tampered, key.clone()).unwrap();
			rejected_both_ways(config).await;
		}
	}

	#[tokio::test]
	async fn identity_mismatch_is_rejected() {
		// The attacker replays the victim's genuine certificate but holds a different key.
		let (victim_cert, _) = credentials(&mldsa());
		let (_, attacker_key) = credentials(&mldsa());
		rejected_both_ways(Config::with_key(victim_cert, attacker_key).unwrap()).await;
	}

	#[test]
	fn non_mldsa_identity_is_refused() {
		assert!(Config::new(&Keypair::generate_ed25519()).is_err());
	}

	fn classical_x25519(identity: &Keypair) -> Config {
		let (cert, key) = credentials(identity);
		let provider =
			CryptoProvider { kx_groups: vec![aws_lc_rs::kx_group::X25519], ..provider() };
		Config::build(provider, Arc::new(MlDsa65Verifier), mldsa_key(key), cert).unwrap()
	}

	#[tokio::test]
	async fn classical_x25519_peer_is_rejected() {
		sp_tracing::try_init_simple();
		rejected_both_ways(classical_x25519(&mldsa())).await;
	}

	#[tokio::test]
	async fn stock_libp2p_tls_peer_is_rejected() {
		// Upstream libp2p-tls: ring provider, classical groups, P-256 certificate.
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
