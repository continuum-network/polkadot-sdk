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

//! Continuum ML-DSA-65-only node key parameters.

use clap::Args;
use sc_network::config::{NodeKeyConfig, NODE_KEY_ED25519_FILE_LEGACY, NODE_KEY_MLDSA65_FILE};
use sc_service::Role;
use std::path::PathBuf;

use crate::{arg_enums::NodeKeyType, error, Error};

/// Parameters used to create the `NodeKeyConfig`, which determines the keypair
/// used for libp2p networking.
///
/// Continuum: ML-DSA-65 only. Classical ed25519 `--node-key` / `secret_ed25519` are rejected.
#[derive(Debug, Clone, Args)]
pub struct NodeKeyParams {
	/// Secret key hex for p2p networking.
	///
	/// Continuum does not accept 64-hex ed25519 seeds. If set, this value must be
	/// hex-encoded Continuum ML-DSA-65 secret material (`secret||public`, 5984 bytes,
	/// 11968 hex chars). The value of this option takes precedence over `--node-key-file`.
	///
	/// WARNING: Secrets provided as command-line arguments are easily exposed.
	/// Use of this option should be limited to development and testing. To use
	/// an externally managed secret key, use `--node-key-file` instead.
	#[arg(long, value_name = "KEY")]
	pub node_key: Option<String>,

	/// Crypto primitive to use for p2p networking.
	///
	/// The secret key of the node is obtained as follows:
	///
	/// - If the `--node-key` option is given, the value is parsed as a secret key according to the
	///   type. See the documentation for `--node-key`.
	///
	/// - If the `--node-key-file` option is given, the secret key is read from the specified file.
	///   See the documentation for `--node-key-file`.
	///
	/// - Otherwise, the secret key is read from a file with a predetermined, type-specific name
	///   from the chain-specific network config directory inside the base directory specified by
	///   `--base-dir`. If this file does not exist, it is created with a newly generated secret
	///   key of the chosen type.
	///
	/// The node's secret key determines the corresponding public key and hence the
	/// node's peer ID in the context of libp2p.
	///
	/// Continuum only supports `ml-dsa65`.
	#[arg(long, value_name = "TYPE", value_enum, ignore_case = true, default_value_t = NodeKeyType::MlDsa65)]
	pub node_key_type: NodeKeyType,

	/// File from which to read the node's secret key to use for p2p networking.
	///
	/// The file must contain raw or hex-encoded Continuum ML-DSA-65 secret material
	/// (`secret||public`, 5984 bytes). The default filename in the network config
	/// directory is `secret_mldsa65`.
	///
	/// If the file does not exist, it is created with a newly generated secret key of
	/// the chosen type.
	#[arg(long, value_name = "FILE")]
	pub node_key_file: Option<PathBuf>,

	/// Forces key generation if node-key-file file does not exist.
	///
	/// This is an unsafe feature for production networks, because as an active authority
	/// other authorities may depend on your node having a stable identity and they might
	/// not being able to reach you if your identity changes after entering the active set.
	///
	/// For minimal node downtime if no custom `node-key-file` argument is provided
	/// the network-key is usually persisted accross nodes restarts,
	/// in the `network` folder from directory provided in `--base-path`
	///
	/// Warning!! If you ever run the node with this argument, make sure
	/// you remove it for the subsequent restarts.
	#[arg(long)]
	pub unsafe_force_node_key_generation: bool,
}

impl NodeKeyParams {
	/// Create a `NodeKeyConfig` from the given `NodeKeyParams` in the context
	/// of an optional network config storage directory.
	pub fn node_key(
		&self,
		net_config_dir: &PathBuf,
		role: Role,
		is_dev: bool,
	) -> error::Result<NodeKeyConfig> {
		match self.node_key_type {
			NodeKeyType::MlDsa65 => {
				let secret = if let Some(node_key) = self.node_key.as_ref() {
					parse_mldsa65_secret_hex(node_key)?
				} else {
					let key_path = self
						.node_key_file
						.clone()
						.unwrap_or_else(|| net_config_dir.join(NODE_KEY_MLDSA65_FILE));

					let legacy = net_config_dir.join(NODE_KEY_ED25519_FILE_LEGACY);
					if legacy.exists() && !key_path.exists() {
						return Err(Error::Input(format!(
							"Found legacy ed25519 node key at {} but Continuum requires \
							 ML-DSA-65 (`{}`). Remove the legacy file and run \
							 `key generate-node-key`.",
							legacy.display(),
							NODE_KEY_MLDSA65_FILE
						)));
					}

					if !self.unsafe_force_node_key_generation &&
						role.is_authority() &&
						!is_dev && !key_path.exists()
					{
						return Err(Error::NetworkKeyNotFound(key_path));
					}
					sc_network::config::Secret::File(key_path)
				};

				Ok(NodeKeyConfig::MlDsa65(secret))
			},
		}
	}
}

/// Create an error caused by an invalid node key argument.
fn invalid_node_key(e: impl std::fmt::Display) -> error::Error {
	error::Error::Input(format!("Invalid node key: {}", e))
}

/// Parse hex-encoded ML-DSA-65 secret material into a `sc_network::Secret`.
fn parse_mldsa65_secret_hex(hex: &str) -> error::Result<sc_network::config::MlDsa65Secret> {
	let trimmed = hex.trim();
	if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
		return Err(invalid_node_key(
			"64-hex ed25519 --node-key is not supported on Continuum; \
			 use --node-key-file with secret_mldsa65 (ML-DSA-65 secret||public)",
		));
	}
	let mut raw =
		array_bytes::hex2bytes(trimmed).map_err(|e| invalid_node_key(format!("{:?}", e)))?;
	libp2p_identity::mldsa65::SecretKey::try_from_bytes(&mut raw)
		.map(sc_network::config::Secret::Input)
		.map_err(invalid_node_key)
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::fs::{self, File};
	use tempfile::TempDir;

	fn params(
		node_key: Option<String>,
		node_key_file: Option<PathBuf>,
		force: bool,
	) -> NodeKeyParams {
		NodeKeyParams {
			node_key_type: NodeKeyType::MlDsa65,
			node_key,
			node_key_file,
			unsafe_force_node_key_generation: force,
		}
	}

	#[test]
	fn test_node_key_config_input() {
		let sk = libp2p_identity::mldsa65::SecretKey::generate();
		let hex = array_bytes::bytes2hex("", sk.as_ref());
		match params(Some(hex), None, false).node_key(&PathBuf::from("x"), Role::Authority, false) {
			Ok(NodeKeyConfig::MlDsa65(sc_network::config::Secret::Input(ref ski))) => {
				assert_eq!(ski.as_ref(), sk.as_ref())
			},
			other => panic!("Unexpected node key config: {other:?}"),
		}
	}

	#[test]
	fn test_node_key_config_default() {
		let dir = PathBuf::from("x");
		for (force, role, is_dev) in [
			(false, Role::Full, false),
			(false, Role::Authority, true),
			(true, Role::Authority, false),
		] {
			match params(None, None, force).node_key(&dir, role, is_dev).unwrap() {
				NodeKeyConfig::MlDsa65(sc_network::config::Secret::File(ref f)) => {
					assert_eq!(f, &dir.join(NODE_KEY_MLDSA65_FILE))
				},
				other => panic!("Unexpected node key config: {other:?}"),
			}
		}
		assert!(matches!(
			params(None, None, false).node_key(&dir, Role::Authority, false),
			Err(Error::NetworkKeyNotFound(_))
		));

		let tempdir = TempDir::new().unwrap();
		let _file = File::create(tempdir.path().join(NODE_KEY_MLDSA65_FILE)).unwrap();
		assert!(params(None, None, false)
			.node_key(&tempdir.path().into(), Role::Authority, false)
			.is_ok());
	}

	#[test]
	fn rejects_ed25519_hex_node_key() {
		let key = "0000000000000000000000000000000000000000000000000000000000000001";
		assert!(params(Some(key.into()), None, false)
			.node_key(&PathBuf::from("x"), Role::Full, false)
			.is_err());
	}

	#[test]
	fn rejects_legacy_secret_ed25519_file() {
		let tempdir = TempDir::new().unwrap();
		let _ = File::create(tempdir.path().join(NODE_KEY_ED25519_FILE_LEGACY)).unwrap();
		assert!(params(None, None, true)
			.node_key(&tempdir.path().into(), Role::Authority, false)
			.is_err());
	}

	#[test]
	fn file_roundtrip_peer_id_stable() {
		let tmp = tempfile::Builder::new().prefix("alice").tempdir().expect("tempdir");
		let file = tmp.path().join("mysecret");
		let sk = libp2p_identity::mldsa65::SecretKey::generate();
		let expected =
			libp2p_identity::Keypair::from(libp2p_identity::mldsa65::Keypair::from(sk.clone()))
				.public()
				.to_peer_id();

		for contents in [sk.as_ref().to_vec(), array_bytes::bytes2hex("", sk.as_ref()).into_bytes()]
		{
			fs::write(&file, contents).expect("write");
			let kp = params(None, Some(file.clone()), false)
				.node_key(&PathBuf::from("not-used"), Role::Authority, false)
				.expect("config")
				.into_keypair()
				.expect("keypair");
			assert_eq!(kp.public().to_peer_id(), expected);
		}
	}
}
