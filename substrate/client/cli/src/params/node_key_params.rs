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
	/// Continuum no longer accepts 64-hex ed25519 seeds. Prefer `--node-key-file`
	/// pointing at Continuum `secret_mldsa65` material (5984 raw bytes =
	/// ML-DSA-65 secret||public). If set, this value must be hex-encoded
	/// Continuum secret material (11968 hex chars).
	///
	/// WARNING: Secrets provided as command-line arguments are easily exposed.
	/// Use `--node-key-file` for anything beyond throwaway local tests.
	#[arg(long, value_name = "KEY")]
	pub node_key: Option<String>,

	/// Crypto primitive to use for p2p networking.
	///
	/// Continuum only supports `mldsa65`.
	#[arg(long, value_name = "TYPE", value_enum, ignore_case = true, default_value_t = NodeKeyType::MlDsa65)]
	pub node_key_type: NodeKeyType,

	/// File from which to read the node's secret key to use for p2p networking.
	///
	/// Continuum: raw or hex-encoded `secret||public` ML-DSA-65 material (5984 bytes).
	/// Default filename in the network config dir is `secret_mldsa65`.
	#[arg(long, value_name = "FILE")]
	pub node_key_file: Option<PathBuf>,

	/// Forces key generation if node-key-file file does not exist.
	///
	/// This is an unsafe feature for production networks, because as an active authority
	/// other authorities may depend on your node having a stable identity and they might
	/// not being able to reach you if your identity changes after entering the active set.
	///
	/// For minimal node downtime if no custom `node-key-file` argument is provided
	/// the network-key is usually persisted across nodes restarts,
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
						)))
					}

					if !self.unsafe_force_node_key_generation &&
						role.is_authority() && !is_dev &&
						!key_path.exists()
					{
						return Err(Error::NetworkKeyNotFound(key_path))
					}
					sc_network::config::Secret::File(key_path)
				};

				Ok(NodeKeyConfig::MlDsa65(secret))
			},
		}
	}
}

fn invalid_node_key(e: impl std::fmt::Display) -> error::Error {
	error::Error::Input(format!("Invalid node key: {}", e))
}

fn parse_mldsa65_secret_hex(
	hex: &str,
) -> error::Result<sc_network::config::MlDsa65Secret> {
	let trimmed = hex.trim();
	// Explicitly reject classical ed25519 64-hex seeds.
	if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
		return Err(invalid_node_key(
			"64-hex ed25519 --node-key is not supported on Continuum; \
			 use --node-key-file with secret_mldsa65 (ML-DSA-65 secret||public)",
		))
	}
	let mut raw = array_bytes::hex2bytes(trimmed)
		.map_err(|e| invalid_node_key(format!("{:?}", e)))?;
	libp2p_identity::mldsa65::SecretKey::try_from_bytes(&mut raw)
		.map(sc_network::config::Secret::Input)
		.map_err(invalid_node_key)
}

#[cfg(test)]
mod tests {
	use super::*;
	use sc_network::config::NODE_KEY_MLDSA65_FILE;
	use std::fs::{self, File};
	use tempfile::TempDir;

	#[test]
	fn test_node_key_config_default_path() {
		let dir = PathBuf::from("x");
		let params = NodeKeyParams {
			node_key_type: NodeKeyType::MlDsa65,
			node_key: None,
			node_key_file: None,
			unsafe_force_node_key_generation: true,
		};
		match params.node_key(&dir, Role::Authority, false).unwrap() {
			NodeKeyConfig::MlDsa65(sc_network::config::Secret::File(ref f)) => {
				assert_eq!(f, &dir.join(NODE_KEY_MLDSA65_FILE));
			},
		}
	}

	#[test]
	fn rejects_ed25519_hex_node_key() {
		let params = NodeKeyParams {
			node_key_type: NodeKeyType::MlDsa65,
			node_key: Some("0000000000000000000000000000000000000000000000000000000000000001".into()),
			node_key_file: None,
			unsafe_force_node_key_generation: false,
		};
		assert!(params.node_key(&PathBuf::from("x"), Role::Full, false).is_err());
	}

	#[test]
	fn rejects_legacy_secret_ed25519_file() {
		let tempdir = TempDir::new().unwrap();
		let _ = File::create(tempdir.path().join(NODE_KEY_ED25519_FILE_LEGACY)).unwrap();
		let params = NodeKeyParams {
			node_key_type: NodeKeyType::MlDsa65,
			node_key: None,
			node_key_file: None,
			unsafe_force_node_key_generation: true,
		};
		assert!(params
			.node_key(&tempdir.path().into(), Role::Authority, false)
			.is_err());
	}

	#[test]
	fn file_roundtrip_peer_id_stable() {
		let tmp = tempfile::Builder::new().prefix("alice").tempdir().expect("tempdir");
		let file = tmp.path().join("mysecret");
		let sk = libp2p_identity::mldsa65::SecretKey::generate();
		fs::write(&file, sk.as_ref()).expect("write");

		let params = NodeKeyParams {
			node_key_type: NodeKeyType::MlDsa65,
			node_key: None,
			node_key_file: Some(file.clone()),
			unsafe_force_node_key_generation: false,
		};
		let kp1 = params
			.node_key(&PathBuf::from("not-used"), Role::Authority, false)
			.expect("config")
			.into_keypair()
			.expect("kp");
		let kp2 = NodeKeyConfig::MlDsa65(sc_network::config::Secret::File(file))
			.into_keypair()
			.expect("kp2");
		assert_eq!(kp1.public().to_peer_id(), kp2.public().to_peer_id());
	}
}
