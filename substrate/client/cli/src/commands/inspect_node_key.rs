// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of the `inspect-node-key` subcommand (Continuum: ML-DSA-65).

use crate::Error;
use clap::Parser;
use libp2p_identity::Keypair;
use std::{
	fs,
	io::{self, Read},
	path::PathBuf,
};

/// The `inspect-node-key` command
#[derive(Debug, Parser)]
#[command(
	name = "inspect-node-key",
	about = "Load a Continuum ML-DSA-65 node key from a file or stdin and print the peer-id."
)]
pub struct InspectNodeKeyCmd {
	/// Name of file to read the secret key from.
	/// If not given, the secret key is read from stdin (up to EOF).
	#[arg(long)]
	file: Option<PathBuf>,

	/// The input is in raw binary format.
	/// If not given, the input is read as an hex encoded string.
	#[arg(long)]
	bin: bool,

	/// This argument is deprecated and has no effect for this command.
	#[deprecated(note = "Network identifier is not used for node-key inspection")]
	#[arg(short = 'n', long = "network", value_name = "NETWORK", ignore_case = true)]
	pub network_scheme: Option<String>,
}

impl InspectNodeKeyCmd {
	/// runs the command
	pub fn run(&self) -> Result<(), Error> {
		let mut file_data = match &self.file {
			Some(file) => fs::read(&file)?,
			None => {
				let mut buf = Vec::with_capacity(libp2p_identity::mldsa65::SECRET_MATERIAL_LENGTH);
				io::stdin().lock().read_to_end(&mut buf)?;
				buf
			},
		};

		if !self.bin {
			let keyhex = String::from_utf8_lossy(&file_data);
			file_data = array_bytes::hex2bytes(keyhex.trim())
				.map_err(|_| "failed to decode secret as hex")?;
		}

		if file_data.len() == 32 || file_data.len() == 64 {
			return Err(Error::Input(
				"ed25519-sized node key rejected; Continuum requires ML-DSA-65 secret_mldsa65 \
				 (secret||public, 5984 bytes)"
					.into(),
			))
		}

		let keypair =
			Keypair::mldsa65_from_bytes(&mut file_data).map_err(|_| "Bad ML-DSA-65 node key file")?;

		println!("{}", keypair.public().to_peer_id());

		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use crate::commands::generate_node_key::GenerateNodeKeyCmd;

	use super::*;

	#[test]
	fn inspect_node_key() {
		let path = tempfile::tempdir().unwrap().into_path().join("node-id").into_os_string();
		let path = path.to_str().unwrap();
		let cmd = GenerateNodeKeyCmd::parse_from(&["generate-node-key", "--file", path, "--bin"]);

		assert!(cmd.run("test", &String::from("test")).is_ok());

		let cmd = InspectNodeKeyCmd::parse_from(&["inspect-node-key", "--file", path, "--bin"]);
		assert!(cmd.run().is_ok());
	}
}
