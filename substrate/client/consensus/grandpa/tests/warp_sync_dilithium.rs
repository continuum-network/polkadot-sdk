// Copyright (C) Continuum Network.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Dilithium (ML-DSA-65) GRANDPA authorities generate a warp-sync proof that verifies across an
//! authority-set change, and the verifier rejects proofs checked against the wrong authority set,
//! the wrong set id, or carrying a tampered signature.

use codec::{Decode, Encode};
use finality_grandpa::{Commit, Precommit, SignedPrecommit};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _};
use sc_block_builder::BlockBuilderBuilder;
use sc_consensus_grandpa::{
	warp_proof::{Error, WarpSyncProof},
	AuthoritySetChanges, GrandpaJustification,
};
use sp_blockchain::HeaderBackend;
use sp_consensus::BlockOrigin;
use sp_consensus_grandpa::{
	ConsensusLogOf, ScheduledChangeOf, DILITHIUM3_PUBLIC_KEY_SIZE, DILITHIUM3_SIGNATURE_SIZE,
	GRANDPA_ENGINE_ID,
};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT};
use std::sync::Arc;
use substrate_test_runtime_client::{
	BlockBuilderExt, ClientBlockImportExt, ClientExt, DefaultTestClientBuilderExt,
	TestClientBuilder, TestClientBuilderExt,
};

type TestBlock = substrate_test_runtime_client::runtime::Block;
type TestHash = <TestBlock as BlockT>::Hash;
type TestNumber = <<TestBlock as BlockT>::Header as HeaderT>::Number;
type Proof = WarpSyncProof<TestBlock, DilithiumId, DilithiumSig>;

/// Opaque Dilithium GRANDPA authority id (1952 bytes).
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Encode, Decode)]
struct DilithiumId([u8; DILITHIUM3_PUBLIC_KEY_SIZE]);

impl AsRef<[u8]> for DilithiumId {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

/// Opaque Dilithium GRANDPA signature (3309 bytes).
#[derive(Clone, Debug, PartialEq, Eq, Encode, Decode)]
struct DilithiumSig([u8; DILITHIUM3_SIGNATURE_SIZE]);

impl AsRef<[u8]> for DilithiumSig {
	fn as_ref(&self) -> &[u8] {
		&self.0
	}
}

struct DilithiumAuthority {
	id: DilithiumId,
	sk: mldsa65::SecretKey,
}

fn generate_authority() -> DilithiumAuthority {
	let (pk, sk) = mldsa65::keypair();
	let mut id = [0u8; DILITHIUM3_PUBLIC_KEY_SIZE];
	id.copy_from_slice(pk.as_bytes());
	DilithiumAuthority { id: DilithiumId(id), sk }
}

fn sign_precommit(
	authority: &DilithiumAuthority,
	round: u64,
	set_id: u64,
	precommit: &Precommit<TestHash, TestNumber>,
) -> DilithiumSig {
	let msg = finality_grandpa::Message::Precommit(precommit.clone());
	let encoded = sp_consensus_grandpa::localized_payload(round, set_id, &msg);
	let sig = mldsa65::detached_sign(&encoded, &authority.sk);
	let mut bytes = [0u8; DILITHIUM3_SIGNATURE_SIZE];
	bytes.copy_from_slice(sig.as_bytes());
	DilithiumSig(bytes)
}

fn assert_invalid<T: std::fmt::Debug>(result: Result<T, Error>) {
	assert!(matches!(result, Err(Error::InvalidProof(_))), "expected InvalidProof, got {result:?}");
}

struct Chain {
	proof: Proof,
	alice: DilithiumAuthority,
	bob: DilithiumAuthority,
}

/// Builds genesis -> #1 -> #2 (schedules Alice -> Bob, finalized by Alice in set 0) -> #3
/// (finalized by Bob in set 1) and generates a warp proof from genesis.
fn build_chain() -> Chain {
	let builder = TestClientBuilder::new();
	let backend = builder.backend();
	let client = Arc::new(builder.build());

	let alice = generate_authority();
	let bob = generate_authority();

	let import_block = |digest: Option<sp_runtime::generic::DigestItem>| {
		let mut block_builder = BlockBuilderBuilder::new(&*client)
			.on_parent_block(client.chain_info().best_hash)
			.with_parent_block_number(client.chain_info().best_number)
			.build()
			.expect("block builder");
		if let Some(digest) = digest {
			block_builder.push_deposit_log_digest_item(digest).expect("push digest");
		}
		let block = block_builder.build().expect("build block").block;
		futures::executor::block_on(client.import(BlockOrigin::Own, block)).expect("import");
		let info = client.info();
		(info.best_hash, info.best_number)
	};

	let finalize = |authority: &DilithiumAuthority, round: u64, set_id: u64, target| {
		let (target_hash, target_number) = target;
		let precommit = Precommit { target_hash, target_number };
		let signature = sign_precommit(authority, round, set_id, &precommit);
		let commit = Commit {
			target_hash,
			target_number,
			precommits: vec![SignedPrecommit { precommit, signature, id: authority.id.clone() }],
		};
		let justification =
			GrandpaJustification::<TestBlock, DilithiumId, DilithiumSig>::from_commit(
				&client, round, commit,
			)
			.expect("justification from commit");
		client
			.finalize_block(target_hash, Some((GRANDPA_ENGINE_ID, justification.encode())))
			.expect("finalize");
	};

	import_block(None);

	let digest = sp_runtime::generic::DigestItem::Consensus(
		GRANDPA_ENGINE_ID,
		ConsensusLogOf::<TestNumber, DilithiumId>::ScheduledChange(ScheduledChangeOf {
			delay: 0u64,
			next_authorities: vec![(bob.id.clone(), 1u64)],
		})
		.encode(),
	);
	let change = import_block(Some(digest));
	finalize(&alice, 42, 0, change);

	// A finalized block under Bob lets `generate` append a finishing justification.
	let tip = import_block(None);
	finalize(&bob, 43, 1, tip);

	let authority_set_changes = AuthoritySetChanges::from(vec![(0u64, change.1)]);
	let genesis_hash = client.hash(0).expect("hash lookup").expect("genesis hash");
	let proof = Proof::generate(&*backend, genesis_hash, &authority_set_changes)
		.expect("Dilithium warp sync proof must generate across a set change");

	Chain { proof, alice, bob }
}

#[test]
fn warp_sync_proof_generate_verify_dilithium_across_authority_set_change() {
	let Chain { proof, alice, bob } = build_chain();

	// Round-trips through the wire encoding with the Dilithium types.
	let proof = Proof::decode(&mut &proof.encode()[..]).expect("proof decodes");

	let (new_set_id, new_authorities) = proof
		.verify(0, vec![(alice.id.clone(), 1u64)], &Default::default())
		.expect("Dilithium warp sync proof must verify across the authority-set change");

	assert_eq!(new_set_id, 1);
	assert_eq!(new_authorities, vec![(bob.id.clone(), 1u64)]);
}

#[test]
fn warp_sync_proof_dilithium_rejects_wrong_authorities_or_set_id() {
	let Chain { proof, alice, bob } = build_chain();

	// Starting from Bob skips set 0: Alice's justification must not be accepted for him.
	assert_invalid(proof.verify(0, vec![(bob.id.clone(), 1u64)], &Default::default()));

	// Signatures are bound to the set id.
	assert_invalid(proof.verify(1, vec![(alice.id.clone(), 1u64)], &Default::default()));

	// Alice alone holds 1 of 3 weight, below the 2/3 supermajority threshold.
	let other = generate_authority();
	assert_invalid(proof.verify(
		0,
		vec![(alice.id.clone(), 1u64), (other.id.clone(), 2u64)],
		&Default::default(),
	));
}

#[test]
fn warp_sync_proof_dilithium_rejects_tampered_signature() {
	let Chain { proof, alice, .. } = build_chain();

	let mut encoded = proof.encode();
	// Flip a byte inside the first 3309-byte signature; locate it by searching for the encoded
	// signer id, which immediately follows the signature in `SignedPrecommit`.
	let id_pos = encoded
		.windows(DILITHIUM3_PUBLIC_KEY_SIZE)
		.position(|w| w == alice.id.as_ref())
		.expect("alice id is in the proof");
	encoded[id_pos - 1] ^= 0x01;

	let tampered = Proof::decode(&mut &encoded[..]).expect("tampered proof still decodes");
	assert_invalid(tampered.verify(0, vec![(alice.id.clone(), 1u64)], &Default::default()));
}
