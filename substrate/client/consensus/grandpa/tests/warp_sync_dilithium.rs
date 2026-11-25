// Copyright (C) Continuum Network.
// SPDX-License-Identifier: GPL-3.0-or-later WITH Classpath-exception-2.0

//! Dilithium (ML-DSA-65) GRANDPA authorities generate a warp-sync proof that verifies across an
//! authority-set change, and the verifier rejects proofs checked against the wrong authority set,
//! the wrong set id, a sub-threshold commit, a header/justification mismatch, a non-final fragment
//! without a set-change digest, or a tampered signature.

use codec::{Decode, Encode};
use finality_grandpa::{Commit, Precommit, SignedPrecommit};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _};
use sc_block_builder::BlockBuilderBuilder;
use sc_consensus_grandpa::{
	warp_proof::{Error, WarpSyncFragment, WarpSyncProof},
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

/// Justification rejected by `finality_grandpa::validate_commit` (unknown voter or below the 2/3
/// threshold).
const INVALID_COMMIT: &str = "invalid commit in grandpa justification";

fn assert_invalid<T: std::fmt::Debug>(result: Result<T, Error>, expected: &str) {
	match result {
		Err(Error::InvalidProof(msg)) => {
			assert!(msg.contains(expected), "expected InvalidProof({expected:?}), got {msg:?}")
		},
		other => panic!("expected InvalidProof({expected:?}), got {other:?}"),
	}
}

/// Mirror of `WarpSyncProof`'s private fields; same SCALE layout, lets tests rebuild proofs.
#[derive(Encode, Decode)]
struct RawProof {
	proofs: Vec<Fragment>,
	is_finished: bool,
}

fn to_raw(proof: &Proof) -> RawProof {
	RawProof::decode(&mut &proof.encode()[..]).expect("same layout")
}

fn from_raw(raw: &RawProof) -> Proof {
	Proof::decode(&mut &raw.encode()[..]).expect("same layout")
}

type Fragment = WarpSyncFragment<TestBlock, DilithiumId, DilithiumSig>;

struct Chain {
	proof: Proof,
	alice: DilithiumAuthority,
	bob: DilithiumAuthority,
	/// Block #3 (no set-change digest) with Bob's set-1 justification. Not part of `proof`.
	tip: Fragment,
}

/// Builds genesis -> #1 -> #2 (schedules Alice -> Bob, finalized by Alice in set 0) -> #3
/// (finalized by Bob in set 1) and generates a warp proof from genesis.
fn build_chain() -> Chain {
	let alice = generate_authority();
	let (proof, bob, tip) = build_chain_signed_by(&[&alice]);
	Chain { proof, alice, bob, tip }
}

/// Like [`build_chain`], but block #2 is finalized by every authority in `set0_signers`.
/// Returns the proof, Bob (the sole set-1 authority) and the #3 fragment.
fn build_chain_signed_by(
	set0_signers: &[&DilithiumAuthority],
) -> (Proof, DilithiumAuthority, Fragment) {
	let builder = TestClientBuilder::new();
	let backend = builder.backend();
	let client = Arc::new(builder.build());

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

	let finalize = |signers: &[&DilithiumAuthority], round: u64, set_id: u64, target| {
		let (target_hash, target_number) = target;
		let precommit = Precommit { target_hash, target_number };
		let precommits = signers
			.iter()
			.map(|a| SignedPrecommit {
				precommit: precommit.clone(),
				signature: sign_precommit(a, round, set_id, &precommit),
				id: a.id.clone(),
			})
			.collect();
		let commit = Commit { target_hash, target_number, precommits };
		let justification =
			GrandpaJustification::<TestBlock, DilithiumId, DilithiumSig>::from_commit(
				&client, round, commit,
			)
			.expect("justification from commit");
		client
			.finalize_block(target_hash, Some((GRANDPA_ENGINE_ID, justification.encode())))
			.expect("finalize");
		justification
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
	finalize(set0_signers, 42, 0, change);

	// #3 is finalized under Bob; `generate` does not include it (no best justification in aux).
	let tip = import_block(None);
	let tip_justification = finalize(&[&bob], 43, 1, tip);
	let tip_header = client.header(tip.0).expect("header lookup").expect("tip header");
	let tip = Fragment { header: tip_header, justification: tip_justification };

	let authority_set_changes = AuthoritySetChanges::from(vec![(0u64, change.1)]);
	let genesis_hash = client.hash(0).expect("hash lookup").expect("genesis hash");
	let proof = Proof::generate(&*backend, genesis_hash, &authority_set_changes)
		.expect("Dilithium warp sync proof must generate across a set change");

	(proof, bob, tip)
}

#[test]
fn warp_sync_proof_generate_verify_dilithium_across_authority_set_change() {
	let Chain { proof, alice, bob, .. } = build_chain();

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
	let Chain { proof, alice, bob, .. } = build_chain();

	// Starting from Bob skips set 0: Alice's justification must not be accepted for him.
	assert_invalid(
		proof.verify(0, vec![(bob.id.clone(), 1u64)], &Default::default()),
		INVALID_COMMIT,
	);

	// Signatures are bound to the set id.
	assert_invalid(
		proof.verify(1, vec![(alice.id.clone(), 1u64)], &Default::default()),
		"outdated justification",
	);

	// Alice alone holds 1 of 3 weight, below the 2/3 supermajority threshold.
	let other = generate_authority();
	assert_invalid(
		proof.verify(
			0,
			vec![(alice.id.clone(), 1u64), (other.id.clone(), 2u64)],
			&Default::default(),
		),
		INVALID_COMMIT,
	);
}

/// Regression pin: the 2409 fork ignored the voter set and the 2/3 threshold. With 4 equal-weight
/// voters the threshold is 3, so 2 signatures must be rejected and 3 accepted.
#[test]
fn warp_sync_proof_dilithium_rejects_two_of_four_voters() {
	let v: Vec<DilithiumAuthority> = (0..4).map(|_| generate_authority()).collect();
	let voter_set: Vec<(DilithiumId, u64)> = v.iter().map(|a| (a.id.clone(), 1)).collect();

	let (two_signed, ..) = build_chain_signed_by(&[&v[0], &v[1]]);
	assert_invalid(two_signed.verify(0, voter_set.clone(), &Default::default()), INVALID_COMMIT);

	// Control: the same voter set accepts a 3-of-4 justification.
	let (three_signed, bob, _) = build_chain_signed_by(&[&v[0], &v[1], &v[2]]);
	let (set_id, authorities) = three_signed
		.verify(0, voter_set, &Default::default())
		.expect("3 of 4 voters reach the threshold");
	assert_eq!((set_id, authorities), (1, vec![(bob.id.clone(), 1u64)]));
}

#[test]
fn warp_sync_proof_dilithium_rejects_header_justification_mismatch() {
	let Chain { proof, alice, tip, .. } = build_chain();
	let mut raw = to_raw(&proof);
	// Alice's justification still finalizes #2, but the header is now #3.
	raw.proofs[0].header = tip.header;

	assert_invalid(
		from_raw(&raw).verify(0, vec![(alice.id.clone(), 1u64)], &Default::default()),
		"Mismatch between header and justification",
	);
}

#[test]
fn warp_sync_proof_dilithium_rejects_middle_fragment_without_set_change() {
	let Chain { bob, tip, .. } = build_chain();
	// Bob's valid #3 fragment has no set-change digest; as a non-final fragment it must fail.
	let tip_again = Fragment::decode(&mut &tip.encode()[..]).expect("fragment round-trips");
	let raw = RawProof { proofs: vec![tip, tip_again], is_finished: true };

	assert_invalid(
		from_raw(&raw).verify(1, vec![(bob.id.clone(), 1u64)], &Default::default()),
		"Header is missing authority set change digest",
	);
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
	assert_invalid(
		tampered.verify(0, vec![(alice.id.clone(), 1u64)], &Default::default()),
		"invalid signature for precommit in grandpa justification",
	);
}
