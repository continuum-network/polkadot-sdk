// Copyright (C) Continuum Network.
// Continuum Phase 10.2 / 9.13 Definition of Done:
// Dilithium (ML-DSA-65) GRANDPA authorities generate a warp-sync proof that
// successfully verifies across at least one authority-set change.

use codec::{Decode, Encode};
use finality_grandpa::{Commit, Precommit, SignedPrecommit};
use pqcrypto_mldsa::mldsa65;
use pqcrypto_traits::sign::{DetachedSignature, PublicKey as _, SecretKey as _};
use sc_block_builder::BlockBuilderBuilder;
use sc_consensus_grandpa::{
	warp_proof::WarpSyncProof, AuthoritySetChanges, GrandpaJustification,
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
	BlockBuilderExt, ClientBlockImportExt, ClientExt, DefaultTestClientBuilderExt, TestClientBuilder,
	TestClientBuilderExt,
};

type TestBlock = substrate_test_runtime_client::runtime::Block;
type TestHash = <TestBlock as BlockT>::Hash;
type TestNumber = <<TestBlock as BlockT>::Header as HeaderT>::Number;

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

#[test]
fn warp_sync_proof_generate_verify_dilithium_across_authority_set_change() {
	let builder = TestClientBuilder::new();
	let backend = builder.backend();
	let client = Arc::new(builder.build());

	let alice = generate_authority();
	let bob = generate_authority();

	let genesis_authorities = vec![(alice.id.clone(), 1u64)];
	let mut current_authorities: Vec<&DilithiumAuthority> = vec![&alice];
	let mut current_set_id = 0u64;
	let mut authority_set_changes = Vec::new();

	// Block 1: no set change.
	{
		let block = BlockBuilderBuilder::new(&*client)
			.on_parent_block(client.chain_info().best_hash)
			.with_parent_block_number(client.chain_info().best_number)
			.build()
			.expect("block builder")
			.build()
			.expect("build block 1")
			.block;
		futures::executor::block_on(client.import(BlockOrigin::Own, block)).expect("import 1");
	}

	// Block 2: schedule change Alice → Bob (delay 0), finalize with Alice.
	let change_block_number = {
		let next_authorities = vec![(bob.id.clone(), 1u64)];
		let digest = sp_runtime::generic::DigestItem::Consensus(
			GRANDPA_ENGINE_ID,
			ConsensusLogOf::<TestNumber, DilithiumId>::ScheduledChange(ScheduledChangeOf {
				delay: 0u64,
				next_authorities,
			})
			.encode(),
		);

		let mut block_builder = BlockBuilderBuilder::new(&*client)
			.on_parent_block(client.chain_info().best_hash)
			.with_parent_block_number(client.chain_info().best_number)
			.build()
			.expect("block builder");
		block_builder
			.push_deposit_log_digest_item(digest)
			.expect("push scheduled change digest");
		let block = block_builder.build().expect("build block 2").block;
		let number = *block.header().number();
		futures::executor::block_on(client.import(BlockOrigin::Own, block)).expect("import 2");

		let (target_hash, target_number) = {
			let info = client.info();
			(info.best_hash, info.best_number)
		};

		let mut precommits = Vec::new();
		for authority in &current_authorities {
			let precommit = Precommit { target_hash, target_number };
			let signature = sign_precommit(authority, 42, current_set_id, &precommit);
			precommits.push(SignedPrecommit {
				precommit,
				signature,
				id: authority.id.clone(),
			});
		}

		let commit = Commit { target_hash, target_number, precommits };
		let justification =
			GrandpaJustification::<TestBlock, DilithiumId, DilithiumSig>::from_commit(
				&client, 42, commit,
			)
			.expect("justification from Alice commit");

		client
			.finalize_block(target_hash, Some((GRANDPA_ENGINE_ID, justification.encode())))
			.expect("finalize set-change block");

		authority_set_changes.push((current_set_id, number));
		current_set_id += 1;
		current_authorities = vec![&bob];
		number
	};

	// Block 3: finalize under Bob so generate() can append a finishing justification
	// past the set-change fragment (see WarpSyncProof::generate limit logic).
	{
		let block = BlockBuilderBuilder::new(&*client)
			.on_parent_block(client.chain_info().best_hash)
			.with_parent_block_number(client.chain_info().best_number)
			.build()
			.expect("block builder")
			.build()
			.expect("build block 3")
			.block;
		futures::executor::block_on(client.import(BlockOrigin::Own, block)).expect("import 3");

		let (target_hash, target_number) = {
			let info = client.info();
			(info.best_hash, info.best_number)
		};

		let mut precommits = Vec::new();
		for authority in &current_authorities {
			let precommit = Precommit { target_hash, target_number };
			let signature = sign_precommit(authority, 43, current_set_id, &precommit);
			precommits.push(SignedPrecommit {
				precommit,
				signature,
				id: authority.id.clone(),
			});
		}

		let commit = Commit { target_hash, target_number, precommits };
		let justification =
			GrandpaJustification::<TestBlock, DilithiumId, DilithiumSig>::from_commit(
				&client, 43, commit,
			)
			.expect("justification from Bob commit");

		client
			.finalize_block(target_hash, Some((GRANDPA_ENGINE_ID, justification.encode())))
			.expect("finalize post-change block");
	}

	let authority_set_changes = AuthoritySetChanges::from(authority_set_changes);
	let genesis_hash = client.hash(0).expect("hash lookup").expect("genesis hash");

	let warp_sync_proof = WarpSyncProof::<TestBlock, DilithiumId, DilithiumSig>::generate(
		&*backend,
		genesis_hash,
		&authority_set_changes,
	)
	.expect("Dilithium warp sync proof must generate across a set change");

	let (new_set_id, new_authorities) = warp_sync_proof
		.verify(0, genesis_authorities, &Default::default())
		.expect("Dilithium warp sync proof must verify across the authority-set change");

	assert_eq!(
		new_set_id, current_set_id,
		"verify must advance past the set change finalized at #{change_block_number}"
	);
	assert_eq!(new_authorities, vec![(bob.id.clone(), 1u64)]);
}
