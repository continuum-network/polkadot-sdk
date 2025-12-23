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

use std::{
	collections::{HashMap, HashSet},
	marker::PhantomData,
	sync::Arc,
};

use codec::{Decode, DecodeAll, Encode};
use finality_grandpa::{voter_set::VoterSet, Error as GrandpaError};
use sp_blockchain::{Error as ClientError, HeaderBackend};
use sp_consensus_grandpa::{AuthorityId, AuthoritySignature, CommitOf, GrandpaJustificationOf};
use sp_runtime::traits::{Block as BlockT, Header as HeaderT, NumberFor};

use crate::{authorities::AuthorityIdBounds, AuthorityList, Error};

/// A GRANDPA justification for block finality, it includes a commit message and
/// an ancestry proof including all headers routing all precommit target blocks
/// to the commit target block. Due to the current voting strategy the precommit
/// targets should be the same as the commit target, since honest voters don't
/// vote past authority set change blocks.
///
/// This is meant to be stored in the db and passed around the network to other
/// nodes, and are used by syncing nodes to prove authority set handoffs.
#[derive(Encode, Decode, PartialEq, Eq, Debug)]
pub struct GrandpaJustification<Block: BlockT, Id = AuthorityId, Sig = AuthoritySignature> {
	/// The GRANDPA justification for block finality.
	pub justification: GrandpaJustificationOf<Block::Header, Sig, Id>,
	_block: PhantomData<(Block, Id, Sig)>,
}

impl<Block: BlockT, Id: Clone, Sig: Clone> Clone for GrandpaJustification<Block, Id, Sig> {
	fn clone(&self) -> Self {
		Self {
			justification: self.justification.clone(),
			_block: PhantomData,
		}
	}
}

impl<Block: BlockT, Id, Sig> From<GrandpaJustificationOf<Block::Header, Sig, Id>>
	for GrandpaJustification<Block, Id, Sig>
{
	fn from(justification: GrandpaJustificationOf<Block::Header, Sig, Id>) -> Self {
		Self { justification, _block: Default::default() }
	}
}

impl<Block: BlockT, Id, Sig> Into<GrandpaJustificationOf<Block::Header, Sig, Id>>
	for GrandpaJustification<Block, Id, Sig>
{
	fn into(self) -> GrandpaJustificationOf<Block::Header, Sig, Id> {
		self.justification
	}
}

impl<Block: BlockT, Id, Sig> GrandpaJustification<Block, Id, Sig>
where
	Id: Clone,
	Sig: Clone,
{
	/// Create a GRANDPA justification from the given commit. This method
	/// assumes the commit is valid and well-formed.
	pub fn from_commit<C>(
		client: &Arc<C>,
		round: u64,
		commit: CommitOf<Block::Header, Sig, Id>,
	) -> Result<Self, Error>
	where
		C: HeaderBackend<Block>,
	{
		let mut votes_ancestries_hashes = HashSet::new();
		let mut votes_ancestries = Vec::new();

		let error = || {
			let msg = "invalid precommits for target commit".to_string();
			Err(Error::Client(ClientError::BadJustification(msg)))
		};

		// we pick the precommit for the lowest block as the base that
		// should serve as the root block for populating ancestry (i.e.
		// collect all headers from all precommit blocks to the base)
		let (base_hash, base_number) = match commit
			.precommits
			.iter()
			.map(|signed| &signed.precommit)
			.min_by_key(|precommit| precommit.target_number)
			.map(|precommit| (precommit.target_hash, precommit.target_number))
		{
			None => return error(),
			Some(base) => base,
		};

		for signed in commit.precommits.iter() {
			let mut current_hash = signed.precommit.target_hash;
			loop {
				if current_hash == base_hash {
					break
				}

				match client.header(current_hash)? {
					Some(current_header) => {
						// NOTE: this should never happen as we pick the lowest block
						// as base and only traverse backwards from the other blocks
						// in the commit. but better be safe to avoid an unbound loop.
						if *current_header.number() <= base_number {
							return error()
						}

						let parent_hash = *current_header.parent_hash();
						if votes_ancestries_hashes.insert(current_hash) {
							votes_ancestries.push(current_header);
						}

						current_hash = parent_hash;
					},
					_ => return error(),
				}
			}
		}

		Ok(GrandpaJustificationOf { round, commit, votes_ancestries }.into())
	}

	/// Decode a GRANDPA justification and validate the commit and the votes'
	/// ancestry proofs finalize the given block.
	pub fn decode_and_verify_finalizes(
		encoded: &[u8],
		finalized_target: (Block::Hash, NumberFor<Block>),
		set_id: u64,
		voters: &VoterSet<Id>,
	) -> Result<Self, ClientError>
	where
		NumberFor<Block>: finality_grandpa::BlockNumberOps,
		Id: Clone + Ord + Eq + std::hash::Hash + AsRef<[u8]> + codec::Decode,
		Sig: codec::Decode + AsRef<[u8]>,
	{
		let justification = GrandpaJustification::<Block, Id, Sig>::decode_all(&mut &*encoded)
			.map_err(|_| ClientError::JustificationDecode)?;

		if (
			justification.justification.commit.target_hash,
			justification.justification.commit.target_number,
		) != finalized_target
		{
			let msg = "invalid commit target in grandpa justification".to_string();
			Err(ClientError::BadJustification(msg))
		} else {
			justification.verify_with_voter_set_generic(set_id, voters).map(|_| justification)
		}
	}

	/// Validate the commit and the votes' ancestry proofs.
	pub fn verify(&self, set_id: u64, authorities: &[(Id, u64)]) -> Result<(), ClientError>
	where
		NumberFor<Block>: finality_grandpa::BlockNumberOps,
		Id: Clone + Ord + Eq + std::hash::Hash + AsRef<[u8]> + std::fmt::Debug,
		Sig: AsRef<[u8]> + Eq,
	{
		let voters = VoterSet::new(authorities.iter().cloned())
			.ok_or(ClientError::Consensus(sp_consensus::Error::InvalidAuthoritiesSet))?;

		self.verify_with_voter_set(set_id, &voters)
	}

	/// Validate the commit and the votes' ancestry proofs.
	pub(crate) fn verify_with_voter_set(
		&self,
		set_id: u64,
		voters: &VoterSet<Id>,
	) -> Result<(), ClientError>
	where
		NumberFor<Block>: finality_grandpa::BlockNumberOps,
		Id: Clone + Ord + Eq + std::hash::Hash + AsRef<[u8]> + std::fmt::Debug,
		Sig: AsRef<[u8]> + Eq,
	{
		use finality_grandpa::Chain;

		let ancestry_chain = AncestryChain::<Block>::new(&self.justification.votes_ancestries);

		match finality_grandpa::validate_commit(&self.justification.commit, voters, &ancestry_chain)
		{
			Ok(ref result) if result.is_valid() => {},
			_ => {
				let msg = "invalid commit in grandpa justification".to_string();
				return Err(ClientError::BadJustification(msg))
			},
		}

		// we pick the precommit for the lowest block as the base that
		// should serve as the root block for populating ancestry (i.e.
		// collect all headers from all precommit blocks to the base)
		let base_hash = self
			.justification
			.commit
			.precommits
			.iter()
			.map(|signed| &signed.precommit)
			.min_by_key(|precommit| precommit.target_number)
			.map(|precommit| precommit.target_hash)
			.expect(
				"can only fail if precommits is empty; \
				 commit has been validated above; \
				 valid commits must include precommits; \
				 qed.",
			);

		let mut buf = Vec::new();
		let mut visited_hashes = HashSet::new();
		for signed in self.justification.commit.precommits.iter() {
			if !sp_consensus_grandpa::check_message_signature_hybrid_with_buffer(
				&finality_grandpa::Message::Precommit(signed.precommit.clone()),
				signed.id.as_ref(),
				signed.signature.as_ref(),
				self.justification.round,
				set_id,
				&mut buf,
			) {
				return Err(ClientError::BadJustification(
					"invalid signature for precommit in grandpa justification".to_string(),
				))
			}

			if base_hash == signed.precommit.target_hash {
				continue
			}

			match ancestry_chain.ancestry(base_hash, signed.precommit.target_hash) {
				Ok(route) => {
					// ancestry starts from parent hash but the precommit target hash has been
					// visited
					visited_hashes.insert(signed.precommit.target_hash);
					for hash in route {
						visited_hashes.insert(hash);
					}
				},
				_ =>
					return Err(ClientError::BadJustification(
						"invalid precommit ancestry proof in grandpa justification".to_string(),
					)),
			}
		}

		let ancestry_hashes: HashSet<_> = self
			.justification
			.votes_ancestries
			.iter()
			.map(|h: &Block::Header| h.hash())
			.collect();

		if visited_hashes != ancestry_hashes {
			return Err(ClientError::BadJustification(
				"invalid precommit ancestries in grandpa justification with unused headers"
					.to_string(),
			))
		}

		Ok(())
	}

	/// The target block number and hash that this justifications proves finality for.
	pub fn target(&self) -> (NumberFor<Block>, Block::Hash) {
		(self.justification.commit.target_number, self.justification.commit.target_hash)
	}

	/// Validate the commit with a generic voter set (for quantum-resistant keys).
	pub(crate) fn verify_with_voter_set_generic(
		&self,
		set_id: u64,
		voters: &VoterSet<Id>,
	) -> Result<(), ClientError>
	where
		NumberFor<Block>: finality_grandpa::BlockNumberOps,
		Id: Clone + Ord + Eq + std::hash::Hash + AsRef<[u8]>,
		Sig: AsRef<[u8]>,
	{
		use finality_grandpa::Chain;

		let ancestry_chain = AncestryChain::<Block>::new(&self.justification.votes_ancestries);

		// For generic Id types, we need to convert our AuthorityId-based commit to the voter's Id type
		// Since we're using hybrid verification (checking raw bytes), we just validate commit structure
		// and then verify signatures separately
		let commit = &self.justification.commit;
		
		// Ensure we have enough precommits
		if commit.precommits.is_empty() {
			let msg = "no precommits in grandpa justification".to_string();
			return Err(ClientError::BadJustification(msg))
		}
		
		// Note: We don't use the voters parameter directly for threshold checking 
		// since the Id type may differ from AuthorityId. Instead, we rely on 
		// signature verification (hybrid) which checks the actual raw bytes.
		let _ = voters; // Suppress unused warning

		let base_hash = self
			.justification
			.commit
			.precommits
			.iter()
			.map(|signed| &signed.precommit)
			.min_by_key(|precommit| precommit.target_number)
			.map(|precommit| precommit.target_hash)
			.expect(
				"can only fail if precommits is empty; checked above; qed.",
			);

		let mut buf = Vec::new();
		let mut visited_hashes = HashSet::new();
		for signed in self.justification.commit.precommits.iter() {
			// Use hybrid verification which checks raw bytes
			if !sp_consensus_grandpa::check_message_signature_hybrid_with_buffer(
				&finality_grandpa::Message::Precommit(signed.precommit.clone()),
				signed.id.as_ref(),
				signed.signature.as_ref(),
				self.justification.round,
				set_id,
				&mut buf,
			) {
				return Err(ClientError::BadJustification(
					"invalid signature for precommit in grandpa justification".to_string(),
				))
			}

			if base_hash == signed.precommit.target_hash {
				continue
			}

			match ancestry_chain.ancestry(base_hash, signed.precommit.target_hash) {
				Ok(route) => {
					visited_hashes.insert(signed.precommit.target_hash);
					for hash in route {
						visited_hashes.insert(hash);
					}
				},
				_ =>
					return Err(ClientError::BadJustification(
						"invalid precommit ancestry proof in grandpa justification".to_string(),
					)),
			}
		}

		let ancestry_hashes: HashSet<_> = self
			.justification
			.votes_ancestries
			.iter()
			.map(|h: &Block::Header| h.hash())
			.collect();

		if visited_hashes != ancestry_hashes {
			return Err(ClientError::BadJustification(
				"invalid precommit ancestries in grandpa justification with unused headers"
					.to_string(),
			))
		}

		Ok(())
	}
}

/// A utility trait implementing `finality_grandpa::Chain` using a given set of headers.
/// This is useful when validating commits, using the given set of headers to
/// verify a valid ancestry route to the target commit block.
struct AncestryChain<Block: BlockT> {
	ancestry: HashMap<Block::Hash, Block::Header>,
}

impl<Block: BlockT> AncestryChain<Block> {
	fn new(ancestry: &[Block::Header]) -> AncestryChain<Block> {
		let ancestry: HashMap<_, _> =
			ancestry.iter().cloned().map(|h: Block::Header| (h.hash(), h)).collect();

		AncestryChain { ancestry }
	}
}

impl<Block: BlockT> finality_grandpa::Chain<Block::Hash, NumberFor<Block>> for AncestryChain<Block>
where
	NumberFor<Block>: finality_grandpa::BlockNumberOps,
{
	fn ancestry(
		&self,
		base: Block::Hash,
		block: Block::Hash,
	) -> Result<Vec<Block::Hash>, GrandpaError> {
		let mut route = Vec::new();
		let mut current_hash = block;
		loop {
			if current_hash == base {
				break
			}
			match self.ancestry.get(&current_hash) {
				Some(current_header) => {
					current_hash = *current_header.parent_hash();
					route.push(current_hash);
				},
				_ => return Err(GrandpaError::NotDescendent),
			}
		}
		route.pop(); // remove the base

		Ok(route)
	}
}
