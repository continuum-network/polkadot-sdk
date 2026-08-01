// This file is part of Substrate.

// Copyright (C) Parity Technologies (UK) Ltd.
// SPDX-License-Identifier: Apache-2.0

// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// 	http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Primitives for GRANDPA integration, suitable for WASM compilation.

#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

#[cfg(feature = "serde")]
use serde::Serialize;

use alloc::vec::Vec;
use codec::{Codec, Decode, Encode};
use scale_info::TypeInfo;
#[cfg(feature = "std")]
use sp_keystore::KeystorePtr;
use sp_runtime::{
	traits::{Header as HeaderT, NumberFor},
	ConsensusEngineId, OpaqueValue, RuntimeDebug,
};

/// The log target to be used by client code.
pub const CLIENT_LOG_TARGET: &str = "grandpa";
/// The log target to be used by runtime code.
pub const RUNTIME_LOG_TARGET: &str = "runtime::grandpa";

/// Key type for GRANDPA module.
pub const KEY_TYPE: sp_core::crypto::KeyTypeId = sp_application_crypto::key_types::GRANDPA;

mod app {
	use sp_application_crypto::{app_crypto, ed25519, key_types::GRANDPA};
	app_crypto!(ed25519, GRANDPA);
}

sp_application_crypto::with_pair! {
	/// The grandpa crypto scheme defined via the keypair type.
	pub type AuthorityPair = app::Pair;
}

/// Identity of a Grandpa authority.
pub type AuthorityId = app::Public;

/// Signature for a Grandpa authority.
pub type AuthoritySignature = app::Signature;

/// Trait alias for signature types that can be used with GRANDPA.
/// This allows for custom signature schemes like Dilithium.
pub trait AuthoritySignatureBounds:
	Clone + Codec + core::fmt::Debug + PartialEq + Eq + Send + Sync + 'static + AsRef<[u8]>
{
}

/// Blanket implementation for all types that satisfy the bounds.
impl<T> AuthoritySignatureBounds for T where
	T: Clone + Codec + core::fmt::Debug + PartialEq + Eq + Send + Sync + 'static + AsRef<[u8]>
{
}

/// Generic signing function that works with any Pair type.
/// This allows for custom signature schemes like Dilithium.
#[cfg(feature = "std")]
pub fn sign_message_generic<P, H, N>(
	keystore: KeystorePtr,
	message: finality_grandpa::Message<H, N>,
	public: <P as sp_core::Pair>::Public,
	round: RoundNumber,
	set_id: SetId,
) -> Option<finality_grandpa::SignedMessage<H, N, <P as sp_core::Pair>::Signature, <P as sp_core::Pair>::Public>>
where
	P: sp_core::Pair + sp_application_crypto::AppCrypto<
		Public = <P as sp_core::Pair>::Public,
		Signature = <P as sp_core::Pair>::Signature,
	>,
	<P as sp_core::Pair>::Public: codec::Codec + Clone + AsRef<[u8]>,
	<P as sp_core::Pair>::Signature: codec::Codec + Clone + TryFrom<Vec<u8>>,
	H: Encode,
	N: Encode,
{
	let encoded = localized_payload(round, set_id, &message);
	
	// Use sign_with for generic signing (supports Ed25519, Dilithium, etc.)
	let signature_bytes = keystore
		.sign_with(
			<P as sp_application_crypto::AppCrypto>::ID,
			<P as sp_application_crypto::AppCrypto>::CRYPTO_ID,
			public.as_ref(),
			&encoded[..],
		)
		.ok()
		.flatten()?;
	
	let signature = signature_bytes.try_into().ok()?;

	Some(finality_grandpa::SignedMessage { message, signature, id: public })
}

/// The `ConsensusEngineId` of GRANDPA.
pub const GRANDPA_ENGINE_ID: ConsensusEngineId = *b"FRNK";

/// The weight of an authority.
pub type AuthorityWeight = u64;

/// The index of an authority.
pub type AuthorityIndex = u64;

/// The monotonic identifier of a GRANDPA set of authorities.
pub type SetId = u64;

/// The round indicator.
pub type RoundNumber = u64;

/// A list of Grandpa authorities with associated weights.
pub type AuthorityList = Vec<(AuthorityId, AuthorityWeight)>;

/// A generic list of Grandpa authorities with associated weights.
/// Use this when you need custom authority types (e.g., Dilithium for quantum resistance).
pub type AuthorityListOf<Id> = Vec<(Id, AuthorityWeight)>;

/// A GRANDPA message for a substrate chain.
pub type Message<Header> =
	finality_grandpa::Message<<Header as HeaderT>::Hash, <Header as HeaderT>::Number>;

/// A signed message.
pub type SignedMessage<Header> = finality_grandpa::SignedMessage<
	<Header as HeaderT>::Hash,
	<Header as HeaderT>::Number,
	AuthoritySignature,
	AuthorityId,
>;

/// A generic signed message with custom signature and authority types.
pub type SignedMessageOf<Header, Sig, Id> = finality_grandpa::SignedMessage<
	<Header as HeaderT>::Hash,
	<Header as HeaderT>::Number,
	Sig,
	Id,
>;

/// A primary propose message for this chain's block type.
pub type PrimaryPropose<Header> =
	finality_grandpa::PrimaryPropose<<Header as HeaderT>::Hash, <Header as HeaderT>::Number>;
/// A prevote message for this chain's block type.
pub type Prevote<Header> =
	finality_grandpa::Prevote<<Header as HeaderT>::Hash, <Header as HeaderT>::Number>;
/// A precommit message for this chain's block type.
pub type Precommit<Header> =
	finality_grandpa::Precommit<<Header as HeaderT>::Hash, <Header as HeaderT>::Number>;
/// A catch up message for this chain's block type.
pub type CatchUp<Header> = finality_grandpa::CatchUp<
	<Header as HeaderT>::Hash,
	<Header as HeaderT>::Number,
	AuthoritySignature,
	AuthorityId,
>;

/// A generic catch up message with custom signature and authority types.
pub type CatchUpOf<Header, Sig, Id> = finality_grandpa::CatchUp<
	<Header as HeaderT>::Hash,
	<Header as HeaderT>::Number,
	Sig,
	Id,
>;

/// A commit message for this chain's block type.
pub type Commit<Header> = finality_grandpa::Commit<
	<Header as HeaderT>::Hash,
	<Header as HeaderT>::Number,
	AuthoritySignature,
	AuthorityId,
>;

/// A generic commit message with custom signature and authority types.
pub type CommitOf<Header, Sig, Id> = finality_grandpa::Commit<
	<Header as HeaderT>::Hash,
	<Header as HeaderT>::Number,
	Sig,
	Id,
>;

/// A compact commit message for this chain's block type.
pub type CompactCommit<Header> = finality_grandpa::CompactCommit<
	<Header as HeaderT>::Hash,
	<Header as HeaderT>::Number,
	AuthoritySignature,
	AuthorityId,
>;

/// A generic compact commit message with custom signature and authority types.
pub type CompactCommitOf<Header, Sig, Id> = finality_grandpa::CompactCommit<
	<Header as HeaderT>::Hash,
	<Header as HeaderT>::Number,
	Sig,
	Id,
>;

/// A GRANDPA justification for block finality, it includes a commit message and
/// an ancestry proof including all headers routing all precommit target blocks
/// to the commit target block. Due to the current voting strategy the precommit
/// targets should be the same as the commit target, since honest voters don't
/// vote past authority set change blocks.
///
/// This is meant to be stored in the db and passed around the network to other
/// nodes, and are used by syncing nodes to prove authority set handoffs.
#[derive(Clone, Encode, Decode, PartialEq, Eq, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct GrandpaJustification<Header: HeaderT> {
	pub round: u64,
	pub commit: Commit<Header>,
	pub votes_ancestries: Vec<Header>,
}

/// A generic GRANDPA justification with custom signature and authority types.
/// Use this for quantum-resistant signature schemes like Dilithium.
#[derive(Clone, Encode, Decode, PartialEq, Eq, TypeInfo)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct GrandpaJustificationOf<Header: HeaderT, Sig, Id> {
	/// The round number.
	pub round: u64,
	/// The commit message.
	pub commit: CommitOf<Header, Sig, Id>,
	/// The ancestry of votes.
	pub votes_ancestries: Vec<Header>,
}

/// A scheduled change of authority set.
#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ScheduledChange<N> {
	/// The new authorities after the change, along with their respective weights.
	pub next_authorities: AuthorityList,
	/// The number of blocks to delay.
	pub delay: N,
}

/// A generic scheduled change with custom authority type.
#[derive(Clone, Eq, PartialEq, Encode, Decode, RuntimeDebug, TypeInfo)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub struct ScheduledChangeOf<N, Id> {
	/// The new authorities after the change, along with their respective weights.
	pub next_authorities: AuthorityListOf<Id>,
	/// The number of blocks to delay.
	pub delay: N,
}

/// An consensus log item for GRANDPA.
#[derive(Decode, Encode, PartialEq, Eq, Clone, RuntimeDebug)]
#[cfg_attr(feature = "serde", derive(Serialize))]
pub enum ConsensusLog<N: Codec> {
	/// Schedule an authority set change.
	///
	/// The earliest digest of this type in a single block will be respected,
	/// provided that there is no `ForcedChange` digest. If there is, then the
	/// `ForcedChange` will take precedence.
	///
	/// No change should be scheduled if one is already and the delay has not
	/// passed completely.
	///
	/// This should be a pure function: i.e. as long as the runtime can interpret
	/// the digest type it should return the same result regardless of the current
	/// state.
	#[codec(index = 1)]
	ScheduledChange(ScheduledChange<N>),
	/// Force an authority set change.
	///
	/// Forced changes are applied after a delay of _imported_ blocks,
	/// while pending changes are applied after a delay of _finalized_ blocks.
	///
	/// The earliest digest of this type in a single block will be respected,
	/// with others ignored.
	///
	/// No change should be scheduled if one is already and the delay has not
	/// passed completely.
	///
	/// This should be a pure function: i.e. as long as the runtime can interpret
	/// the digest type it should return the same result regardless of the current
	/// state.
	#[codec(index = 2)]
	ForcedChange(N, ScheduledChange<N>),
	/// Note that the authority with given index is disabled until the next change.
	#[codec(index = 3)]
	OnDisabled(AuthorityIndex),
	/// A signal to pause the current authority set after the given delay.
	/// After finalizing the block at _delay_ the authorities should stop voting.
	#[codec(index = 4)]
	Pause(N),
	/// A signal to resume the current authority set after the given delay.
	/// After authoring the block at _delay_ the authorities should resume voting.
	#[codec(index = 5)]
	Resume(N),
}

impl<N: Codec> ConsensusLog<N> {
	/// Try to cast the log entry as a contained signal.
	pub fn try_into_change(self) -> Option<ScheduledChange<N>> {
		match self {
			ConsensusLog::ScheduledChange(change) => Some(change),
			_ => None,
		}
	}

	/// Try to cast the log entry as a contained forced signal.
	pub fn try_into_forced_change(self) -> Option<(N, ScheduledChange<N>)> {
		match self {
			ConsensusLog::ForcedChange(median, change) => Some((median, change)),
			_ => None,
		}
	}

	/// Try to cast the log entry as a contained pause signal.
	pub fn try_into_pause(self) -> Option<N> {
		match self {
			ConsensusLog::Pause(delay) => Some(delay),
			_ => None,
		}
	}

	/// Try to cast the log entry as a contained resume signal.
	pub fn try_into_resume(self) -> Option<N> {
		match self {
			ConsensusLog::Resume(delay) => Some(delay),
			_ => None,
		}
	}
}

/// Generic consensus log item for GRANDPA with configurable authority ID.
#[derive(Decode, Encode, PartialEq, Eq, Clone, RuntimeDebug)]
pub enum ConsensusLogOf<N: Codec, Id: Codec> {
	/// Schedule an authority set change.
	#[codec(index = 1)]
	ScheduledChange(ScheduledChangeOf<N, Id>),
	/// Force an authority set change.
	#[codec(index = 2)]
	ForcedChange(N, ScheduledChangeOf<N, Id>),
	/// Note that the authority with given index is disabled until the next change.
	#[codec(index = 3)]
	OnDisabled(AuthorityIndex),
	/// A signal to pause the current authority set after the given delay.
	#[codec(index = 4)]
	Pause(N),
	/// A signal to resume the current authority set after the given delay.
	#[codec(index = 5)]
	Resume(N),
}

impl<N: Codec, Id: Codec> ConsensusLogOf<N, Id> {
	/// Try to cast the log entry as a contained signal.
	pub fn try_into_change(self) -> Option<ScheduledChangeOf<N, Id>> {
		match self {
			ConsensusLogOf::ScheduledChange(change) => Some(change),
			_ => None,
		}
	}

	/// Try to cast the log entry as a contained forced signal.
	pub fn try_into_forced_change(self) -> Option<(N, ScheduledChangeOf<N, Id>)> {
		match self {
			ConsensusLogOf::ForcedChange(median, change) => Some((median, change)),
			_ => None,
		}
	}

	/// Try to cast the log entry as a contained pause signal.
	pub fn try_into_pause(self) -> Option<N> {
		match self {
			ConsensusLogOf::Pause(delay) => Some(delay),
			_ => None,
		}
	}

	/// Try to cast the log entry as a contained resume signal.
	pub fn try_into_resume(self) -> Option<N> {
		match self {
			ConsensusLogOf::Resume(delay) => Some(delay),
			_ => None,
		}
	}
}

/// Proof of voter misbehavior on a given set id. Misbehavior/equivocation in
/// GRANDPA happens when a voter votes on the same round (either at prevote or
/// precommit stage) for different blocks. Proving is achieved by collecting the
/// signed messages of conflicting votes.
#[derive(Clone, Debug, Decode, Encode, PartialEq, Eq, TypeInfo)]
pub struct EquivocationProof<H, N> {
	set_id: SetId,
	equivocation: Equivocation<H, N>,
}

impl<H, N> EquivocationProof<H, N> {
	/// Create a new `EquivocationProof` for the given set id and using the
	/// given equivocation as proof.
	pub fn new(set_id: SetId, equivocation: Equivocation<H, N>) -> Self {
		EquivocationProof { set_id, equivocation }
	}

	/// Returns the set id at which the equivocation occurred.
	pub fn set_id(&self) -> SetId {
		self.set_id
	}

	/// Returns the round number at which the equivocation occurred.
	pub fn round(&self) -> RoundNumber {
		match self.equivocation {
			Equivocation::Prevote(ref equivocation) => equivocation.round_number,
			Equivocation::Precommit(ref equivocation) => equivocation.round_number,
		}
	}

	/// Returns the authority id of the equivocator.
	pub fn offender(&self) -> &AuthorityId {
		self.equivocation.offender()
	}
}

/// Wrapper object for GRANDPA equivocation proofs, useful for unifying prevote
/// and precommit equivocations under a common type.
#[derive(Clone, Debug, Decode, Encode, PartialEq, Eq, TypeInfo)]
pub enum Equivocation<H, N> {
	/// Proof of equivocation at prevote stage.
	Prevote(
		finality_grandpa::Equivocation<
			AuthorityId,
			finality_grandpa::Prevote<H, N>,
			AuthoritySignature,
		>,
	),
	/// Proof of equivocation at precommit stage.
	Precommit(
		finality_grandpa::Equivocation<
			AuthorityId,
			finality_grandpa::Precommit<H, N>,
			AuthoritySignature,
		>,
	),
}

impl<H, N>
	From<
		finality_grandpa::Equivocation<
			AuthorityId,
			finality_grandpa::Prevote<H, N>,
			AuthoritySignature,
		>,
	> for Equivocation<H, N>
{
	fn from(
		equivocation: finality_grandpa::Equivocation<
			AuthorityId,
			finality_grandpa::Prevote<H, N>,
			AuthoritySignature,
		>,
	) -> Self {
		Equivocation::Prevote(equivocation)
	}
}

impl<H, N>
	From<
		finality_grandpa::Equivocation<
			AuthorityId,
			finality_grandpa::Precommit<H, N>,
			AuthoritySignature,
		>,
	> for Equivocation<H, N>
{
	fn from(
		equivocation: finality_grandpa::Equivocation<
			AuthorityId,
			finality_grandpa::Precommit<H, N>,
			AuthoritySignature,
		>,
	) -> Self {
		Equivocation::Precommit(equivocation)
	}
}

impl<H, N> Equivocation<H, N> {
	/// Returns the authority id of the equivocator.
	pub fn offender(&self) -> &AuthorityId {
		match self {
			Equivocation::Prevote(ref equivocation) => &equivocation.identity,
			Equivocation::Precommit(ref equivocation) => &equivocation.identity,
		}
	}

	/// Returns the round number when the equivocation happened.
	pub fn round_number(&self) -> RoundNumber {
		match self {
			Equivocation::Prevote(ref equivocation) => equivocation.round_number,
			Equivocation::Precommit(ref equivocation) => equivocation.round_number,
		}
	}
}

/// Generic equivocation proof with custom authority and signature types.
/// Use this for quantum-resistant GRANDPA implementations.
#[derive(Clone, Debug, Decode, Encode, PartialEq, Eq, TypeInfo)]
pub struct EquivocationProofOf<H, N, Id, Sig> {
	set_id: SetId,
	equivocation: EquivocationOf<H, N, Id, Sig>,
}

impl<H, N, Id: Clone, Sig> EquivocationProofOf<H, N, Id, Sig> {
	/// Create a new generic EquivocationProof.
	pub fn new(set_id: SetId, equivocation: EquivocationOf<H, N, Id, Sig>) -> Self {
		EquivocationProofOf { set_id, equivocation }
	}

	/// Returns the set id at which the equivocation occurred.
	pub fn set_id(&self) -> SetId {
		self.set_id
	}

	/// Returns the authority id of the equivocator.
	pub fn offender(&self) -> &Id {
		self.equivocation.offender()
	}

	/// Returns a reference to the equivocation.
	pub fn equivocation(&self) -> &EquivocationOf<H, N, Id, Sig> {
		&self.equivocation
	}

	/// Returns the round number at which the equivocation occurred.
	pub fn round(&self) -> RoundNumber {
		self.equivocation.round_number()
	}
}

/// Generic equivocation wrapper with custom authority and signature types.
#[derive(Clone, Debug, Decode, Encode, PartialEq, Eq, TypeInfo)]
pub enum EquivocationOf<H, N, Id, Sig> {
	/// Proof of equivocation at prevote stage.
	Prevote(
		finality_grandpa::Equivocation<
			Id,
			finality_grandpa::Prevote<H, N>,
			Sig,
		>,
	),
	/// Proof of equivocation at precommit stage.
	Precommit(
		finality_grandpa::Equivocation<
			Id,
			finality_grandpa::Precommit<H, N>,
			Sig,
		>,
	),
}

impl<H, N, Id: Clone, Sig> EquivocationOf<H, N, Id, Sig> {
	/// Returns the authority id of the equivocator.
	pub fn offender(&self) -> &Id {
		match self {
			EquivocationOf::Prevote(ref equivocation) => &equivocation.identity,
			EquivocationOf::Precommit(ref equivocation) => &equivocation.identity,
		}
	}

	/// Returns the round number when the equivocation happened.
	pub fn round_number(&self) -> RoundNumber {
		match self {
			EquivocationOf::Prevote(ref equivocation) => equivocation.round_number,
			EquivocationOf::Precommit(ref equivocation) => equivocation.round_number,
		}
	}
}

/// Verifies the equivocation proof by making sure that both votes target
/// different blocks and that its signatures are valid.
pub fn check_equivocation_proof<H, N>(report: EquivocationProof<H, N>) -> bool
where
	H: Clone + Encode + PartialEq,
	N: Clone + Encode + PartialEq,
{
	// NOTE: the bare `Prevote` and `Precommit` types don't share any trait,
	// this is implemented as a macro to avoid duplication.
	macro_rules! check {
		( $equivocation:expr, $message:expr ) => {
			// if both votes have the same target the equivocation is invalid.
			if $equivocation.first.0.target_hash == $equivocation.second.0.target_hash &&
				$equivocation.first.0.target_number == $equivocation.second.0.target_number
			{
				return false
			}

			// check signatures on both votes are valid
			let valid_first = check_message_signature(
				&$message($equivocation.first.0),
				&$equivocation.identity,
				&$equivocation.first.1,
				$equivocation.round_number,
				report.set_id,
			);

			let valid_second = check_message_signature(
				&$message($equivocation.second.0),
				&$equivocation.identity,
				&$equivocation.second.1,
				$equivocation.round_number,
				report.set_id,
			);

			return valid_first && valid_second
		};
	}

	match report.equivocation {
		Equivocation::Prevote(equivocation) => {
			check!(equivocation, finality_grandpa::Message::Prevote);
		},
		Equivocation::Precommit(equivocation) => {
			check!(equivocation, finality_grandpa::Message::Precommit);
		},
	}
}

/// Verifies the equivocation proof by making sure that both votes target
/// different blocks and that its signatures are valid.
/// Generic version that works with configurable authority ID and signature types.
pub fn check_equivocation_proof_generic<H, N, Id, Sig>(
	report: &EquivocationProofOf<H, N, Id, Sig>,
) -> bool
where
	H: Clone + Encode + PartialEq,
	N: Clone + Encode + PartialEq,
	Id: Clone + Encode + PartialEq + sp_core::crypto::ByteArray
		+ sp_application_crypto::RuntimeAppPublic<Signature = Sig>
		+ core::fmt::Debug,
	Sig: Clone + Encode + sp_core::crypto::ByteArray + codec::Decode,
{
	let set_id = report.set_id();

	// NOTE: the bare `Prevote` and `Precommit` types don't share any trait,
	// this is implemented as a macro to avoid duplication.
	macro_rules! check {
		( $equivocation:expr, $message:expr ) => {
			// if both votes have the same target the equivocation is invalid.
			if $equivocation.first.0.target_hash == $equivocation.second.0.target_hash &&
				$equivocation.first.0.target_number == $equivocation.second.0.target_number
			{
				return false
			}

			// check signatures on both votes are valid
			let valid_first = check_message_signature_generic::<H, N, Id, Sig>(
				&$message($equivocation.first.0.clone()),
				&$equivocation.identity,
				&$equivocation.first.1,
				$equivocation.round_number,
				set_id,
			);

			let valid_second = check_message_signature_generic::<H, N, Id, Sig>(
				&$message($equivocation.second.0.clone()),
				&$equivocation.identity,
				&$equivocation.second.1,
				$equivocation.round_number,
				set_id,
			);

			return valid_first && valid_second
		};
	}

	match report.equivocation() {
		EquivocationOf::Prevote(ref equivocation) => {
			check!(equivocation, finality_grandpa::Message::Prevote);
		},
		EquivocationOf::Precommit(ref equivocation) => {
			check!(equivocation, finality_grandpa::Message::Precommit);
		},
	}
}

/// Encode round message localized to a given round and set id.
pub fn localized_payload<E: Encode>(round: RoundNumber, set_id: SetId, message: &E) -> Vec<u8> {
	let mut buf = Vec::new();
	localized_payload_with_buffer(round, set_id, message, &mut buf);
	buf
}

/// Encode round message localized to a given round and set id using the given
/// buffer. The given buffer will be cleared and the resulting encoded payload
/// will always be written to the start of the buffer.
pub fn localized_payload_with_buffer<E: Encode>(
	round: RoundNumber,
	set_id: SetId,
	message: &E,
	buf: &mut Vec<u8>,
) {
	buf.clear();
	(message, round, set_id).encode_to(buf)
}

/// Check a message signature by encoding the message as a localized payload and
/// verifying the provided signature using the expected authority id.
pub fn check_message_signature<H, N>(
	message: &finality_grandpa::Message<H, N>,
	id: &AuthorityId,
	signature: &AuthoritySignature,
	round: RoundNumber,
	set_id: SetId,
) -> bool
where
	H: Encode,
	N: Encode,
{
	check_message_signature_with_buffer(message, id, signature, round, set_id, &mut Vec::new())
}

/// Check a message signature by encoding the message as a localized payload and
/// verifying the provided signature using the expected authority id.
/// The encoding necessary to verify the signature will be done using the given
/// buffer, the original content of the buffer will be cleared.
///
/// This function supports both Ed25519 (64 bytes) and Dilithium3 (3309 bytes) signatures
/// by checking the signature length.
pub fn check_message_signature_with_buffer<H, N>(
	message: &finality_grandpa::Message<H, N>,
	id: &AuthorityId,
	signature: &AuthoritySignature,
	round: RoundNumber,
	set_id: SetId,
	buf: &mut Vec<u8>,
) -> bool
where
	H: Encode,
	N: Encode,
{
	use sp_application_crypto::RuntimeAppPublic;

	localized_payload_with_buffer(round, set_id, message, buf);

	let valid = id.verify(&buf, signature);

	if !valid {
		let log_target = if cfg!(feature = "std") { CLIENT_LOG_TARGET } else { RUNTIME_LOG_TARGET };

		log::debug!(target: log_target, "Bad signature on message from {:?}", id);
	}

	valid
}

/// Dilithium3 signature size constant for hybrid verification
pub const DILITHIUM3_SIGNATURE_SIZE: usize = 3309;

/// Dilithium3 public key size constant
pub const DILITHIUM3_PUBLIC_KEY_SIZE: usize = 1952;

/// Check a message signature supporting both Ed25519 and Dilithium3.
/// 
/// This function detects the signature type based on size and verifies accordingly.
/// Used by chains that support quantum-resistant GRANDPA.
#[cfg(feature = "std")]
pub fn check_message_signature_hybrid<H, N>(
	message: &finality_grandpa::Message<H, N>,
	id_bytes: &[u8],
	signature_bytes: &[u8],
	round: RoundNumber,
	set_id: SetId,
) -> bool
where
	H: Encode,
	N: Encode,
{
	let mut buf = Vec::new();
	localized_payload_with_buffer(round, set_id, message, &mut buf);

	// Check signature size to determine algorithm
	if signature_bytes.len() == DILITHIUM3_SIGNATURE_SIZE && id_bytes.len() == DILITHIUM3_PUBLIC_KEY_SIZE {
		// ML-DSA-65 (Dilithium3) verification using pqcrypto-mldsa
		use pqcrypto_mldsa::mldsa65;
		use pqcrypto_traits::sign::PublicKey as PqPublicKey;
		use pqcrypto_traits::sign::DetachedSignature;
		
		if let Ok(pk) = mldsa65::PublicKey::from_bytes(id_bytes) {
			if let Ok(sig) = mldsa65::DetachedSignature::from_bytes(signature_bytes) {
				return pqcrypto_mldsa::mldsa65::verify_detached_signature(&sig, &buf, &pk).is_ok();
			}
		}
		false
	} else if signature_bytes.len() == 64 && id_bytes.len() == 32 {
		// Ed25519 verification - use the standard path
		if let Ok(id) = AuthorityId::try_from(id_bytes) {
			if let Ok(signature) = AuthoritySignature::try_from(signature_bytes) {
				use sp_application_crypto::RuntimeAppPublic;
				return id.verify(&buf, &signature);
			}
		}
		false
	} else {
		log::debug!(target: CLIENT_LOG_TARGET, 
			"Unknown signature format: sig_len={}, id_len={}", 
			signature_bytes.len(), id_bytes.len());
		false
	}
}

/// Check a message signature supporting both Ed25519 and Dilithium3, with buffer reuse.
/// 
/// This is the buffered version of `check_message_signature_hybrid` for better performance
/// when verifying multiple signatures.
#[cfg(feature = "std")]
pub fn check_message_signature_hybrid_with_buffer<H, N>(
	message: &finality_grandpa::Message<H, N>,
	id_bytes: &[u8],
	signature_bytes: &[u8],
	round: RoundNumber,
	set_id: SetId,
	buf: &mut Vec<u8>,
) -> bool
where
	H: Encode,
	N: Encode,
{
	localized_payload_with_buffer(round, set_id, message, buf);

	// Check signature size to determine algorithm
	if signature_bytes.len() == DILITHIUM3_SIGNATURE_SIZE && id_bytes.len() == DILITHIUM3_PUBLIC_KEY_SIZE {
		// ML-DSA-65 (Dilithium3) verification using pqcrypto-mldsa
		use pqcrypto_mldsa::mldsa65;
		use pqcrypto_traits::sign::PublicKey as PqPublicKey;
		use pqcrypto_traits::sign::DetachedSignature;
		
		if let Ok(pk) = mldsa65::PublicKey::from_bytes(id_bytes) {
			if let Ok(sig) = mldsa65::DetachedSignature::from_bytes(signature_bytes) {
				return pqcrypto_mldsa::mldsa65::verify_detached_signature(&sig, buf, &pk).is_ok();
			}
		}
		false
	} else if signature_bytes.len() == 64 && id_bytes.len() == 32 {
		// Ed25519 verification
		if let Ok(id) = AuthorityId::try_from(id_bytes) {
			if let Ok(signature) = AuthoritySignature::try_from(signature_bytes) {
				use sp_application_crypto::RuntimeAppPublic;
				return id.verify(buf, &signature);
			}
		}
		false
	} else {
		log::debug!(target: CLIENT_LOG_TARGET, 
			"Unknown signature format: sig_len={}, id_len={}", 
			signature_bytes.len(), id_bytes.len());
		false
	}
}

/// Generic signature verification for custom authority types (e.g., Dilithium).
/// 
/// This allows verifying GRANDPA messages signed with quantum-resistant algorithms.
pub fn check_message_signature_generic<H, N, Id, Sig>(
	message: &finality_grandpa::Message<H, N>,
	id: &Id,
	signature: &Sig,
	round: RoundNumber,
	set_id: SetId,
) -> bool
where
	H: Encode,
	N: Encode,
	Id: sp_application_crypto::RuntimeAppPublic<Signature = Sig> + core::fmt::Debug,
	Sig: Clone,
{
	check_message_signature_generic_with_buffer(message, id, signature, round, set_id, &mut Vec::new())
}

/// Generic signature verification with buffer for custom authority types.
pub fn check_message_signature_generic_with_buffer<H, N, Id, Sig>(
	message: &finality_grandpa::Message<H, N>,
	id: &Id,
	signature: &Sig,
	round: RoundNumber,
	set_id: SetId,
	buf: &mut Vec<u8>,
) -> bool
where
	H: Encode,
	N: Encode,
	Id: sp_application_crypto::RuntimeAppPublic<Signature = Sig> + core::fmt::Debug,
	Sig: Clone,
{
	localized_payload_with_buffer(round, set_id, message, buf);

	let valid = id.verify(&buf, signature);

	if !valid {
		let log_target = if cfg!(feature = "std") { CLIENT_LOG_TARGET } else { RUNTIME_LOG_TARGET };

		log::debug!(target: log_target, "Bad signature on message from {:?}", id);
	}

	valid
}

/// Localizes the message to the given set and round and signs the payload.
/// 
/// This function uses the generic `sign_with` keystore method, which allows
/// custom signature schemes (like Dilithium for quantum resistance) to be used.
#[cfg(feature = "std")]
pub fn sign_message<H, N>(
	keystore: KeystorePtr,
	message: finality_grandpa::Message<H, N>,
	public: AuthorityId,
	round: RoundNumber,
	set_id: SetId,
) -> Option<finality_grandpa::SignedMessage<H, N, AuthoritySignature, AuthorityId>>
where
	H: Encode,
	N: Encode,
{
	use sp_application_crypto::AppCrypto;

	let encoded = localized_payload(round, set_id, &message);
	
	// Use sign_with for generic signing - this allows custom keystores
	// (like DilithiumKeystore) to intercept and use their own signing logic
	let signature = keystore
		.sign_with(AuthorityId::ID, AuthorityId::CRYPTO_ID, public.as_ref(), &encoded[..])
		.ok()
		.flatten()
		.and_then(|sig_bytes| sig_bytes.try_into().ok())
		// Fallback to ed25519_sign for compatibility with standard keystores
		.or_else(|| {
			keystore
				.ed25519_sign(AuthorityId::ID, public.as_ref(), &encoded[..])
				.ok()
				.flatten()
				.and_then(|sig| sig.try_into().ok())
		})?;

	Some(finality_grandpa::SignedMessage { message, signature, id: public })
}

/// An opaque type used to represent the key ownership proof at the runtime API
/// boundary. The inner value is an encoded representation of the actual key
/// ownership proof which will be parameterized when defining the runtime. At
/// the runtime API boundary this type is unknown and as such we keep this
/// opaque representation, implementors of the runtime API will have to make
/// sure that all usages of `OpaqueKeyOwnershipProof` refer to the same type.
pub type OpaqueKeyOwnershipProof = OpaqueValue;

sp_api::decl_runtime_apis! {
	/// APIs for integrating the GRANDPA finality gadget into runtimes.
	/// This should be implemented on the runtime side.
	///
	/// This is primarily used for negotiating authority-set changes for the
	/// gadget. GRANDPA uses a signaling model of changing authority sets:
	/// changes should be signaled with a delay of N blocks, and then automatically
	/// applied in the runtime after those N blocks have passed.
	///
	/// The consensus protocol will coordinate the handoff externally.
	///
	/// # Version history
	/// - **v3**: added [`Self::grandpa_authorities_raw`] for non-ed25519 authority lists.
	/// - **v4**: added [`Self::submit_report_equivocation_unsigned_extrinsic_raw`] and
	///   [`Self::generate_key_ownership_proof_raw`] so Dilithium (and other non-32-byte)
	///   authority identities can be reported without forcing `AuthorityId`/`AuthoritySignature`
	///   (ed25519) at the runtime-API boundary.
	#[api_version(4)]
	pub trait GrandpaApi {
		/// Get the current GRANDPA authorities and weights. This should not change except
		/// for when changes are scheduled and the corresponding delay has passed.
		///
		/// When called at block B, it will return the set of authorities that should be
		/// used to finalize descendants of this block (B+1, B+2, ...). The block B itself
		/// is finalized by the authorities from block B-1.
		fn grandpa_authorities() -> AuthorityList;

		/// Get the current GRANDPA authorities as opaque bytes.
		/// This is used for chains with custom authority types (e.g., Dilithium for quantum resistance).
		/// Returns a SCALE-encoded list of (authority_bytes, weight) tuples.
		fn grandpa_authorities_raw() -> alloc::vec::Vec<(alloc::vec::Vec<u8>, AuthorityWeight)>;

		/// Submits an unsigned extrinsic to report an equivocation. The caller
		/// must provide the equivocation proof and a key ownership proof
		/// (should be obtained using `generate_key_ownership_proof`). The
		/// extrinsic will be unsigned and should only be accepted for local
		/// authorship (not to be broadcast to the network). This method returns
		/// `None` when creation of the extrinsic fails, e.g. if equivocation
		/// reporting is disabled for the given runtime (i.e. this method is
		/// hardcoded to return `None`). Only useful in an offchain context.
		///
		/// Prefer [`Self::submit_report_equivocation_unsigned_extrinsic_raw`] when the
		/// chain's GRANDPA authorities are not ed25519-shaped.
		fn submit_report_equivocation_unsigned_extrinsic(
			equivocation_proof: EquivocationProof<Block::Hash, NumberFor<Block>>,
			key_owner_proof: OpaqueKeyOwnershipProof,
		) -> Option<()>;

		/// Submits an unsigned extrinsic to report an equivocation using a SCALE-encoded
		/// [`EquivocationProofOf`] whose `Id`/`Sig` match the chain's configured GRANDPA
		/// authority types (e.g. Dilithium / ML-DSA-65).
		///
		/// The proof bytes are opaque at this boundary so the runtime API does not hardcode
		/// ed25519 `AuthorityId`/`AuthoritySignature`. Returns `None` when reporting is
		/// disabled or the extrinsic cannot be created.
		fn submit_report_equivocation_unsigned_extrinsic_raw(
			equivocation_proof: alloc::vec::Vec<u8>,
			key_owner_proof: OpaqueKeyOwnershipProof,
		) -> Option<()>;

		/// Generates a proof of key ownership for the given authority in the
		/// given set. An example usage of this module is coupled with the
		/// session historical module to prove that a given authority key is
		/// tied to a given staking identity during a specific session. Proofs
		/// of key ownership are necessary for submitting equivocation reports.
		/// NOTE: even though the API takes a `set_id` as parameter the current
		/// implementations ignore this parameter and instead rely on this
		/// method being called at the correct block height, i.e. any point at
		/// which the given set id is live on-chain. Future implementations will
		/// instead use indexed data through an offchain worker, not requiring
		/// older states to be available.
		///
		/// Prefer [`Self::generate_key_ownership_proof_raw`] when the chain's GRANDPA
		/// authorities are not ed25519-shaped.
		fn generate_key_ownership_proof(
			set_id: SetId,
			authority_id: AuthorityId,
		) -> Option<OpaqueKeyOwnershipProof>;

		/// Generates a key-ownership proof for an authority identified by raw public-key
		/// bytes (any length; Dilithium ML-DSA-65 keys are 1952 bytes).
		///
		/// Same semantics as [`Self::generate_key_ownership_proof`], but without forcing
		/// the ed25519 `AuthorityId` type at the runtime-API boundary.
		fn generate_key_ownership_proof_raw(
			set_id: SetId,
			authority_id: alloc::vec::Vec<u8>,
		) -> Option<OpaqueKeyOwnershipProof>;

		/// Get current GRANDPA authority set id.
		fn current_set_id() -> SetId;
	}
}
