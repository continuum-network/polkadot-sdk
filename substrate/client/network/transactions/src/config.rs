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

//! Configuration of the transaction protocol

use futures::prelude::*;
use sc_network::MAX_RESPONSE_SIZE;
use sc_network_common::ExHashT;
use sp_runtime::traits::Block as BlockT;
use std::{collections::HashMap, future::Future, pin::Pin, sync::Arc, time};

/// Interval at which we propagate transactions; see [`PER_PEER_ROUND_BUDGET`].
pub(crate) const PROPAGATE_TIMEOUT: time::Duration = time::Duration::from_millis(1000);

/// Maximum number of known transaction hashes to keep for a peer.
///
/// This should be approx. 2 blocks full of transactions for the network to function properly.
pub(crate) const MAX_KNOWN_TRANSACTIONS: usize = 10240; // ~300kb per peer + overhead.

/// Size of a connection's sync notification buffer in `sc-network`
/// (`SYNC_NOTIFICATIONS_BUFFER_SIZE`); overflowing it closes the connection
/// (`SyncNotificationsClogged`). Each transaction is its own notification (RFC 56).
const SYNC_NOTIFICATIONS_BUFFER: usize = 2048;

/// Most transaction notifications we let pile up for one peer: ~73% of the buffer, leaving room
/// for other sync notifications.
pub(crate) const MAX_QUEUED_PER_PEER: usize = 1500;
const _: () = assert!(MAX_QUEUED_PER_PEER < SYNC_NOTIFICATIONS_BUFFER);

/// Transactions sent to one peer per [`PROPAGATE_TIMEOUT`] round, immediate and periodic together.
///
/// A peer that reads nothing for a whole round holds at most two rounds, i.e.
/// [`MAX_QUEUED_PER_PEER`]. A peer that keeps reading holds at most one: on loopback a peer read
/// 1024 ML-DSA-signed (~5 KB) transactions in 32-173 ms, so a round drains well within 1 s.
/// 750 per 1 s is 750 tx/s per peer, ~0.85x a full block per second (~890 EIP-1559 txs), a middle
/// ground between CPU cost (500 ms rounds raised node CPU ~40%) and block fill. The previous 2.9 s
/// round with 1024 + 256 gave ~440 tx/s and left validators half empty.
const PER_PEER_ROUND_BUDGET: usize = MAX_QUEUED_PER_PEER / 2;

/// Maximum number of transactions sent to a peer by the immediate (per-import) propagation between
/// two periodic rounds: a fifth of the round budget. Over budget they are not marked known, so the
/// next (capped) periodic round sends them.
pub(crate) const MAX_IMMEDIATE_TRANSACTIONS_PER_PEER: usize = PER_PEER_ROUND_BUDGET / 5;

/// Maximum number of transactions sent to one peer per periodic propagation: the rest of the round
/// budget. The others are not marked known and go in later rounds.
pub(crate) const MAX_PROPAGATED_TRANSACTIONS_PER_PEER: usize =
	PER_PEER_ROUND_BUDGET - MAX_IMMEDIATE_TRANSACTIONS_PER_PEER;

/// Maximum allowed size for a transactions notification.
pub(crate) const MAX_TRANSACTIONS_SIZE: u64 = MAX_RESPONSE_SIZE;

/// Maximum number of transaction validation request we keep at any moment.
pub(crate) const MAX_PENDING_TRANSACTIONS: usize = 8192;

/// Result of the transaction import.
#[derive(Clone, Copy, Debug)]
pub enum TransactionImport {
	/// Transaction is good but already known by the transaction pool.
	KnownGood,
	/// Transaction is good and not yet known.
	NewGood,
	/// Transaction is invalid.
	Bad,
	/// Transaction is outdated (stale nonce) or of unknown validity; likely a gossip race.
	Outdated,
	/// Transaction import was not performed.
	None,
}

/// Future resolving to transaction import result.
pub type TransactionImportFuture = Pin<Box<dyn Future<Output = TransactionImport> + Send>>;

/// Transaction pool interface
pub trait TransactionPool<H: ExHashT, B: BlockT>: Send + Sync {
	/// Get transactions from the pool that are ready to be propagated.
	fn transactions(&self) -> Vec<(H, Arc<B::Extrinsic>)>;
	/// Get hash of transaction.
	fn hash_of(&self, transaction: &B::Extrinsic) -> H;
	/// Import a transaction into the pool.
	///
	/// This will return future.
	fn import(&self, transaction: B::Extrinsic) -> TransactionImportFuture;
	/// Notify the pool about transactions broadcast.
	fn on_broadcasted(&self, propagations: HashMap<H, Vec<String>>);
	/// Get transaction by hash.
	fn transaction(&self, hash: &H) -> Option<Arc<B::Extrinsic>>;
}

/// Dummy implementation of the [`TransactionPool`] trait for a transaction pool that is always
/// empty and discards all incoming transactions.
///
/// Requires the "hash" type to implement the `Default` trait.
///
/// Useful for testing purposes.
pub struct EmptyTransactionPool;

impl<H: ExHashT + Default, B: BlockT> TransactionPool<H, B> for EmptyTransactionPool {
	fn transactions(&self) -> Vec<(H, Arc<B::Extrinsic>)> {
		Vec::new()
	}

	fn hash_of(&self, _transaction: &B::Extrinsic) -> H {
		Default::default()
	}

	fn import(&self, _transaction: B::Extrinsic) -> TransactionImportFuture {
		Box::pin(future::ready(TransactionImport::KnownGood))
	}

	fn on_broadcasted(&self, _: HashMap<H, Vec<String>>) {}

	fn transaction(&self, _h: &H) -> Option<Arc<B::Extrinsic>> {
		None
	}
}
