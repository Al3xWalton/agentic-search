// Stract is an open source web search engine.
// Copyright (C) 2024 Stract ApS
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>

pub mod api;
pub mod raft;

use api::{
    AllTables, BatchGet, BatchSet, BatchUpsert, CloneTable, CreateTable, DropTable, Get, NumKeys,
    RangeGet, Set, Upsert,
};
use std::{collections::BTreeMap, net::SocketAddr, sync::Arc};

use openraft::{Raft, RaftNetworkFactory};

use self::raft::RemoteClient;
use crate::distributed::sonic::service::sonic_service;

use super::{store::StateMachineStore, BasicNode, NodeId, TypeConfig};

#[derive(Clone)]
pub struct Network;

impl RaftNetworkFactory<TypeConfig> for Network {
    type Network = RemoteClient;

    async fn new_client(&mut self, _: NodeId, node: &BasicNode) -> Self::Network {
        RemoteClient::new(node.addr.parse().unwrap()).await.unwrap()
    }
}

#[derive(bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct AppendEntries(#[bincode(with_serde)] openraft::raft::AppendEntriesRequest<TypeConfig>);
#[derive(bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize, Debug)]
pub struct AppendEntriesResponse(
    #[bincode(with_serde)] pub openraft::raft::AppendEntriesResponse<NodeId>,
);

#[derive(bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct InstallSnapshot(
    #[bincode(with_serde)] pub openraft::raft::InstallSnapshotRequest<TypeConfig>,
);
#[derive(bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize, Debug)]
pub struct InstallSnapshotResponse(
    #[bincode(with_serde)] pub openraft::raft::InstallSnapshotResponse<NodeId>,
);

#[derive(bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct Vote(#[bincode(with_serde)] pub openraft::raft::VoteRequest<NodeId>);
#[derive(bincode::Encode, bincode::Decode, serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct VoteResponse(#[bincode(with_serde)] pub openraft::raft::VoteResponse<NodeId>);

#[derive(serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
pub struct AddLearner {
    pub id: NodeId,
    pub addr: SocketAddr,
}

#[derive(serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
pub struct AddNodes {
    members: BTreeMap<NodeId, BasicNode>,
}

#[derive(serde::Serialize, serde::Deserialize, bincode::Encode, bincode::Decode, Debug, Clone)]
pub struct Metrics;

/// Encoded body-byte cap for DHT frames: 134,217,728 bytes (128 MiB), in both directions.
///
/// The sizing case is a synthetic batch-body projection of a configured-maximum raft append: one
/// measured 4096-pair `(u64, HyperLogLog<64>)` batch encodes to 278,029 bytes, and 300 entries of
/// it come to 83,408,700 bytes, above sonic's 64 MiB default. 128 MiB leaves about 1.6x headroom
/// over that projection. The decoder's separate 256 MiB claim budget does not bound this frame's
/// decoded size: raft payloads decode through serde and make no bincode claims.
pub const MAX_DHT_FRAME_BODY_BYTES: usize = 128 * 1024 * 1024;

sonic_service!(
    Server,
    [
        AppendEntries,
        InstallSnapshot,
        Vote,
        Metrics,
        AddLearner,
        AddNodes,
        Get,
        BatchGet,
        Set,
        BatchSet,
        NumKeys,
        Upsert,
        BatchUpsert,
        DropTable,
        CreateTable,
        AllTables,
        CloneTable,
        RangeGet,
    ],
    max_frame_body_bytes = crate::ampc::dht::network::MAX_DHT_FRAME_BODY_BYTES
);

pub struct Server {
    raft: Raft<TypeConfig>,
    state_machine_store: Arc<StateMachineStore>,
}

impl Server {
    pub fn new(raft: Raft<TypeConfig>, state_machine_store: Arc<StateMachineStore>) -> Self {
        Self {
            raft,
            state_machine_store,
        }
    }
}
