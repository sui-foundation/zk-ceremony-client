// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use fastcrypto::ed25519::Ed25519PublicKey;
use sui_sdk::types::base_types::SuiAddress;

use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "small_circuit")] {
        pub const CIRCUITS: &[&str] = &["_FE1", "_FE2"];
        pub const TIMEOUT: u64 = 2 * 60;
        pub const MONITOR: u64 = 10;
        pub const MAX_DOWNLOAD_UPLOAD: i32 = 20;
        pub const MAX_WALLET_UPDATE: i32 = 5;
    } else {
        pub const CIRCUITS: &[&str] = &[""];
        pub const TIMEOUT: u64 = 30 * 60;
        pub const MONITOR: u64 = 30;
        pub const MAX_DOWNLOAD_UPLOAD: i32 = 100;
        pub const MAX_WALLET_UPDATE: i32 = 10;
    }
}

cfg_if! {
    if #[cfg(feature = "localhost")] {
        pub const URI: &str = "http://127.0.0.1:37681";
        pub const BASE_PATH: &str = "./data/";
    } else {
        pub const URI: &str = "https://tsc.mystenlabs.com";
        pub const BASE_PATH: &str = "/ts-coordinator/data/";
    }
}

pub const MAX_RPC_PARAMS_SIZE: u32 = 1 << 30;
pub const NUM_CHUNK: u32 = 3;
pub const MAX_DB_ATTEMPT: u32 = 10;

pub fn get_contributor_status_msg(pk: &Ed25519PublicKey) -> String {
    format!("Fetch status of contributor with activation key {:?}", *pk)
}

pub fn get_update_wallet_msg(pk: &Ed25519PublicKey, addr: &SuiAddress) -> String {
    format!(
        "Link contribution by activation pk {:?} to sui address {:?}",
        *pk, *addr
    )
}

pub fn get_join_queue_msg(pk: &Ed25519PublicKey) -> String {
    format!("Join the contribution queue with activation pk {:?}", *pk)
}

pub fn get_contribute_msg(method: &str, pk: &Ed25519PublicKey, hashes: &[String]) -> String {
    let mut msg = format!("Contribute in {} with activation pk {:?}", method, *pk);
    for (i, hash) in hashes.iter().enumerate() {
        msg = msg + &format!(" #{} contribution hash: {:?}", i + 1, hash);
    }
    msg
}
