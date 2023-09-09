// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use std::time::Duration;

use crate::config::{MAX_RPC_PARAMS_SIZE, TIMEOUT};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::core::params::ArrayParams;
use jsonrpsee::http_client::HttpClientBuilder;
use serde::de::DeserializeOwned;

use fastcrypto::ed25519::{Ed25519KeyPair, Ed25519PublicKey};
use jsonrpsee::types::ErrorObject;
use serde::{Deserialize, Serialize};
use shared_crypto::intent::{Intent, IntentMessage, IntentScope, PersonalMessage};
use std::fs::File;
use std::io::{Read, Write};
use sui_sdk::types::base_types::SuiAddress;
use sui_sdk::types::crypto::SuiSignature;
use sui_sdk::types::crypto::{Ed25519SuiSignature, Signature};
use tracing::info;

pub type JsonRpcResult<T> = Result<T, jsonrpsee_types::ErrorObject<'static>>;

// Query to get queue length
#[derive(Debug, Serialize, Deserialize)]
pub struct GetQueueResponse {
    pub head: i32,
    pub tail: i32,
    pub contribution: i32,
}

// Query to get contributor status by activation pk
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetContributorRequest {
    pub pk: String,
    pub sig: String,
}

// Query to join the queue
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct JoinQueueRequest {
    pub pk: String,
    pub sig: String,
}

// Response to join_queue query
#[derive(Debug, Serialize, Deserialize)]
pub struct JoinQueueResponse {
    pub queue_position: i32,
}

// Query to get the params
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct GetParamsRequest {
    pub pk: String,
    pub sig: String,
}

// Response to get_params query
#[derive(Debug, Serialize, Deserialize)]
pub struct GetParamsResponse {
    pub params: Vec<String>,
}

// Query to submit new params files
#[derive(Debug, Serialize, Deserialize)]
pub struct ContributeRequest {
    pub pk: String,
    pub msg: String,
    pub sig: String,
    pub method: String,
    pub index: u32,
    pub params: Vec<String>,
}

// Response to new contributions
#[derive(Debug, Serialize, Deserialize)]
pub struct ContributeResponse {
    pub index: i32,
}

// Query in browser to add new ephemeral public key
#[derive(Debug, Serialize, Deserialize)]
pub struct UpdateWalletRequest {
    pub pk: String,
    pub address: String,
    pub sig: String,
}

pub fn to_json_rpc_err(msg: &str) -> ErrorObject {
    ErrorObject::owned(1, msg.to_string(), None::<String>)
}

pub fn read_from_file(file_path: &str) -> JsonRpcResult<Vec<u8>> {
    let mut file = match File::open(file_path) {
        Ok(f) => f,
        Err(e) => {
            info!("{e}");
            return Err(to_json_rpc_err("Open file error"));
        }
    };
    let mut content = vec![];
    match file.read_to_end(&mut content) {
        Ok(_) => Ok(content),
        Err(e) => {
            info!("{e}");
            Err(to_json_rpc_err("Read file error"))
        }
    }
}

pub fn write_to_file(file_path: &str, content: &[u8]) -> JsonRpcResult<()> {
    let mut file = match File::create(file_path) {
        Ok(f) => f,
        Err(e) => {
            info!("{e}");
            return Err(to_json_rpc_err("Open file error"));
        }
    };
    match file.write_all(content) {
        Ok(()) => Ok(()),
        Err(e) => {
            info!("{e}");
            return Err(to_json_rpc_err("Write file error"));
        }
    }
}

pub fn sign_msg(key: &Ed25519KeyPair, msg: &String) -> Signature {
    Signature::new_secure(
        &IntentMessage::new(
            Intent::sui_app(IntentScope::PersonalMessage),
            PersonalMessage {
                message: msg.as_bytes().to_vec(),
            },
        ),
        key,
    )
}

pub fn verify_sig(
    sig: &Ed25519SuiSignature,
    pk: &Ed25519PublicKey,
    msg: &String,
) -> JsonRpcResult<()> {
    let addr = SuiAddress::from(pk);
    sig.verify_secure(
        &IntentMessage::new(
            Intent::sui_app(IntentScope::PersonalMessage),
            PersonalMessage {
                message: msg.as_bytes().to_vec(),
            },
        ),
        addr,
        sui_sdk::types::crypto::SignatureScheme::ED25519,
    )
    .map_err(|_| to_json_rpc_err("Signature verification failed"))
}

pub async fn http_client<T: DeserializeOwned>(
    uri: String,
    method: String,
    params: ArrayParams,
) -> JsonRpcResult<T> {
    let client = HttpClientBuilder::default()
        .max_request_size(MAX_RPC_PARAMS_SIZE)
        .max_response_size(MAX_RPC_PARAMS_SIZE)
        .request_timeout(Duration::from_secs(TIMEOUT))
        .build(uri)
        .map_err(|_| to_json_rpc_err("Failed to build http client"))?;

    let response = client.request(&method, params).await;
    match response {
        Ok(r) => Ok(r),
        Err(e) => {
            info!("{e}");
            Err(to_json_rpc_err("Rpc call error"))
        }
    }
}
