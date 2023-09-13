// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

use anyhow::anyhow;
use fastcrypto::ed25519::Ed25519PublicKey;
use fastcrypto::encoding::Hex;
use fastcrypto::traits::KeyPair;
use fastcrypto::{
    ed25519::Ed25519KeyPair,
    encoding::{Base64, Encoding},
};
use jsonrpsee::rpc_params;
use phase2::phase2::contribute;
use std::cmp::min;
use std::thread;
use std::time::Duration;
use sui_sdk::types::crypto::{Signature, ToFromBytes};
use tracing::{info, warn};
use zk_ceremony_client::config::{
    get_contribute_msg, get_join_queue_msg, CIRCUITS, MONITOR, NUM_CHUNK, URI,
};
use zk_ceremony_client::logger::init_logger;
use zk_ceremony_client::utils::http_client;
use zk_ceremony_client::utils::{
    read_from_file, sign_msg, write_to_file, ContributeRequest, ContributeResponse,
    GetParamsRequest, GetParamsResponse, GetQueueResponse, JoinQueueRequest, JoinQueueResponse,
    JsonRpcResult,
};

pub fn get_params_path(circuit: &str, counter: &str) -> String {
    "./phase2".to_string() + circuit + "_" + counter + ".params"
}

async fn join_queue(pk: &Ed25519PublicKey, sig: &Signature) -> JsonRpcResult<JoinQueueResponse> {
    let join_queue_query = JoinQueueRequest {
        pk: pk.to_string(),
        sig: Base64::encode(sig),
    };
    http_client(
        URI.to_string(),
        "join_queue".to_string(),
        rpc_params!(join_queue_query.clone()),
    )
    .await
}

async fn get_params(pk: &Ed25519PublicKey, sig: &Signature) -> JsonRpcResult<GetParamsResponse> {
    let get_params_query = GetParamsRequest {
        pk: pk.to_string(),
        sig: Base64::encode(sig),
    };
    http_client(
        URI.to_string(),
        "get_params".to_string(),
        rpc_params!(get_params_query.clone()),
    )
    .await
}

async fn start_contribution(
    pk: &Ed25519PublicKey,
    key: &Ed25519KeyPair,
    old_params: &[String],
    entropy: &str,
) -> anyhow::Result<()> {
    let mut hashes = vec![];
    let mut new_params = vec![];
    for (i, circuit) in CIRCUITS.iter().enumerate() {
        let old_params_path = get_params_path(circuit, "old");
        let new_params_path = get_params_path(circuit, "new");
        let params = Base64::decode(&old_params[i]).map_err(|_| anyhow!("Invalid Base64"))?;
        write_to_file(&old_params_path, &params)?;

        let circuit_entropy = format!("Circuit#{}: ", i)
            + &String::from_utf8(
                Base64::decode(entropy).map_err(|_| anyhow!("Invalid base64 entropy"))?,
            )
            .map_err(|_| anyhow!("Invalid utf-8"))?;

        hashes.push(Hex::encode(
            contribute(
                &old_params_path,
                &new_params_path,
                &circuit_entropy,
                false,
                0,
            )
            .map_err(|e| anyhow!(format!("phase2 error: {e}")))?,
        ));
        new_params.push(read_from_file(&new_params_path)?);
    }

    let msg = get_contribute_msg("docker", pk, &hashes);
    let sig = sign_msg(&key, &msg);

    for num_chunk in 0..NUM_CHUNK {
        let mut response_chunk: Vec<String> = vec![];
        for i in 0..CIRCUITS.len() {
            let chunk_size = 1
                + (new_params[i].len() - 1)
                    / usize::try_from(NUM_CHUNK).map_err(|_| anyhow!("usize to u32 error"))?;
            let start = chunk_size
                * usize::try_from(num_chunk).map_err(|_| anyhow!("usize to u32 error"))?;
            let end = min(start + chunk_size, new_params[i].len());
            response_chunk.push(Base64::encode(&new_params[i][start..end]));
        }

        let contribute_query = ContributeRequest {
            pk: pk.to_string(),
            msg: msg.clone(),
            sig: Base64::encode(&sig),
            method: "docker".to_string(),
            index: num_chunk + 1,
            params: response_chunk,
        };

        let res: JsonRpcResult<ContributeResponse> = http_client(
            URI.to_string(),
            "contribute".to_string(),
            rpc_params!(contribute_query),
        )
        .await;

        match res {
            Ok(res) => {
                if num_chunk == NUM_CHUNK - 1 {
                    info!("#{} contribution successfully recorded", res.index);
                    info!("Thank you for your contribution!");
                }
            }
            Err(e) => {
                return Err(anyhow!("{:?}", e));
            }
        }
    }
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    init_logger();

    info!("Welcome to the zklogin ceremony!");
    info!("Getting you into the queue to start your contribution.");
    info!("You can leave it running in the background.");

    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        info!("Usage: \n<activation_code> <in_str_entropy>");
        std::process::exit(exitcode::USAGE);
    }

    let key = Ed25519KeyPair::from_bytes(
        &Base64::decode(&args[1])
            .map_err(|_| anyhow!("Invalid Base64"))?
            .get(0..32)
            .unwrap_or(&vec![]),
    )
    .map_err(|_| anyhow!("Invalid keypair"))?;

    let msg = get_join_queue_msg(key.public());
    let sig = sign_msg(&key, &msg);

    let mut queue_position = 0;

    loop {
        let get_queue_res: JsonRpcResult<GetQueueResponse> =
            http_client(URI.to_string(), "get_queue".to_string(), rpc_params!()).await;

        match get_queue_res {
            Ok(queue) => {
                if queue.head + 1 >= queue_position {
                    match join_queue(key.public(), &sig).await {
                        Ok(res) => {
                            if res.queue_position != queue_position {
                                info!(
                                    "Assigned new slot #{}, waiting for {} contributors",
                                    res.queue_position,
                                    res.queue_position - queue.head - 1
                                );
                                queue_position = res.queue_position;
                            }
                            if queue.head + 1 == queue_position {
                                match get_params(key.public(), &sig).await {
                                    Ok(res) => {
                                        if res.params.len() == 0 {
                                            continue;
                                        } else {
                                            start_contribution(
                                                key.public(),
                                                &key,
                                                &res.params,
                                                &args[2],
                                            )
                                            .await?;
                                            return Ok(());
                                        }
                                    }
                                    Err(e) => {
                                        return Err(anyhow!("{:?}", e));
                                    }
                                }
                            }
                        }
                        Err(e) => {
                            return Err(anyhow!("{:?}", e));
                        }
                    }
                }
            }
            Err(e) => {
                warn!("{e}");
            }
        }

        let interval = Duration::from_secs(MONITOR);
        thread::sleep(interval);
    }
}
