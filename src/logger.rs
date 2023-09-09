// Copyright (c) 2022, Mysten Labs, Inc.
// SPDX-License-Identifier: Apache-2.0

pub fn init_logger() {
    tracing_subscriber::FmtSubscriber::builder()
        .try_init()
        .expect("setting default subscriber failed");
}
