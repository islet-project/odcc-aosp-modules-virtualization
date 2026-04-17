// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use anyhow::Result;
use crate::MicrodroidData;
use log::info;
use openssl::sha::Sha512;
use rsi::{abi_version, measurement_extend, measurement_read, realm_config,
    RSI_RIM_INDEX, RSI_REM0_INDEX, RSI_REM1_INDEX, RSI_REM2_INDEX, RSI_REM3_INDEX};
use std::sync::Once;
use std::sync::atomic::AtomicBool;
use std::sync::atomic::Ordering;

static ARM_CCA_SUPPORTED_FLAG: AtomicBool = AtomicBool::new(false);
static ARM_CCA_ONCE: Once = Once::new();

pub fn is_arm_cca_supported() -> bool
{
    ARM_CCA_ONCE.call_once(|| {
        let feature_supported = abi_version().is_ok();
        ARM_CCA_SUPPORTED_FLAG.store(feature_supported, Ordering::SeqCst);
    });

    ARM_CCA_SUPPORTED_FLAG.load(Ordering::SeqCst)
}

pub fn extend_measurements_for_payload(
    instance_data: &MicrodroidData
) -> Result<()> {
    let mut code_hash_ctx = Sha512::new();
    let mut authority_hash_ctx = Sha512::new();

    code_hash_ctx.update(instance_data.apk_data.root_hash.as_ref());
    authority_hash_ctx.update(instance_data.apk_data.cert_hash.as_ref());

    for extra_apk in &instance_data.extra_apks_data {
        code_hash_ctx.update(extra_apk.root_hash.as_ref());
        authority_hash_ctx.update(extra_apk.cert_hash.as_ref());
    }

    for apex in &instance_data.apex_data {
        code_hash_ctx.update(apex.root_digest.as_ref());
        authority_hash_ctx.update(apex.public_key.as_ref());
    }

    let code_hash = code_hash_ctx.finish();
    let authority_hash = authority_hash_ctx.finish();

    measurement_extend(RSI_REM1_INDEX, &code_hash)?;
    measurement_extend(RSI_REM1_INDEX, &authority_hash)?;

    Ok(())
}

pub fn display_realm_config() -> Result<()> {
    let config = realm_config()?;
    info!("Realm Config: {}", config);
    Ok(())
}

pub fn display_realm_measurements() -> Result<()> {
    let rim = measurement_read(RSI_RIM_INDEX)?;
    let rem0 = measurement_read(RSI_REM0_INDEX)?;
    let rem1 = measurement_read(RSI_REM1_INDEX)?;
    let rem2 = measurement_read(RSI_REM2_INDEX)?;
    let rem3 = measurement_read(RSI_REM3_INDEX)?;

    info!("RIM: {}", hex::encode(rim.as_slice()));
    info!("REM0: {}", hex::encode(rem0.as_slice()));
    info!("REM1: {}", hex::encode(rem1.as_slice()));
    info!("REM2: {}", hex::encode(rem2.as_slice()));
    info!("REM3: {}", hex::encode(rem3.as_slice()));

    Ok(())
}
