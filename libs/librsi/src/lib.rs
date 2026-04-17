// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! This module allows to interact with the Arm CCA RSI kernel driver

mod ioctl;
mod token;

pub use ioctl::kernel::RsiRealmConfig;
pub use ioctl::kernel::MAX_MEASUR_LEN;
pub use ioctl::kernel::CHALLENGE_LEN;
pub use ioctl::kernel::GRANULE_LEN;
pub use ioctl::kernel::RSI_RIM_INDEX;
pub use ioctl::kernel::RSI_REM0_INDEX;
pub use ioctl::kernel::RSI_REM1_INDEX;
pub use ioctl::kernel::RSI_REM2_INDEX;
pub use ioctl::kernel::RSI_REM3_INDEX;
pub use ioctl::kernel::RSI_SEALING_KEY_FLAGS_KEY;
pub use ioctl::kernel::RSI_SEALING_KEY_FLAGS_RIM;
pub use ioctl::kernel::RSI_SEALING_KEY_FLAGS_REALM_ID;
pub use ioctl::kernel::RSI_SEALING_KEY_FLAGS_SVN;
pub use ioctl::kernel::RSI_HASH_SHA_256;
pub use ioctl::kernel::RSI_HASH_SHA_512;

pub use ioctl::abi_version;
pub use ioctl::attestation_token;
pub use ioctl::measurement_extend;
pub use ioctl::measurement_read;
pub use ioctl::sealing_key;
pub use ioctl::realm_config;
pub use nix::Error as NixError;

pub use token::AttestationClaims;
pub use token::TokenError;
pub use token::verifier::verify_token;
pub use token::verifier::verify_token_platform;
pub use token::dumper::print_token;
pub use token::dumper::print_token_platform;

pub use token::parser::PlatClaims;
pub use token::parser::PlatSwComponent;
pub use token::parser::RealmClaims;
pub use token::CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS;
