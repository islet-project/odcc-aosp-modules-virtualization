// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

/*
 * This file must match kernel API.
 *
 * This includes rsi.h from the rsi module and eventually some internals from
 * the upstream kernel like the version split below.
 */

use std::fmt;

mod internal
{
    use super::{RsiMeasurement, RsiAttestation, RsiSealingKey, RsiRealmConfig};

    // TODO: These should be hex
    nix::ioctl_read!(abi_version, b'x', 190u8, u64);
    nix::ioctl_readwrite_buf!(measurement_read, b'x', 192u8, RsiMeasurement);
    nix::ioctl_write_buf!(measurement_extend, b'x', 193u8, RsiMeasurement);
    nix::ioctl_readwrite_buf!(attestation_token, b'x', 194u8, RsiAttestation);
    nix::ioctl_readwrite_buf!(sealing_key, b'x', 200u8, RsiSealingKey);
    nix::ioctl_read_buf!(realm_config, b'x', 202u8, RsiRealmConfig);
}


/// Maximum measure length in bytes
pub const MAX_MEASUR_LEN: u16 = 0x40;
/// The challenge length in bytes
pub const CHALLENGE_LEN:  u16 = 0x40;
/// Granule length in bytes
pub const GRANULE_LEN:  u16 = 0x1000;

/// The index of Realm Initial Measurement slot
pub const RSI_RIM_INDEX: u32 = 0;
/// The index of 1st Realm Extensible Measurement slot
pub const RSI_REM0_INDEX: u32 = 1;
/// The index of 2nd Realm Extensible Measurement slot
pub const RSI_REM1_INDEX: u32 = 2;
/// The index of 3rd Realm Extensible Measurement slot
pub const RSI_REM2_INDEX: u32 = 3;
/// The index of 4th Realm Extensible Measurement slot
pub const RSI_REM3_INDEX: u32 = 4;

// should be pub(super) but nix leaks the type through pub ioctl definitions
#[repr(C)]
/// This structure is used to store the measurement data exchanged with the RSI driver
pub struct RsiMeasurement
{
    /// The index of measurement slot: 0 - RIM, 1..4 - REMs
    pub(super) index: u32,
    /// The length of measurement
    pub(super) data_len: u32,
    /// Measurement
    pub(super) data: [u8; MAX_MEASUR_LEN as usize],
}

impl RsiMeasurement
{
    /// Constructs an empty RsiMeasurement struct insteance
    pub(super) fn new_empty(index: u32) -> Self
    {
        Self { index, data_len: 0, data: [0; MAX_MEASUR_LEN as usize] }
    }

    /// Constructs a measurement struct instance from provided data and index
    pub(super) fn new_from_data(index: u32, src: &[u8]) -> Self
    {
        // panic on wrong size here to avoid obscured panic below
        assert!(!src.is_empty() && src.len() <= MAX_MEASUR_LEN as usize);

        let mut data = [0u8; MAX_MEASUR_LEN as usize];
        data[..src.len()].copy_from_slice(src);
        Self { index, data_len: src.len().try_into().unwrap(), data }
    }
}

// should be pub(super) but nix leaks the type through pub ioctl definitions
/// This structure represents the Arm CCA attestation token (attestation evidence)
/// retrieved from the RSI driver
#[repr(C)]
pub struct RsiAttestation
{
    /// A challenge field filled by the client
    /// This will be sent to the RSI kernel driver which delegates attestation token
    /// generation to the Realm Management Monitor
    pub(super) challenge: [u8; CHALLENGE_LEN as usize],
    /// The length of the returned attestation token in bytes
    pub(super) token_len: u64,
    /// Contains the RAW Arm CCA attestation token
    pub(super) token: *mut u8,
}

impl RsiAttestation
{
    /// Constructs an instance of RsiAttesation struct using the challenge and expected token length
    pub(super) fn new(src: &[u8; CHALLENGE_LEN as usize], token_len: u64) -> Self
    {
        Self { challenge: *src, token_len, token: std::ptr::null_mut() }
    }
}

/// Bit representing the Input Key Material (IKM) used for sealing key derivation
/// If the bit is set, the derivation process takes the Virtual Hardware Unique Key that depends on the binary measurements of firmware components (VHUK_M)
/// if the bit is not set, the derivation process takes the Virtual Hardware Unique Key that depends on the authority data of firmware components (VHUK_A)
pub const RSI_SEALING_KEY_FLAGS_KEY:      u64 = 1 << 0;
/// If the bit is set, include the RIM (Realm Initial Measurement) during derivation of the sealing key
pub const RSI_SEALING_KEY_FLAGS_RIM:      u64 = 1 << 1;
/// If the bit is set, include the Realm identifier during derivation of the sealing key
pub const RSI_SEALING_KEY_FLAGS_REALM_ID: u64 = 1 << 2;
/// If the bit is set, include the Security Version Number of Realm during derivation of the sealing key
pub const RSI_SEALING_KEY_FLAGS_SVN:      u64 = 1 << 3;
/// The sealing key derivation flags bitmask
pub(super) const RSI_SEALING_KEY_FLAGS_MASK:     u64 = 0x0F;

#[repr(C)]
/// This structure is used to exchange the sealing key with the RSI driver
pub struct RsiSealingKey
{
    /// Flags used to control the sealing key derivation process
    pub(super) flags: u64,
    /// Security Version Number
    pub(super) svn: u64,
    /// The resulting Realm Sealing Key
    pub(super) realm_sealing_key: [u8; 32]
}

impl RsiSealingKey
{
    /// Constructs the RsiSealingKey structure using flags and svn number
    pub(super) fn new(flags: u64, svn: u64) -> Self
    {
        Self { flags: flags & RSI_SEALING_KEY_FLAGS_MASK, svn, realm_sealing_key: [0u8; 32] }
    }
}

/// SHA256 Hash algorithm used for Realm measurements
pub const RSI_HASH_SHA_256: u32 = 0;
/// SHA512 Hash algorithm used for Realm measurements
pub const RSI_HASH_SHA_512: u32 = 1;

/// A struct representing the Realm Config
#[repr(C)]
#[derive(Clone)]
pub struct RsiRealmConfig
{
    /// Width of IPA in bits
    pub ipa_bits: u32,
    /// Hash algorithm
    pub hash_algo: u32,
    /// Realm Personalization Value
    pub rpv: [u8; 64]
}

impl Default for RsiRealmConfig {
    fn default() -> Self {
        Self {
            ipa_bits: 0,
            hash_algo: 0,
            rpv: [0; 64],
        }
    }
}

impl fmt::Display for RsiRealmConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let hash_algo_str = match self.hash_algo {
            RSI_HASH_SHA_256 => "sha256",
            RSI_HASH_SHA_512 => "sha512",
            _ => "unknown"
        };
        write!(f, "ipa_bits: {} hash_algo: {} rpv: {}", self.ipa_bits, hash_algo_str, hex::encode(self.rpv))
    }
}

/// Retrieves the major component of version
pub(super) const fn abi_version_get_major(version: u64) -> u32
{
    ((version & 0x7FFF0000) >> 16) as u32
}

/// Retrieves the minor component of version
pub(super) const fn abi_version_get_minor(version: u64) -> u32
{
    (version & 0xFFFF) as u32
}

/// Retrieves the version from the RSI driver
pub(super) fn abi_version(fd: i32, data: *mut u64) -> nix::Result<()>
{
    //  SAFETY: Internally it calls the ioctl on the RSI device driver
    unsafe { internal::abi_version(fd, data) }.map(|_| ())
}

/// Reads the measurement from the RSI driver
pub(super) fn measurement_read(fd: i32, data: &mut [RsiMeasurement]) -> nix::Result<()>
{
    //  SAFETY: Internally it calls the ioctl on the RSI device driver
    unsafe { internal::measurement_read(fd, data) }.map(|_| ())
}

/// Extends the measurement
pub(super) fn measurement_extend(fd: i32, data: &[RsiMeasurement]) -> nix::Result<()>
{
    //  SAFETY: Internally it calls the ioctl on the RSI device driver
    unsafe { internal::measurement_extend(fd, data) }.map(|_| ())
}

/// Retrieves the Arm CCA attestation token
pub(super) fn attestation_token(fd: i32, data: &mut [RsiAttestation]) -> nix::Result<()>
{
    //  SAFETY: Internally it calls the ioctl on the RSI device driver
    unsafe { internal::attestation_token(fd, data) }.map(|_| ())
}

/// Retrieves the sealing key
pub(super) fn sealing_key(fd: i32, data: &mut [RsiSealingKey]) -> nix::Result<()>
{
    //  SAFETY: Internally it calls the ioctl on the RSI device driver
    unsafe { internal::sealing_key(fd, data) }.map(|_| ())
}

pub(super) fn realm_config(fd: i32, data: &mut [RsiRealmConfig]) -> nix::Result<()>
{
    //  SAFETY: Internally it calls the ioctl on the RSI device driver
    unsafe { internal::realm_config(fd, data) }.map(|_| ())
}
