// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implementation of Realm Management Monitor (RMM) measurement extend functionality.

use ring::digest::{self, Context};

/// Maximum Realm Measurement Width in Bytes
pub const RMM_REALM_MEASUREMENT_WIDTH: usize = 64;

/// Hash algorithm enumeration for realm measurements.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RmmHashAlgorithm {
    /// SHA-256 (Secure Hash Standard)
    HashSha256,
    /// SHA-512 (Secure Hash Standard)
    HashSha512,
}

impl RmmHashAlgorithm {
    /// Returns the digest algorithm for ring library.
    fn digest_algorithm(&self) -> &'static digest::Algorithm {
        match self {
            RmmHashAlgorithm::HashSha256 => &digest::SHA256,
            RmmHashAlgorithm::HashSha512 => &digest::SHA512,
        }
    }

    /// Returns the output size in bytes for this hash algorithm.
    pub fn output_size(&self) -> usize {
        self.digest_algorithm().output_len
    }
}

/// Realm Extensible Measurement (REM) - a 512-bit measurement value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RmmRealmMeasurement {
    /// The 512-bit measurement value (64 bytes)
    data: [u8; RMM_REALM_MEASUREMENT_WIDTH],
}

impl RmmRealmMeasurement {
    /// Creates a new measurement with all zeros (initial value).
    pub const fn new() -> Self {
        Self { data: [0u8; RMM_REALM_MEASUREMENT_WIDTH] }
    }

    /// Creates a measurement from a byte slice.
    ///
    /// # Panics
    /// Panics if the slice is not exactly 64 bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), RMM_REALM_MEASUREMENT_WIDTH, "RmmRealmMeasurement must be exactly 64 bytes");
        let mut data = [0u8; RMM_REALM_MEASUREMENT_WIDTH];
        data.copy_from_slice(bytes);
        Self { data }
    }

    /// Creates a measurement from a byte slice, zero-padding if necessary.
    ///
    /// If the slice is shorter than 64 bytes, the remaining bytes are zero-padded.
    /// If the slice is longer than 64 bytes, only the first 64 bytes are used.
    pub fn from_bytes_padded(bytes: &[u8]) -> Self {
        let mut data = [0u8; RMM_REALM_MEASUREMENT_WIDTH];
        let copy_len = bytes.len().min(RMM_REALM_MEASUREMENT_WIDTH);
        data[0..copy_len].copy_from_slice(&bytes[0..copy_len]);
        Self { data }
    }

    /// Returns the measurement as a byte array.
    pub fn as_bytes(&self) -> &[u8; RMM_REALM_MEASUREMENT_WIDTH] {
        &self.data
    }

    /// Returns the measurement as a mutable byte slice.
    pub fn as_bytes_mut(&mut self) -> &mut [u8; RMM_REALM_MEASUREMENT_WIDTH] {
        &mut self.data
    }
}

impl Default for RmmRealmMeasurement {
    fn default() -> Self {
        Self::new()
    }
}

/// Extends a Realm Extensible Measurement (REM) with a new value.
///
/// This function implements the RemExtend operation from the RMM specification:
/// - Takes `size` LSBs from `new_value`
/// - Zero-pads the remaining byes   to form a 512-bit value
/// - Hashes the result using the specified algorithm
/// - Returns the new measurement value
///
/// # Arguments
/// * `hash_algo` - The hash algorithm to use (SHA-256 or SHA-512)
/// * `old_value` - The current measurement value
/// * `new_value` - The value to extend the measurement with
/// * `size` - The number of most significant bytes to use from `new_value`
///
/// # Returns
/// The new measurement value after extension
///
/// # Panics
/// Panics if `size` is greater than 64 bytes.
pub fn rem_extend(
    hash_algo: RmmHashAlgorithm,
    old_value: RmmRealmMeasurement,
    new_value: RmmRealmMeasurement,
    size: usize,
) -> RmmRealmMeasurement {
    assert!(size <= RMM_REALM_MEASUREMENT_WIDTH, "size cannot exceed 64 bytes");

    // Create new measurement: hash(old_value || hash_of_new)
    let algorithm = hash_algo.digest_algorithm();
    let mut context = Context::new(algorithm);

    // The previous measurement is truncated to hash_algo.size
    let old_value_truncated = &old_value.as_bytes()[0..hash_algo.output_size()];
    let new_value_truncated = &new_value.as_bytes()[0..size];

    // Include old measurement in the hash
    context.update(old_value_truncated);
    // Include hash of new value
    context.update(new_value_truncated);

    let result_digest = context.finish();

    // Create new measurement from the hash result
    // If the hash output is smaller than 64 bytes (512 bits), we zero-pad it
    let mut result = RmmRealmMeasurement::new();
    let copy_len = result_digest.as_ref().len().min(RMM_REALM_MEASUREMENT_WIDTH);
    result.as_bytes_mut()[0..copy_len].copy_from_slice(&result_digest.as_ref()[0..copy_len]);

    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_measurement_initial_value_is_zero() {
        let meas = RmmRealmMeasurement::new();
        assert_eq!(meas.as_bytes(), &[0u8; RMM_REALM_MEASUREMENT_WIDTH]);
    }

    #[test]
    fn test_measurement_from_bytes() {
        let mut bytes = [0u8; RMM_REALM_MEASUREMENT_WIDTH];
        bytes[0] = 0x12;
        bytes[1] = 0x34;
        bytes[63] = 0xAB;

        let meas = RmmRealmMeasurement::from_bytes(&bytes);
        assert_eq!(meas.as_bytes(), &bytes);
    }

    #[test]
    fn test_rem_extend_with_sha256() {
        let old_value = RmmRealmMeasurement::new();
        let mut new_value = RmmRealmMeasurement::new();
        new_value.as_bytes_mut()[0] = 0x42;

        // Extend with 8 bits of data
        let result = rem_extend(RmmHashAlgorithm::HashSha256, old_value, new_value, 8);

        // Result should not be zero since we hashed non-zero input
        assert_ne!(result.as_bytes(), &[0u8; RMM_REALM_MEASUREMENT_WIDTH]);
    }

    #[test]
    fn test_rem_extend_with_sha512() {
        let old_value = RmmRealmMeasurement::new();
        let mut new_value = RmmRealmMeasurement::new();
        new_value.as_bytes_mut()[0] = 0x42;

        let result = rem_extend(RmmHashAlgorithm::HashSha512, old_value, new_value, 1);

        assert_ne!(result.as_bytes(), &[0u8; RMM_REALM_MEASUREMENT_WIDTH]);
    }

    #[test]
    #[should_panic(expected = "size cannot exceed 64 bytes")]
    fn test_rem_extend_size_too_large() {
        let old_value = RmmRealmMeasurement::new();
        let new_value = RmmRealmMeasurement::new();
        rem_extend(RmmHashAlgorithm::HashSha256, old_value, new_value, 65);
    }

    #[test]
    fn test_rem_extend_deterministic() {
        let old_value = RmmRealmMeasurement::new();
        let mut new_value = RmmRealmMeasurement::new();
        new_value.as_bytes_mut()[0] = 0x42;

        let result1 = rem_extend(RmmHashAlgorithm::HashSha256, old_value, new_value, 1);
        let result2 = rem_extend(RmmHashAlgorithm::HashSha256, old_value, new_value, 1);

        assert_eq!(result1.as_bytes(), result2.as_bytes());
    }
}
