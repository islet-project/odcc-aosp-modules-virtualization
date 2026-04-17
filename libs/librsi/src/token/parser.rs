// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;


/// This structure represents claims
/// included in the CCA platform attestation token
pub struct PlatClaims {
    /// The challenge
    /// it contains the hash of the realm public key
    pub challenge: Vec<u8>,
    /// The URL of a verification service
    pub verification_service: String,
    /// Profile of the CCA platform attestation token
    pub profile: String,
    /// The instance ID of the CCA platform
    pub instance_id: Vec<u8>,
    /// The implementation ID of the CCA platform
    pub implementation_id: Vec<u8>,
    /// The security lifecycle of the platform
    pub lifecycle: i64,
    /// The configuration of the CCA platform
    pub configuration: Vec<u8>,
    /// The hash algorithm used to calculate measurements of
    /// the SW components. It may be overridden by hash algorithm
    /// of an individual SW component
    pub hash_algo: String,
}

fn get_claim(key: u32, claims: &ClaimsMap) -> Result<ClaimData, TokenError> {
    if claims.contains_key(&key) {
        Ok(claims[&key].data.clone())
    } else {
        Err(TokenError::MissingPlatSwClaim(key))
    }
}

impl PlatClaims {
    /// It allows to construct the instance of PlatClaims
    /// from raw claims
    pub fn from_raw_claims(claims: &ClaimsMap) -> Result<Self, TokenError> {
        Ok(Self {
            challenge: get_claim(CCA_PLAT_CHALLENGE, claims)?.try_into()?,
            verification_service: get_claim(CCA_PLAT_VERIFICATION_SERVICE, claims)?.try_into()?,
            profile: get_claim(CCA_PLAT_PROFILE, claims)?.try_into()?,
            instance_id: get_claim(CCA_PLAT_INSTANCE_ID, claims)?.try_into()?,
            implementation_id: get_claim(CCA_PLAT_IMPLEMENTATION_ID, claims)?.try_into()?,
            lifecycle: get_claim(CCA_PLAT_SECURITY_LIFECYCLE, claims)?.try_into()?,
            configuration: get_claim(CCA_PLAT_CONFIGURATION, claims)?.try_into()?,
            hash_algo: get_claim(CCA_PLAT_HASH_ALGO_ID, claims)?.try_into()?,
        })
    }
}

/// This structure represents a platform software component
pub struct PlatSwComponent {
    /// The type of software component (e.g. name)
    pub ty: String,
    /// The hash algorithm used to measure a SW component
    pub hash_algo: String,
    /// The measurement value of a SW component
    pub value: Vec<u8>,
    /// The version of a SW component
    pub version: String,
    /// The identifier of signer of SW component
    pub signer_id: Vec<u8>,
}

impl PlatSwComponent {
    /// It allows to construct the instance of PlatSwComponent
    /// from raw claims
    #[allow(clippy::ptr_arg)]
    pub fn from_raw_claims(
        claims: &ClaimsMap,
        plat_hash_algo: &String,
    ) -> Result<Self, TokenError> {
        Ok(Self {
            ty: get_claim(CCA_SW_COMP_TITLE, claims)?.try_into()?,
            hash_algo: match get_claim(CCA_SW_COMP_HASH_ALGORITHM, claims) {
                Ok(i) => i.try_into()?,
                Err(_) => plat_hash_algo.clone(),
            },
            value: get_claim(CCA_SW_COMP_MEASUREMENT_VALUE, claims)?.try_into()?,
            version: get_claim(CCA_SW_COMP_VERSION, claims)?.try_into()?,
            signer_id: get_claim(CCA_SW_COMP_SIGNER_ID, claims)?.try_into()?,
        })
    }
}

#[derive(Debug)]
/// This structure represents claims
/// included in the realm attestation token
pub struct RealmClaims {
    /// The challenge
    pub challenge: Vec<u8>,
    /// Realm token profile
    pub profile: String,
    /// Personalization value
    pub personalization_value: Vec<u8>,
    /// Hash algorithm used for measurements
    pub hash_algo: String,
    /// Hash algorithm used to cryptographically
    /// bound the realm token with the platform token
    pub pub_key_hash_algo: String,
    /// Public key used to verify the realm token
    pub pub_key: Vec<u8>,
    /// Realm Initial Measurement
    pub rim: Vec<u8>,
    /// Realm Extensible Measurements
    pub rems: [Vec<u8>; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS],
}

impl RealmClaims {
    /// It allows to construct the instance of RealmClaims structure
    /// from raw claims
    #[allow(clippy::needless_range_loop)]
    pub fn from_raw_claims(
        claims: &ClaimsMap,
        measurement_claims: &ClaimsMap,
    ) -> Result<Self, TokenError> {
        let mut rems: [Vec<u8>; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS] =
            <[Vec<u8>; CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS]>::default();

        for i in 0..CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS {
            rems[i] = get_claim(i as u32, measurement_claims)?.try_into()?;
        }

        Ok(Self {
            challenge: get_claim(CCA_REALM_CHALLENGE, claims)?.try_into()?,
            profile: get_claim(CCA_REALM_PROFILE, claims)?.try_into()?,
            personalization_value: get_claim(CCA_REALM_PERSONALIZATION_VALUE, claims)?
                .try_into()?,
            hash_algo: get_claim(CCA_REALM_HASH_ALGO_ID, claims)?.try_into()?,
            pub_key_hash_algo: get_claim(CCA_REALM_PUB_KEY_HASH_ALGO_ID, claims)?.try_into()?,
            pub_key: get_claim(CCA_REALM_PUB_KEY, claims)?.try_into()?,
            rim: get_claim(CCA_REALM_INITIAL_MEASUREMENT, claims)?.try_into()?,
            rems,
        })
    }
}
