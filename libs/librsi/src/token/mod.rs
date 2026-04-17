// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

pub(crate) mod crypto;
pub(crate) mod dumper;
pub(crate) mod verifier;
pub(crate) mod parser;


use ciborium::de;
use coset::CoseSign1;
use std::collections::HashMap;
use std::fmt::Debug;
use std::default::Default;


const TAG_COSE_SIGN1: u64 =                             18;
const TAG_CCA_TOKEN: u64 =                             399;

const CCA_PLAT_TOKEN: u32 =                          44234;
const CCA_REALM_DELEGATED_TOKEN: u32 =               44241;

/* CCA Platform Attestation Token */
const CCA_PLAT_CHALLENGE: u32 =                         10;
const CCA_PLAT_INSTANCE_ID: u32 =                      256;
const CCA_PLAT_PROFILE: u32 =                          265;
const CCA_PLAT_SECURITY_LIFECYCLE: u32 =              2395;
const CCA_PLAT_IMPLEMENTATION_ID: u32 =               2396;
const CCA_PLAT_SW_COMPONENTS: u32 =                   2399;
const CCA_PLAT_VERIFICATION_SERVICE: u32 =            2400;
const CCA_PLAT_CONFIGURATION: u32 =                   2401;
const CCA_PLAT_HASH_ALGO_ID: u32 =                    2402;

/* CCA Realm Delegated Attestation Token */
const CCA_REALM_CHALLENGE: u32 =                        10;
const CCA_REALM_PROFILE: u32 =                         265;
const CCA_REALM_PERSONALIZATION_VALUE: u32 =         44235;
const CCA_REALM_HASH_ALGO_ID: u32 =                  44236;
const CCA_REALM_PUB_KEY: u32 =                       44237;
const CCA_REALM_INITIAL_MEASUREMENT: u32 =           44238;
const CCA_REALM_EXTENSIBLE_MEASUREMENTS: u32 =       44239;
const CCA_REALM_PUB_KEY_HASH_ALGO_ID: u32 =          44240;

/* Software components */
const CCA_SW_COMP_TITLE: u32 =                           1;
const CCA_SW_COMP_MEASUREMENT_VALUE: u32 =               2;
const CCA_SW_COMP_VERSION: u32 =                         4;
const CCA_SW_COMP_SIGNER_ID: u32 =                       5;
const CCA_SW_COMP_HASH_ALGORITHM: u32 =                  6;

/* Counts */
const CLAIM_COUNT_REALM_TOKEN: usize =                   7;
const CLAIM_COUNT_PLATFORM_TOKEN: usize =                8;
/// The number of available Realm Extensible Measurement (REM) slots
pub const CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS: usize = 4;
const CLAIM_COUNT_SW_COMPONENT: usize =                  5;
const MAX_SW_COMPONENT_COUNT: usize =                   32;


#[derive(Debug, Clone)]
/// Represents attestation token claims values
pub enum ClaimData
{
    Bool(bool),
    Int64(i64),
    Bstr(Vec<u8>),
    Text(String),
}

#[allow(dead_code)]
impl ClaimData
{
    fn new_bool() -> Self {
        ClaimData::Bool(false)
    }
    fn new_int64() -> Self {
        ClaimData::Int64(0)
    }
    fn new_bstr() -> Self {
        ClaimData::Bstr(Vec::new())
    }
    fn new_text() -> Self {
        ClaimData::Text(String::new())
    }

    fn get_bool(&self) -> bool {
        if let ClaimData::Bool(b) = self {
            *b
        } else {
            panic!("ClaimData is not Bool");
        }
    }
    fn get_int64(&self) -> i64 {
        if let ClaimData::Int64(i) = self {
            *i
        } else {
            panic!("ClaimData is not Int64");
        }
    }
    fn get_bstr(&self) -> &[u8] {
        if let ClaimData::Bstr(d) = self {
            d
        } else {
            panic!("ClaimData is not Bstr");
        }
    }
    fn get_text(&self) -> &str {
        if let ClaimData::Text(s) = self {
            s
        } else {
            panic!("ClaimData is not Text");
        }
    }
}

impl TryInto<String> for ClaimData {
    type Error = TokenError;

    fn try_into(self) -> Result<String, Self::Error> {
        if let ClaimData::Text(v) = self {
            Ok(v)
        } else {
            Err(TokenError::ClaimDataMisMatchType)
        }
    }
}

impl TryInto<Vec<u8>> for ClaimData {
    type Error = TokenError;

    fn try_into(self) -> Result<Vec<u8>, Self::Error> {
        if let ClaimData::Bstr(v) = self {
            Ok(v)
        } else {
            Err(TokenError::ClaimDataMisMatchType)
        }
    }
}

impl TryInto<i64> for ClaimData {
    type Error = TokenError;

    fn try_into(self) -> Result<i64, Self::Error> {
        if let ClaimData::Int64(v) = self {
            Ok(v)
        } else {
            Err(TokenError::ClaimDataMisMatchType)
        }
    }
}

impl Default for ClaimData
{
    fn default() -> Self
    {
        Self::Bool(false)
    }
}

#[derive(Debug, Default)]
/// Represents the Claim - A piece of asserted information, often in the form of a name/value pair.
/// provides atomic information used during verification of
/// the attestation token
/// The attestation tokens are comprised from multiple claims
pub struct Claim
{
    /// If set the claim is mandatory
    pub mandatory: bool,
    /// The title of the claim
    pub title: String,
    /// If set the claim is present
    pub present: bool,
    /// Contains the claims data
    pub data: ClaimData,
}

impl Claim
{
    fn new(mandatory: bool, data: ClaimData, title: &str, present: bool) -> Self
    {
        Self {
            mandatory,
            data,
            title: title.to_string(),
            present,
        }
    }
}

type ClaimsMap = HashMap<u32, Claim>;

#[derive(Debug, Default)]
/// Represents software component
pub struct SwComponent
{
    /// If set, the software component is present
    pub present: bool,
    /// The set of claims for a particular SwComponent
    pub claims: ClaimsMap,
}

#[derive(Debug, Default)]
/// Represents the Realm attestation token
pub struct RealmToken
{
    /// COSE signature
    pub cose_sign1: CoseSign1,
    /// The set of standard Realm claims
    pub token_claims: ClaimsMap,
    /// The set of claims representing measurements
    pub measurement_claims: ClaimsMap,
}

#[derive(Debug, Default)]
/// The structure representing the CCA platform attestation token
pub struct PlatformToken
{
    /// COSE signature
    pub cose_sign1: CoseSign1,
    /// The set of standard Arm CCA Platform claims
    pub token_claims: ClaimsMap,
    /// The set of software components
    pub sw_component_claims: [SwComponent; MAX_SW_COMPONENT_COUNT],
}

impl RealmToken
{
    fn new() -> Self
    {
        let mut token = Self::default();

        token.token_claims.insert(CCA_REALM_CHALLENGE,             Claim::new(true, ClaimData::new_bstr(), "Realm challenge",               false));
        token.token_claims.insert(CCA_REALM_PROFILE,               Claim::new(true, ClaimData::new_text(), "Realm profile",                 false));
        token.token_claims.insert(CCA_REALM_PERSONALIZATION_VALUE, Claim::new(true, ClaimData::new_bstr(), "Realm personalization value",   false));
        token.token_claims.insert(CCA_REALM_HASH_ALGO_ID,          Claim::new(true, ClaimData::new_text(), "Realm hash algo id",            false));
        token.token_claims.insert(CCA_REALM_PUB_KEY_HASH_ALGO_ID,  Claim::new(true, ClaimData::new_text(), "Realm public key hash algo id", false));
        token.token_claims.insert(CCA_REALM_PUB_KEY,               Claim::new(true, ClaimData::new_bstr(), "Realm signing public key",      false));
        token.token_claims.insert(CCA_REALM_INITIAL_MEASUREMENT,   Claim::new(true, ClaimData::new_bstr(), "Realm initial measurement",     false));
        assert!(token.token_claims.len() == CLAIM_COUNT_REALM_TOKEN);

        let mut count = 0;
        loop {
            token.measurement_claims.insert(count, Claim::new(true, ClaimData::new_bstr(), "Realm extensible measurement", false));
            count += 1;
            if count as usize == CLAIM_COUNT_REALM_EXTENSIBLE_MEASUREMENTS {
                break;
            }
        }

        token
    }
}

impl PlatformToken
{
    fn new() -> Self
    {
        let mut token = Self::default();

        token.token_claims.insert(CCA_PLAT_CHALLENGE,            Claim::new(true,  ClaimData::new_bstr(),  "Challange",            false));
        token.token_claims.insert(CCA_PLAT_VERIFICATION_SERVICE, Claim::new(false, ClaimData::new_text(),  "Verification service", false));
        token.token_claims.insert(CCA_PLAT_PROFILE,              Claim::new(true,  ClaimData::new_text(),  "Profile",              false));
        token.token_claims.insert(CCA_PLAT_INSTANCE_ID,          Claim::new(true,  ClaimData::new_bstr(),  "Instance ID",          false));
        token.token_claims.insert(CCA_PLAT_IMPLEMENTATION_ID,    Claim::new(true,  ClaimData::new_bstr(),  "Implementation ID",    false));
        token.token_claims.insert(CCA_PLAT_SECURITY_LIFECYCLE,   Claim::new(true,  ClaimData::new_int64(), "Lifecycle",            false));
        token.token_claims.insert(CCA_PLAT_CONFIGURATION,        Claim::new(true,  ClaimData::new_bstr(),  "Configuration",        false));
        token.token_claims.insert(CCA_PLAT_HASH_ALGO_ID,         Claim::new(true,  ClaimData::new_text(),  "Platform hash algo",   false));
        assert!(token.token_claims.len() == CLAIM_COUNT_PLATFORM_TOKEN);

        for component in &mut token.sw_component_claims {
            component.present = false;
            component.claims.insert(CCA_SW_COMP_TITLE,             Claim::new(true,  ClaimData::new_text(), "SW Type",           false));
            component.claims.insert(CCA_SW_COMP_HASH_ALGORITHM,    Claim::new(false, ClaimData::new_text(), "Hash algorithm",    false));
            component.claims.insert(CCA_SW_COMP_MEASUREMENT_VALUE, Claim::new(true,  ClaimData::new_bstr(), "Measurement value", false));
            component.claims.insert(CCA_SW_COMP_VERSION,           Claim::new(false, ClaimData::new_text(), "Version",           false));
            component.claims.insert(CCA_SW_COMP_SIGNER_ID,         Claim::new(true,  ClaimData::new_bstr(), "Signer ID",         false));
            assert!(component.claims.len() == CLAIM_COUNT_SW_COMPONENT);
        }

        token
    }
}

#[derive(Debug, Default)]
/// This represents the attestation claims
pub struct AttestationClaims
{
    /// The Realm token
    pub realm_claims: RealmToken,
    /// The Arm CCA platform token
    pub platform_claims: PlatformToken,
}

impl AttestationClaims
{
    fn new(realm_claims: RealmToken, platform_claims: PlatformToken) -> Self
    {
        Self { realm_claims, platform_claims }
    }
}

#[derive(Debug)]
/// Represents errors encountered during parsing or verifying
/// the attestation token
pub enum TokenError
{
    /// The key is invalid
    InvalidKey(&'static str),
    /// The tag is invalid
    InvalidTag(&'static str),
    /// The format of the token is invalid
    InvalidTokenFormat(&'static str),
    /// Not implemented functionality
    NotImplemented(&'static str),
    /// The verification process has failed
    VerificationFailed(&'static str),
    /// Invalid algorithm
    InvalidAlgorithm(Option<coset::Algorithm>),
    /// Ciborium deserialization error
    Ciborium(de::Error<std::io::Error>),
    /// Coset error
    Coset(coset::CoseError),
    /// Missing platform claim
    MissingPlatClaim(u32),
    /// Missing Platform SW component claim
    MissingPlatSwClaim(u32),
    /// Mismatched data type
    ClaimDataMisMatchType,
}

impl std::fmt::Display for TokenError
{
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result
    {
        write!(f, "{:?}", self)
    }
}

impl std::error::Error for TokenError {}

impl From<de::Error<std::io::Error>> for TokenError
{
    fn from(value: de::Error<std::io::Error>) -> Self {
        Self::Ciborium(value)
    }
}

impl From<coset::CoseError> for TokenError
{
    fn from(value: coset::CoseError) -> Self {
        Self::Coset(value)
    }
}
