// Copyright (c) 2026 Samsung Electronics Co., Ltd. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

use super::*;

use ciborium::{de, value::Value};
use coset::{AsCborValue, iana, CoseKey, Label};
use ring:: {
    signature::{self},
    digest::{Context, SHA256, SHA384, SHA512},
};

#[derive(PartialEq)]
enum SigningAlgorithm
{
    // sha256 + secp256r1/prime256v1/P-256
    ES256,
    // sha384 + secp384r1/P-384
    ES384,
    // sha512 + secp521r1/P-521
    ES512,
}

const COSE_EC2_ALGORITHM_LABEL: coset::Label = Label::Int(iana::Ec2KeyParameter::Crv as i64);
const COSE_EC2_KEY_PARAM_X_LABEL: Label = Label::Int(iana::Ec2KeyParameter::X as i64);
const COSE_EC2_KEY_PARAM_Y_LABEL: Label = Label::Int(iana::Ec2KeyParameter::Y as i64);

impl TryFrom<coset::Algorithm> for SigningAlgorithm
{
    type Error = TokenError;

    fn try_from(alg: coset::Algorithm) -> Result<Self, Self::Error>
    {
        match alg {
            coset::Algorithm::Assigned(coset::iana::Algorithm::ES256) => Ok(SigningAlgorithm::ES256),
            coset::Algorithm::Assigned(coset::iana::Algorithm::ES384) => Ok(SigningAlgorithm::ES384),
            coset::Algorithm::Assigned(coset::iana::Algorithm::ES512) => Ok(SigningAlgorithm::ES512),
            unknown => Err(TokenError::InvalidAlgorithm(Some(unknown))),
        }
    }
}

impl TryFrom<&str> for SigningAlgorithm
{
    type Error = TokenError;

    fn try_from(alg: &str) -> Result<Self, Self::Error>
    {
        match alg {
            "sha-256" => Ok(SigningAlgorithm::ES256),
            "sha-384" => Ok(SigningAlgorithm::ES384),
            "sha-512" => Ok(SigningAlgorithm::ES512),
            _ => Err(TokenError::InvalidTokenFormat("invalid hash algorithm")),
        }
    }
}

fn get_uncompressed_public_key_from_cosekey(key: &CoseKey) -> Result<(Vec<u8>, SigningAlgorithm), TokenError>
{
    let mut x_component: Vec<u8> = Vec::new();
    let mut y_component: Vec<u8> = Vec::new();

    let mut algorithm: Option::<SigningAlgorithm> = None;
    for pair in &key.params {
        match pair {
            (COSE_EC2_ALGORITHM_LABEL, val) => {
                if *val == Value::from(iana::EllipticCurve::P_256 as u64) {
                    algorithm = Some(SigningAlgorithm::ES256);
                } else if *val == Value::from(iana::EllipticCurve::P_384 as u64) {
                    algorithm = Some(SigningAlgorithm::ES384);
                };
            },
            (COSE_EC2_KEY_PARAM_X_LABEL, Value::Bytes(x)) => {
                x_component = x.clone()
            },
            (COSE_EC2_KEY_PARAM_Y_LABEL, Value::Bytes(y)) => {
                y_component = y.clone()
            },
            _ => continue,
        };
    }

    if let Some(alg) = algorithm {
        match alg {
            SigningAlgorithm::ES256 => {
                if x_component.len() != 32 || y_component.len() != 32 {
                    return Err(TokenError::InvalidKey("Invalid length of P256 EC public key"));
                }
            },
            SigningAlgorithm::ES384 => {
                if x_component.len() != 48 || y_component.len() != 48 {
                    return Err(TokenError::InvalidKey("Invalid length of P384 EC public key"));
                }
            },
            SigningAlgorithm::ES512 => {
                return Err(TokenError::InvalidKey("ES512 is not implemented yet!"));
            }
        }
        // the public key is encoded in uncompressed form (required by ring crate)
        // this is indicated by prepending the X and Y components by the 0x04 byte
        Ok(([vec![0x04u8], x_component, y_component].concat(), alg))
    } else {
        Err(TokenError::InvalidKey("This is not P384 or P256 EC public key"))
    }
}

struct RustCryptoVerifier
{
    algorithm: SigningAlgorithm,
    key_public_raw: Vec<u8>,
}

impl RustCryptoVerifier
{
    fn new(algorithm: SigningAlgorithm, key_public: &[u8]) -> Self
    {
        Self {
            algorithm,
            key_public_raw: key_public.to_vec(),
        }
    }

    fn verify(&self, sig: &[u8], data: &[u8]) -> Result<(), TokenError>
    {
        let cbor_val = de::from_reader(self.key_public_raw.as_slice())?;
        let cose_key = CoseKey::from_cbor_value(cbor_val)?;
        let (realm_public_key, alg) = get_uncompressed_public_key_from_cosekey(&cose_key)?;

        if alg != self.algorithm {
            return Err(TokenError::VerificationFailed("The COSE signature algorithm doesn't match the embedded CoseKey"));
        }

        match self.algorithm {
            SigningAlgorithm::ES256 => {
                let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P256_SHA256_FIXED, &realm_public_key);
                key.verify(data, sig).map_err(|_| TokenError::VerificationFailed("ECDSA P256 signature verification failed"))?
            },
            SigningAlgorithm::ES384 => {
                let key = signature::UnparsedPublicKey::new(&signature::ECDSA_P384_SHA384_FIXED, &realm_public_key);
                key.verify(data, sig).map_err(|_| TokenError::VerificationFailed("ECDSA P384 signature verification failed"))?
            },
            SigningAlgorithm::ES512 => {
                // p521 from RustCrypto cannot do ecdsa
                return Err(TokenError::NotImplemented("P521 ecdsa"));
            },
        }
        Ok(())
    }
}

pub(crate) fn verify_coset_signature(cose: &CoseSign1, key_pub: &[u8], aad: &[u8]) -> Result<(), TokenError>
{
    if cose.protected.header.alg.is_none() {
        return Err(TokenError::InvalidAlgorithm(None));
    }
    let alg = cose.protected.header.alg.as_ref().unwrap().clone().try_into()?;
    let verifier = RustCryptoVerifier::new(alg, key_pub);
    cose.verify_signature(aad, |sig, data| verifier.verify(sig, data))
}

pub(crate) fn verify_digest(data: &[u8], hash: &[u8], alg: &str) -> Result<(), TokenError>
{
    let algorithm = alg.try_into()?;

    let digest = match algorithm {
        SigningAlgorithm::ES256 => {
            let mut context = Context::new(&SHA256);
            context.update(data);
            context.finish()
        },
        SigningAlgorithm::ES384 => {
            let mut context = Context::new(&SHA384);
            context.update(data);
            context.finish()
        },
        SigningAlgorithm::ES512 => {
            let mut context = Context::new(&SHA512);
            context.update(data);
            context.finish()
        },
    };

    if digest.as_ref().to_vec() != hash {
        return Err(TokenError::VerificationFailed("challenge verification failed"));
    }

    Ok(())
}
