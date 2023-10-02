use std::fmt;
use std::ops::Deref;
use std::{sync::OnceLock, time::Duration};

use crate::util::{b64_to_bytes, b64_to_str};
use crate::{Error, Result};
use base64::{prelude::BASE64_URL_SAFE_NO_PAD, Engine};
use josekit::jwk::Jwk;
use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm;
use josekit::jws::alg::eddsa::EddsaJwsAlgorithm;
use josekit::jws::{self, JwsAlgorithm, JwsVerifier};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};

/// Representation of a tang advertisment response which is a JWS of available keys.
#[derive(Deserialize)]
pub struct Advertisment {
    #[serde(deserialize_with = "b64_to_str")]
    protected: String,
    #[serde(deserialize_with = "b64_to_str")]
    payload: String,
    #[serde(deserialize_with = "b64_to_bytes")]
    signature: Vec<u8>,
}

impl Advertisment {
    /// Validate the entire advertisment. This checks the `verify` key correctly signs the data.
    fn validate(&self, jwks: &JwkSet) -> Result<()> {
        let verify_jwk = jwks.get_key_by_op("verify")?;
        let verifier = get_verifier(verify_jwk)?;

        // B64 is 4/3 data length, plus a `.`
        let verify_len = ((self.payload.len() + self.protected.len()) * 4 / 3) + 1;
        let mut to_verify = String::with_capacity(verify_len);

        // The format `b64(HEADER).b64(PAYLOAD)` is used for validation
        BASE64_URL_SAFE_NO_PAD.encode_string(&self.protected, &mut to_verify);
        to_verify.push('.');
        BASE64_URL_SAFE_NO_PAD.encode_string(&self.payload, &mut to_verify);

        verifier
            .verify(to_verify.as_bytes(), &self.signature)
            .map_err(Into::into)
    }

    /// Validate the advertisment and extract its keys
    pub fn into_keys(self) -> Result<JwkSet> {
        let jwks: JwkSet = serde_json::from_str(&self.payload)?;
        self.validate(&jwks)?;
        Ok(jwks)
    }
}

impl fmt::Debug for Advertisment {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fn json_field(s: &str) -> Box<dyn fmt::Debug + '_> {
            match serde_json::from_str::<Value>(s) {
                Ok(v) => Box::new(v),
                Err(_) => Box::new(s),
            }
        }

        f.debug_struct("Advertisment")
            .field("payload", &json_field(&self.payload))
            .field("protected", &json_field(&self.protected))
            .field("signature", &BASE64_URL_SAFE_NO_PAD.encode(&self.signature))
            .finish()
    }
}

#[derive(Debug, Deserialize)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    /// Get a single key that contains an operation
    fn get_key_by_op(&self, op_name: &str) -> Result<&Jwk> {
        self.keys
            .iter()
            .find(|key| {
                key.key_operations().map_or(false, |key_ops| {
                    key_ops.iter().any(|op| op.eq_ignore_ascii_case(op_name))
                })
            })
            .ok_or(Error::MissingKeyOp(op_name.into()))
    }
}

/// The key types we support
#[derive(Clone, Copy, Debug, PartialEq)]
enum KeyType {
    Ec,
    Rsa,
}

/// Extract the key type of a jwk
fn key_type(jwk: &Jwk) -> Result<KeyType> {
    match jwk.key_type() {
        "EC" => Ok(KeyType::Ec),
        "RSA" => Ok(KeyType::Rsa),
        _ => Err(Error::KeyType(jwk.key_type().into())),
    }
}

/// Get a verifier from a JWK
fn get_verifier(jwk: &Jwk) -> Result<Box<dyn JwsVerifier>> {
    let kty = key_type(jwk)?;
    if kty == KeyType::Ec {
        jws::ES512
            .verifier_from_jwk(jwk)
            .or_else(|_| jws::ES256.verifier_from_jwk(jwk))
            .or_else(|_| jws::ES256K.verifier_from_jwk(jwk))
            .or_else(|_| jws::ES384.verifier_from_jwk(jwk))
            .map(|v| Box::new(v) as Box<dyn JwsVerifier>)
    } else if kty == KeyType::Rsa {
        jws::RS256
            .verifier_from_jwk(jwk)
            .or_else(|_| jws::RS384.verifier_from_jwk(jwk))
            .or_else(|_| jws::RS512.verifier_from_jwk(jwk))
            .map(|v| Box::new(v) as Box<dyn JwsVerifier>)
    } else {
        unreachable!()
    }
    .map_err(Into::into)
}

fn make_thumbprint(jwk: &Jwk) {}

#[cfg(test)]
#[path = "jose_tests.rs"]
mod tests;
