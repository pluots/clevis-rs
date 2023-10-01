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

const DEFAULT_URL: &str = "http://tang.local";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

#[derive(Clone, Debug)]
pub struct TangClient {
    url: String,
    timeout: Duration,
}

impl TangClient {
    /// Create a new client. If timeout is not specified, it will default to 120s.
    pub fn new(url: &str, timeout: Option<Duration>) -> Self {
        let url = if url.starts_with("http") {
            url.to_owned()
        } else {
            format!("http://{url}")
        };
        Self {
            url,
            timeout: timeout.unwrap_or(DEFAULT_TIMEOUT),
        }
    }

    /// Advertisment step that gets all public keys. Verifies the signature
    #[must_use]
    pub fn fetch_public_keys(&self) -> Result<()> {
        let url = format!("{}/adv", &self.url);
        log::debug!("fetching advertisment from '{url}'");
        let keys: Advertisment = ureq::get(&url).timeout(self.timeout).call()?.into_json()?;
        dbg!(&keys);
        keys.validate()?;
        Ok(())
    }

    // /// Fetch a public key with a key ID
    // pub fn fetch_public_key(url: &str, key_id: String) {}

    // /// Perform recovery
    // pub fn recover_key(url: &str, key_id: String) {}
}

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
    pub fn validate(&self) -> Result<()> {
        let jwks: JwkSet = serde_json::from_str(&self.payload)?;
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

    fn signature(&self) {}
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

/// Get a verifier from a JWK
fn get_verifier(jwk: &Jwk) -> Result<Box<dyn JwsVerifier>> {
    // Start with most likely algorithms
    jws::ES512
        .verifier_from_jwk(jwk)
        .or_else(|_| jws::ES256.verifier_from_jwk(jwk))
        .or_else(|_| jws::ES256K.verifier_from_jwk(jwk))
        .or_else(|_| jws::ES384.verifier_from_jwk(jwk))
        .map(|v| Box::new(v) as Box<dyn JwsVerifier>)
        .or_else(|_| {
            // EdDSA
            jws::EdDSA
                .verifier_from_jwk(jwk)
                .map(|v| Box::new(v) as Box<dyn JwsVerifier>)
        })
        .or_else(|_| {
            // HMAC
            jws::HS256
                .verifier_from_jwk(jwk)
                .or_else(|_| jws::HS384.verifier_from_jwk(jwk))
                .or_else(|_| jws::HS512.verifier_from_jwk(jwk))
                .map(|v| Box::new(v) as Box<dyn JwsVerifier>)
        })
        .or_else(|_| {
            // RSA
            jws::RS256
                .verifier_from_jwk(jwk)
                .or_else(|_| jws::RS384.verifier_from_jwk(jwk))
                .or_else(|_| jws::RS512.verifier_from_jwk(jwk))
                .map(|v| Box::new(v) as Box<dyn JwsVerifier>)
        })
        .or_else(|_| {
            // RSA PSS
            jws::PS256
                .verifier_from_jwk(jwk)
                .or_else(|_| jws::PS384.verifier_from_jwk(jwk))
                .or_else(|_| jws::PS512.verifier_from_jwk(jwk))
                .map(|v| Box::new(v) as Box<dyn JwsVerifier>)
        })
        .map_err(Into::into)
}
