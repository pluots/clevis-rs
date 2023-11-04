use std::fmt;
use std::ops::Deref;
use std::{sync::OnceLock, time::Duration};

use crate::jose::{Advertisment, JwkSet};
use crate::util::{b64_to_bytes, b64_to_str};
use crate::{Error, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use josekit::jwk::Jwk;
use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm;
use josekit::jws::alg::eddsa::EddsaJwsAlgorithm;
use josekit::jws::{self, JwsAlgorithm, JwsVerifier};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};

const DEFAULT_URL: &str = "http://tang.local";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// A tang server connection specification
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
    pub fn fetch_keys(&self) -> Result<JwkSet> {
        let url = format!("{}/adv", &self.url);
        log::debug!("fetching advertisment from '{url}'");
        let adv: Advertisment = ureq::get(&url).timeout(self.timeout).call()?.into_json()?;
        adv.into_keys()
    }

    // /// Fetch a public key with a key ID
    // pub fn fetch_public_key(url: &str, key_id: String) {}

    // /// Perform recovery
    // pub fn recover_key(url: &str, key_id: String) {}
}
