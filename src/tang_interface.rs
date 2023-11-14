use std::time::Duration;

use crate::jose::{Advertisment, Jwk, JwkSet, KeyMeta, ProvisionedData};
use crate::{EncryptionKey, Result};

// const DEFAULT_URL: &str = "http://tang.local";
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(120);

/// A tang server connection specification.
///
/// This does not hold an active connection, only connection parameters.
#[must_use]
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

    /// This client's connection URL
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Locate derive keys from the server and provision an encryption key with specified lengh.
    pub fn create_secure_key<const KEYBYTES: usize>(&self) -> Result<ProvisionedData<KEYBYTES>> {
        let (keys, signing_thp) = self.fetch_keys(None)?;
        keys.make_tang_enc_key(&self.url, signing_thp)
    }

    /// A version of [`Self::create_secure_key`] that accepts a thumbprint.
    pub fn create_secure_key_trusted_key<const KEYBYTES: usize>(
        &self,
        thumbprint: &str,
    ) -> Result<ProvisionedData<KEYBYTES>> {
        let (keys, signing_thp) = self.fetch_keys(Some(thumbprint))?;
        keys.make_tang_enc_key(&self.url, signing_thp)
    }

    /// Recover a secure key using metadata that was stored.
    pub fn recover_secure_key<const KEYBYTES: usize>(
        &self,
        meta: &KeyMeta,
    ) -> Result<EncryptionKey<KEYBYTES>> {
        meta.recover_key(|kid, x_pub_jwk| self.fetch_recovery_key(kid, x_pub_jwk))
    }

    /// Advertisment step that gets all public keys. Verifies the signature
    fn fetch_keys(&self, thumbprint: Option<&str>) -> Result<(JwkSet, Box<str>)> {
        let url = format!("{}/adv/{}", &self.url, thumbprint.unwrap_or(""));
        log::debug!("fetching advertisment from '{url}'");
        let adv: Advertisment = ureq::get(&url).timeout(self.timeout).call()?.into_json()?;
        adv.validate_into_keys(thumbprint)
    }

    fn fetch_recovery_key(&self, kid: &str, x_pub_jwk: &Jwk) -> Result<Jwk> {
        let url = format!("{}/rec/{kid}", &self.url);
        log::debug!("requesting recovery key from '{url}'");
        ureq::post(&url)
            .timeout(self.timeout)
            .set("Content-Type", "application/jwk+json")
            .send_json(x_pub_jwk)?
            .into_json()
            .map_err(Into::into)
    }
}
