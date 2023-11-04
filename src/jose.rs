use crate::key_exchange::{create_enc_key, recover_enc_key};
use crate::util::{b64_to_bytes, b64_to_str};
use crate::{EncryptionKey, Error, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use josekit::jwk::Jwk;
use josekit::jws::{self, JwsVerifier};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use sha2::Sha256;
use std::fmt;

/// Representation of a tang advertisment response which is a JWS of available keys.
///
/// This is what is produced when you GET `tang_url/adv`.
#[derive(Clone, Deserialize)]
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
    ///
    /// If a thumbprint is specified, only use a verify key with that thumbprint. Otherwise,
    /// use any verify key.
    fn validate(&self, jwks: &JwkSet, thumbprint: Option<&str>) -> Result<Box<str>> {
        let (verify_jwk, thp) = if let Some(thp) = thumbprint {
            (jwks.get_key_by_id(thp)?, Box::from(thp))
        } else {
            let verify_jwk = jwks.get_key_by_op("verify")?;
            (
                verify_jwk,
                make_thumbprint(verify_jwk, ThpHashAlg::Sha256)?.into(),
            )
        };
        // jwks.get_key_by_id()
        let verifier = get_verifier(verify_jwk)?;

        // B64 is 4/3 data length, plus a `.`
        let payload_b64_len = Base64UrlUnpadded::encoded_len(self.payload.as_bytes());
        let protected_b64_len = Base64UrlUnpadded::encoded_len(self.protected.as_bytes());
        let mut to_verify = vec![b'.'; payload_b64_len + 1 + protected_b64_len];

        // The format `b64(HEADER).b64(PAYLOAD)` is used for validation
        Base64UrlUnpadded::encode(
            self.protected.as_bytes(),
            &mut to_verify[..protected_b64_len],
        )
        .unwrap();
        Base64UrlUnpadded::encode(
            self.payload.as_bytes(),
            &mut to_verify[(protected_b64_len + 1)..],
        )
        .unwrap();

        verifier.verify(&to_verify, &self.signature)?;
        Ok(thp)
    }

    /// Validate the advertisment and extract its keys
    pub fn validate_into_keys(self, thumbprint: Option<&str>) -> Result<(JwkSet, Box<str>)> {
        let jwks: JwkSet = serde_json::from_str(&self.payload)?;
        let thp = self.validate(&jwks, thumbprint)?;
        Ok((jwks, thp))
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
            .field(
                "signature",
                &Base64UrlUnpadded::encode_string(&self.signature),
            )
            .finish()
    }
}

/// The response from a Tang server, containing a list of possible keys to use for derivation
#[derive(Clone, Debug, Serialize, Deserialize)]
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

    pub(crate) fn get_key_by_id(&self, kid: &str) -> Result<&Jwk> {
        for key in &self.keys {
            let thp_sha256 = make_thumbprint(key, ThpHashAlg::Sha256)?;
            if thp_sha256 == kid {
                return Ok(key);
            }
            let thp_sha1 = make_thumbprint(key, ThpHashAlg::Sha1)?;
            if thp_sha1 == kid {
                return Ok(key);
            }
        }
        Err(Error::MissingPublicKey)
    }

    pub(crate) fn make_tang_enc_key<const N: usize>(
        &self,
        url: &str,
        signing_thumbprint: Box<str>,
    ) -> Result<GeneratedKey<N>> {
        let derive_jwk = self.get_key_by_op("deriveKey")?.clone();

        let (epk, encryption_key) = create_enc_key(&derive_jwk)?;
        let clevis = ClevisParams {
            pin: "tang".into(),
            tang: TangParams {
                adv: self.clone(),
                url: url.into(),
            },
        };
        let meta = KeyMeta {
            alg: "ECDH-ES".into(),
            clevis,
            enc: None,
            epk,
            kid: make_thumbprint(&derive_jwk, ThpHashAlg::Sha256)?.into(),
        };

        Ok(GeneratedKey {
            encryption_key,
            signing_thumbprint,
            meta,
        })
    }
}

/// The key types we support
#[derive(Clone, Copy, Debug, PartialEq)]
enum KeyType {
    Ec,
    Rsa,
}

/// The key types we support
#[derive(Clone, Copy, Debug, PartialEq)]
enum ThpHashAlg {
    Sha1,
    Sha256,
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

/// Jwk thumbprint as described in RFC7638 section 3.1.
fn make_thumbprint(jwk: &Jwk, alg: ThpHashAlg) -> Result<String> {
    let kty = key_type(jwk)?;
    let to_enc = if kty == KeyType::Ec {
        let crv = get_jwk_param(jwk, "crv")?;
        let crv = crv
            .as_str()
            .ok_or_else(|| Error::JsonKeyType(crv.to_string().into()))?;

        // Only specific curves require `y`
        let y_param = if ["P-256", "P-384", "P-521"].contains(&crv) {
            Some(get_jwk_param(jwk, "y")?)
        } else {
            None
        };

        json! {{
            "crv": get_jwk_param(jwk, "crv")?,
            "kty": jwk.key_type(),
            "x": get_jwk_param(jwk, "x")?,
            "y": y_param
        }}
    } else if kty == KeyType::Rsa {
        json! {{
            "e": get_jwk_param(jwk, "e")?,
            "kty": jwk.key_type(),
            "n": get_jwk_param(jwk, "n")?,
        }}
    } else {
        // symmetric keys need "k" and "kty"
        unreachable!()
    };

    let to_hash = to_enc.to_string();

    match alg {
        ThpHashAlg::Sha1 => {
            let mut hasher = sha1::Sha1::new();
            hasher.update(to_hash.as_bytes());
            Ok(Base64UrlUnpadded::encode_string(&hasher.finalize()))
        }
        ThpHashAlg::Sha256 => {
            let mut hasher = Sha256::new();
            hasher.update(to_hash.as_bytes());
            Ok(Base64UrlUnpadded::encode_string(&hasher.finalize()))
        }
    }
}

/// Get a parameter from the JWK
fn get_jwk_param<'a>(jwk: &'a Jwk, key: &str) -> Result<&'a Value> {
    jwk.parameter(key)
        .ok_or_else(|| Error::JsonMissingKey(key.into()))
}

pub struct GeneratedKey<const KEYBYTES: usize> {
    /// Use this key to encrypt data
    pub encryption_key: EncryptionKey<KEYBYTES>,
    /// The thumbprint used for signing. Future keys can be requested using this thumbprint.
    pub signing_thumbprint: Box<str>,

    /// Metadata required to regenerate an encryption key.
    ///
    /// Both this metadata and a connection to the Tang server are needed to regenerate the
    /// key for use with encryption. This data can be stored in JSON form.
    ///
    /// Note that while this data does not contain the encryption key, it should still not
    /// be exposed. Any device that can read this metadata could potentially decrypt
    /// the ciphertext if it has access to the Tang server.
    pub meta: KeyMeta,
}

/// Store this to retrieve the key
#[derive(Debug, Deserialize, Serialize)]
pub struct KeyMeta {
    /// Key exchange algorithm. Typically Elliptic Curve Diffie-Hellman Ephemeral Static
    /// (ECDH-ES) with the concat KDF.
    alg: Box<str>,
    clevis: ClevisParams,
    /// Encryption algorithm
    enc: Option<Box<str>>,
    /// Our public key that is used to create the encryption key
    epk: Jwk,
    /// Key ID of the derive key, i.e. key used to generate the secret (not signing key)
    kid: Box<str>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ClevisParams {
    /// This is always `tang` I think...
    pin: Box<str>,
    tang: TangParams,
}

#[derive(Debug, Deserialize, Serialize)]
struct TangParams {
    /// Keys from the initial tang response
    adv: JwkSet,
    /// Tang URL
    url: Box<str>,
}

impl KeyMeta {
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("serialization failure")
    }

    pub fn from_json(val: &str) -> Result<Self> {
        serde_json::from_str(val).map_err(Into::into)
    }

    pub(crate) fn recover_key<const N: usize>(
        &self,
        server_key_exchange: impl FnOnce(&str, &Jwk) -> Result<Jwk>,
    ) -> Result<EncryptionKey<N>> {
        let c_pub_jwk = &self.epk;
        let kid = &self.kid;
        let s_pub_jwk = self.clevis.tang.adv.get_key_by_id(kid)?;
        recover_enc_key(c_pub_jwk, s_pub_jwk, |x_pub_jwk| {
            server_key_exchange(kid, x_pub_jwk)
        })
    }
}

#[cfg(test)]
#[path = "jose_tests.rs"]
mod tests;
