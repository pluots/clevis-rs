use crate::key_exchange::create_encryption_key;
use crate::util::{b64_to_bytes, b64_to_str};
use crate::{Error, Result};
use base64ct::{Base64UrlUnpadded, Encoding};
use josekit::jwe::alg::ecdh_es::EcdhEsJweAlgorithm;
use josekit::jwe::{self, JweHeader};
use josekit::jwk::Jwk;
use josekit::jws::alg::ecdsa::EcdsaJwsAlgorithm;
use josekit::jws::alg::eddsa::EddsaJwsAlgorithm;
use josekit::jws::{self, JwsAlgorithm, JwsVerifier};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Value};
use sha2::Digest;
use sha2::Sha256;
use std::fmt;
use std::ops::Deref;
use std::{sync::OnceLock, time::Duration};

/// Representation of a tang advertisment response which is a JWS of available keys.
///
/// This is what is produced when you GET `tang_url/adv`.
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

        verifier
            .verify(&to_verify, &self.signature)
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
            .field(
                "signature",
                &Base64UrlUnpadded::encode_string(&self.signature),
            )
            .finish()
    }
}

#[derive(Debug, Serialize, Deserialize)]
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

    pub(crate) fn exchange_key(&self, url: Option<&str>) -> Result<()> {
        // let exc_keys = self.keys.iter().filter(|key| {
        //     key.key_operations().map_or(false, |key_ops| {
        //         key_ops.iter().any(|op| op.eq_ignore_ascii_case(op_name))
        //     })
        // });
        let alg = jwe::ECDH_ES;
        let enc_alg = jwe::enc::A256GCM;

        let mut derive_jwk = self.get_key_by_op("deriveKey")?.clone();

        create_encryption_key(&derive_jwk).unwrap();

        if derive_jwk.algorithm() == Some("ECMR") {
            derive_jwk.set_algorithm("ECDH-ES");
        }

        let enc = alg.encrypter_from_jwk(&derive_jwk)?;
        let mut header = JweHeader::new();
        header.set_algorithm(dbg!(alg.name()));
        header.set_content_encryption(dbg!(enc_alg.name()));
        let clevis_claim = json! {{
            "pin": "tang",
            "tang": {
                "adv": self,
                "url": url.unwrap_or_default(),
            }
        }};
        header.set_claim("clevis", Some(clevis_claim));
        dbg!(&header);

        // let newkey = enc
        //     .compute_content_encryption_key(&enc_alg, &JweHeader::new(), &mut header)?
        //     .unwrap();
        // dbg!(newkey.len(), &newkey);
        // dbg!(&header);
        // pop key_ops
        // pop alg
        // take the first derive key and get its thumbprint
        // take jwe, jwk, and input and produce JWE encrypted data in compact serialization
        // let jwk = self.get_key_by_op("deriveKey")?;
        // todo!()
        Ok(())
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

#[cfg(test)]
#[path = "jose_tests.rs"]
mod tests;
