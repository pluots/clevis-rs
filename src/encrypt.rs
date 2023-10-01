use crate::error::{Error, Result};
use crate::util::{b64_to_bytes, b64_to_str};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use josekit::{
    jwe::{
        alg::{aesgcmkw::AesgcmkwJweAlgorithm, ecdh_es::EcdhEsJweAlgorithm},
        JweHeader,
    },
    jwk::Jwk,
};
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{json, Map, Value as JsonValue};
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::{
    collections::BTreeMap,
    io::{self, Write},
};

/// Data needed to perform encryption
pub struct EncryptConfig {
    pub thp: String,
    pub source: EncryptSource,
}

pub enum EncryptSource {
    Raw,
    File(String),
    Server(String),
}

impl EncryptConfig {
    pub fn encrypt(&self, payload: &[u8]) -> Result<()> {
        let thp = &self.thp;
        let mut url = "";

        let jws: TangJws = match &self.source {
            EncryptSource::Raw => todo!(),
            EncryptSource::File(_) => todo!(),
            EncryptSource::Server(tmp_url) => {
                url = &tmp_url;
                ureq::get(&(format!("http://{url}/adv/{thp}")))
                    .call()?
                    .into_json()?
            }
        };

        dbg!(&jws);

        let jws_payload: TangJwsPayload = serde_json::from_str(&jws.payload).unwrap();
        // let k = josekit::jwk::Jwk::from_bytes(&keys.keys[0]);
        dbg!(&jws_payload);
        let verify_jwk = jws_payload.find_key_by_op("verify")?;
        // TODO: check trust
        let derive_jwk = jws_payload.find_key_by_op("deriveKey")?;

        dbg!(&verify_jwk);
        dbg!(&derive_jwk);

        let thumbprint = dbg!(calculate_jwk_thp(derive_jwk.clone()))?;

        let jwe = json!({
            // "protected": {
            "alg": "ECDH-ES",
            "enc": "A256GCM",
            "clevis": {
                "pin": "tang",
                "tang": {
                    "url": url,
                    "adv": jws_payload
                }
            },
            "kid": thumbprint
            // }
        });

        let header =
            JweHeader::from_bytes(&serde_json::to_string(&jwe).unwrap().as_bytes()).unwrap();

        let mut map: Map<String, JsonValue> = derive_jwk.clone().into();
        dbg!(map.get("alg"));
        map.insert("alg".to_owned(), JsonValue::String("ECDH-ES".into()));
        let dk = Jwk::from_map(map).unwrap();

        let enc = EcdhEsJweAlgorithm::EcdhEs.encrypter_from_jwk(&dk).unwrap();
        // let enc = AesgcmkwJweAlgorithm::A256gcmkw.encrypter_from_jwk(derive_jwk).unwrap();
        let out = josekit::jwe::serialize_compact(payload, &header, &enc).unwrap();
        // io::stdout().lock().write_all(&out);
        write!(io::stdout().lock(), "{out}").unwrap();

        Ok(())
    }
}

/// The `clevis` tool removes unneeded keys, sorts the map, hashes, then encodes
/// to get a thumbprint
fn calculate_jwk_thp(jwk: Jwk) -> Result<String> {
    let mut map: Map<String, JsonValue> = jwk.into();
    map.remove("key_ops").expect("missing 'key_ops' key");
    map.remove("alg").expect("missing 'alg' key");
    let sorted_map: BTreeMap<String, JsonValue> = map.into_iter().collect();
    let mut hasher = Sha256::new();
    hasher.update(serde_json::to_string(&sorted_map).unwrap().as_bytes());
    Ok(BASE64_STANDARD_NO_PAD.encode(&hasher.finalize()))
}

/// Representation of a tang response, all fields are base64
#[derive(Debug, Deserialize)]
struct TangJws {
    #[serde(deserialize_with = "b64_to_str")]
    payload: String,
    #[serde(deserialize_with = "b64_to_str")]
    protected: String,
    // #[serde(deserialize_with = "b64_to_bytes")]
    signature: String,
    // signature: Vec<u8>,
}

#[derive(Debug, Deserialize, Serialize)]
struct TangJwsPayload {
    keys: Vec<Jwk>,
}

impl TangJwsPayload {
    /// Case insensitive
    fn find_key_by_op(&self, op_name: &'static str) -> Result<&Jwk> {
        Ok(self
            .keys
            .iter()
            .find(|k| {
                k.key_operations().map_or(false, |v| {
                    v.iter().any(|ko| ko.eq_ignore_ascii_case(op_name))
                })
            })
            .ok_or(Error::MissingKeyOp(op_name.into()))?)
    }
}
