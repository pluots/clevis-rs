use std::collections::BTreeMap;

use base64::prelude::BASE64_URL_SAFE_NO_PAD;
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer, Serialize};
use serde_json::{Map, Value as JsonValue};

pub fn b64_to_str<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: Deserializer<'de>,
{
    b64_to_bytes(deserializer).and_then(|bytes| {
        String::from_utf8(bytes).map_err(|err| DeError::custom(dbg!(err.to_string())))
    })
}

pub fn b64_to_bytes<'de, D>(deserializer: D) -> Result<Vec<u8>, D::Error>
where
    D: Deserializer<'de>,
{
    String::deserialize(deserializer).and_then(|string| {
        BASE64_URL_SAFE_NO_PAD
            .decode(&string)
            .map_err(|err| DeError::custom(dbg!(err.to_string())))
    })
}
