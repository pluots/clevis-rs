use base64ct::{Base64UrlUnpadded, Encoding};
use serde::de::Error as DeError;
use serde::{Deserialize, Deserializer};

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
        Base64UrlUnpadded::decode_vec(&string).map_err(|err| DeError::custom(err.to_string()))
    })
}
