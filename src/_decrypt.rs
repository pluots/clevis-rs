use crate::error::{Error, Result};
use crate::util::{b64_to_bytes, b64_to_str};
use base64::{prelude::BASE64_STANDARD_NO_PAD, Engine};

pub struct DecryptConfig;

impl DecryptConfig {
    pub fn from_b64_jwe(encoded: &[u8]) -> Result<Self> {
        // let header_bytes = BASE64_STANDARD_NO_PAD.decode(encoded)?;
        // let header = std::str::from_utf8(&header_bytes)?;
        let header = std::str::from_utf8(&encoded)?;
        // dbg!(&header);
        let foo = josekit::jwe::deserialize_compact_with_selector(
            header,
            // let foo = josekit::jwe::deserialize_json_with_selector(header,
            |x| {
                dbg!(x);
                todo!()
            },
        );
        dbg!(foo);
        todo!()
    }
}
