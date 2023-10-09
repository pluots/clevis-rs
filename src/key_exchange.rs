use josekit::jwe::ECDH_ES;
use josekit::{
    jwe::alg::ecdh_es::EcdhEsJweAlgorithm,
    jwk::{alg::ec::EcCurve, Jwk},
};
use serde_json::Value;

use crate::{Error, Result};

/// Perform key generation in accordance with tang protocol
///
/// Rough description, capitals are public:
///
/// - Take in a server public JWK `S` (internally the server has `S = [s]G`)
/// - Create a client keypair `c` and `C`
/// - Perform half of ECDH with client private key and server public key to get `K = [c]S`. `K` is the
///   key used to encrypt data, and also satisfies `K = [cs]G`
pub fn create_encryption_key(s_jwk: &Jwk) -> Result<()> {
    match s_jwk.algorithm() {
        Some("ECMR") => (),
        Some("ECDH-ES") => (),
        alg => {
            return Err(Error::Algorithm(
                alg.unwrap_or("none").into(),
                "key exchange algorithm",
            ))
        }
    }

    let crv = match s_jwk.parameter("crv") {
        Some(Value::String(c)) if c == "P-521" => EcCurve::P521,
        Some(Value::String(c)) if c == "P-384" => EcCurve::P384,
        Some(Value::String(c)) if c == "P-256" => EcCurve::P256,
        arg => {
            return Err(Error::Algorithm(
                serde_json::to_string(&arg)
                    .unwrap_or("none".to_owned())
                    .into(),
                "key exchange crv",
            ))
        }
    };

    let c_keypair = EcdhEsJweAlgorithm::EcdhEs.generate_ec_key_pair(crv)?;

    dbg!(&c_keypair);
    dbg!(hex::encode(c_keypair.to_raw_private_key()));
    dbg!(String::from_utf8_lossy(&c_keypair.to_raw_private_key()));

    let ecdh = ECDH_ES;

    // panic!();

    Ok(())
}
