//! Tests to verify we match with `jose jwk exc`
//!
//! Quoting from <https://www.mankier.com/1/jose-jwk-exc>:
//!
//!
//! > The ECMR algorithm has three modes of operation. Where the local key has a
//! > private key (the "d" property), it performs exactly like ECDH. If the local key
//! > does not have a private key and the remote key does have a private key, elliptic
//! > curve addition is performed on the two values. Otherwise, if neither the local
//! > key nor the remote key have a private key, the remote key is subtracted from the
//! > local key using elliptic curve subtraction. When using ECMR, be sure to validate
//! > the content of your inputs to avoid triggering the incorrect operation!
//!
//! We provide each mode with a separate function and test against the jose output

use crate::jose::Jwk;

use super::*;
use serde_json::Value;

// PUB and PRIV are random keys, not related
// It seems like jose doesn't do what we want unless we slap an `alg: ECMR` on everything

const PUB1: &str = r#"{
    "alg": "ECMR",
    "kty":"EC",
    "crv":"P-521",
    "x":"ARMEJ-j3d1XTYnWVIcTBLx-CsLW2L1j31j91AFw7Q-XIo1EvNQnSp9jZMp4BG9B2UOpeA9CpuByzCWkKR8j4Xlu4",
    "y":"Abhfvfn8PCMeaD-zXRYGc2PNLPvx9lfXbO4ujG-oA2qVST0f_Gm1n1Fo64yhOA-POepFuzO3VQBSu2HBh2W_0AZY"
}"#;

const PUB2: &str = r#"{
    "alg": "ECMR",
    "crv": "P-521",
    "d": "AfzVlb8M1oqMD81H9CM9WA29rAp6AwlHLYcHWnqhB-9qX3JfLAza2WiNS8WXpThl80QTiEyyFk-WWLoyAJ-dEWGU",
    "kty": "EC",
    "x": "AKUjAYzkwyvYMf_kaPB7sCpMmSXtAB0fEtpoomxJItcJh_uUbVAoCa2CEHmKvNYnDbOBlpuaZYHkfmrn00LaC-ys",
    "y": "ASH_5_uGnl_nrtbaRYclJbK_6bxhz2oI7ZcAq9oIRGKF1YBX0X7cm50uXcqIn0E2ixNd8zvxG996_27ydO9KKTh8"
}"#;

const PRIV: &str = r#"{
    "alg": "ECMR",
    "kty":"EC",
    "crv":"P-521",
    "d":"AQYMXLDMMZ3zUX2fDquuF6DdKCv006AWC8JXWN380xPwnXkPucVnAYKcYPdHlAxVaN702rMY7Zy0ZdhzdCVE4MOy",
    "x":"APEGU4eUd47tN9NMZUUZw5gdUI8ye7rV0DD46YIm2ilq3kHCsQAmqQzeBoW0CwtRia0lJTab3qs75EcNGMmgHCOZ",
    "y":"AS0bF_r4j82E2hLXJCPtaHHPxX8JGTj97gyzIl29kiLrJbdWmYtSBM9OLLUuyZ5quexlKE2R5oKmCZgVMeq1pSjK"
}"#;

// Output from `jose jwk exc -l- -r- <<< "$priv$pub1"`
const DIFFIE_OUT: &str = r#"{
  "crv": "P-521",
  "kty": "EC",
  "x": "AAZrHpTgNhFuxODvOSF8xgu1rB5jxlMQFHMEuen4LnIfJaHfKWOP0bfLWfoFV-t_myDTmXLJPPvIr__JJUGJOEyg",
  "y": "AHCpxNlTWWRJ4eEK-wOgO6CM2HdJyMUj8ccKBWKDGZ0orxv6NI-XzXhFiYOe07blUAr2rkmuZI-EgoshRopkXgKO"
}"#;

// Output from `jose jwk exc -l- -r- <<< "$pub1$priv"`
const ADDITION: &str = r#"{
  "crv": "P-521",
  "kty": "EC",
  "x": "AU9biY0WqoT-mi1-kJ0fUE5dpmnTTGNrNICn3j83t2GIjvd-Novwxrm8ktYj06fIcovfGJfhmVVu5VJWlVFVd7ax",
  "y": "Aa44e2GyQKArXq39QPvTu4D_u8kNdSIXOZuWduRzwIXRwfkCGV177sAC4bQcKQdtb1kU20U589qeGG0dUwNCMpJD"
}"#;

// // Output from `jose jwk exc -l- -r- <<< "$pub1$pub2"`
// // This doesn't appear to actually be subtraction since this doesn't add up...
// const SUBTRACTION: &str = r#"{
//   "crv": "P-521",
//   "kty": "EC",
//   "x": "AaG_X2ASudUbzUj2P3WkRc5EDmXrQhOykyqUMZzwe9hLecXqJ-lh5gETEHS1O0X0OIPR1CgBEMA4E_rnVJlQivx_",
//   "y": "AL7_5J63H2BnK7g_jlyHs14E_HLTGTKLxgiGTCFBH1x66xPRiM9sgepOp1FKX2izNH0ZyrkMUSon2npDwkbAs7tG"
// }"#;

fn pub1_jwk() -> PublicKey<p521::NistP521> {
    EcJwk::to_pub(&serde_json::from_str(PUB1).unwrap()).unwrap()
}

fn pub2_jwk() -> PublicKey<p521::NistP521> {
    EcJwk::to_pub(&serde_json::from_str(PUB2).unwrap()).unwrap()
}

fn priv_jwk() -> SecretKey<p521::NistP521> {
    EcJwk::to_priv(&serde_json::from_str(PRIV).unwrap()).unwrap()
}

fn assert_json_eq(left: &str, right: &str) {
    let left: Value = serde_json::from_str(left).unwrap();
    let right: Value = serde_json::from_str(right).unwrap();
    assert_eq!(left, right);
}

#[test]
fn test_diffie_hellman() {
    let out = diffie_hellman(&priv_jwk(), &pub1_jwk()).unwrap();
    assert_json_eq(&out.to_jwk_string(), DIFFIE_OUT);
}

#[test]
fn test_ecmr_add() {
    let out = ecmr_add(&pub1_jwk(), &priv_jwk().public_key()).unwrap();
    assert_json_eq(&out.to_jwk_string(), ADDITION);
}

// #[test]
// fn test_ecmr_sub() {
//     let out = ecmr_sub(&pub1_jwk(), &pub2_jwk()).unwrap();
//     assert_json_eq(&out.to_jwk_string(), SUBTRACTION);
// }

#[test]
fn test_ecmr_add_sub() {
    let pub1 = pub1_jwk();
    let pub2 = pub2_jwk();

    let tmp = ecmr_add(&pub1, &pub2).unwrap();
    let new_pub1 = ecmr_sub(&tmp, &pub2).unwrap();
    assert_eq!(pub1, new_pub1);
}

/// Test the "Understanding the Algorithm" section of Tang
///
/// ```text
/// s = g * S # sJWK (Server advertisement)
/// c = g * C # cJWK (Client provisioning)
/// K = s * C # dJWK (Client provisioning)
///
/// K = c * S # dJWK (Server recovery)
/// ```seems
#[test]
fn test_roundtrip_simple() {
    // s = g * S
    let s_priv = SecretKey::<p521::NistP521>::random(&mut OsRng);
    let s_pub = s_priv.public_key();
    // c = g * C
    let c_priv = SecretKey::<p521::NistP521>::random(&mut OsRng);
    let c_pub = c_priv.public_key();

    // K = s * C, key as provisioned on the client
    let k1 = diffie_hellman(&s_priv, &c_pub).unwrap();

    // K = c * S, key as recovered via the server
    let k2 = diffie_hellman(&c_priv, &s_pub).unwrap();

    assert_eq!(k1, k2);
}

/// Verify the math that should work
#[test]
fn test_roundtrip_full() {
    // PROVISIONING

    // s = g * S
    let s_priv = SecretKey::<p521::NistP521>::random(&mut OsRng);
    let s_pub = s_priv.public_key();

    // c = g * C
    let c_priv = SecretKey::<p521::NistP521>::random(&mut OsRng);
    let c_pub = c_priv.public_key();

    // K = s * C, key as provisioned on the client
    let k1 = diffie_hellman(&s_priv, &c_pub).unwrap();

    // client stores only the public key
    drop(c_priv);

    // RECOVERY

    // e = g * E
    let e_priv = SecretKey::<p521::NistP521>::random(&mut OsRng);
    let e_pub = e_priv.public_key();

    // x = c + e, this is sent to the server
    let x_pub = ecmr_add(&c_pub, &e_pub).unwrap();

    // y = x * S, server operation, responds with y
    let y_pub = diffie_hellman(&s_priv, &x_pub).unwrap();

    // z = s * E
    let z_pub = diffie_hellman(&e_priv, &s_pub).unwrap();

    // K = y - z
    let k2 = ecmr_sub(&y_pub, &z_pub).unwrap();

    assert_eq!(k1, k2);
}

/// Same as above but using our JWK wrapper functions
#[test]
fn test_roundtrip_jwk() {
    let s_priv = SecretKey::<p521::NistP521>::random(&mut OsRng);

    // Pretend to be the server
    let server_key_exchange = |x_pub_jwk: &Jwk| -> Result<Jwk> {
        let x_pub = x_pub_jwk.as_ec().unwrap().to_pub().unwrap();
        let y_pub = diffie_hellman(&s_priv, &x_pub).unwrap();
        Ok(EcJwk::from_pub(&y_pub).into())
    };

    let s_pub = s_priv.public_key();

    let s_pub_jwk = EcJwk::from_pub(&s_pub);
    dbg!(&s_pub_jwk);

    let (c_pub_jwk, k1) = create_enc_key::<10>(&s_pub_jwk).unwrap();

    let k2 = recover_enc_key(&c_pub_jwk, &s_pub_jwk, server_key_exchange).unwrap();

    assert_eq!(k1, k2);
}

// /// Check that our encryption with a key matches `jose`
// ///
// /// Sample:
// ///
// /// ```sh
// /// jwe_base='{"protected":{"alg":"ECDH-ES","enc":"A256GCM"}}'
// /// jose jwe enc -i- -k- -I- -c <<< "$jwe_base$jwk\nhello"
// /// ```
// ///
// /// This generates a different output each time. For the sake of this test we will use the
// /// JWE in the test body with this jwk:
// ///
// /// ```text
// /// {
// ///     "crv": "P-521",
// ///     "kty": "EC",
// ///     "x": "AbkDg4XtZlIWV-gkfQd6YYx7T7sMBds_xk-YANmBucBCPL4CMmiJP0VS6A0GvbimkZANrjmnC2PGwYvhVxY4StWd",
// ///     "y": "AeIkvpdwKd-8l5sl01u-rP9ebNRvpgK3bSKCvI2BhhwLO7KD-EI8IFBC3_x8_hkpurNXhD5t2t8dInT37O3Y4Vr2"
// /// }
// /// ```
// #[test]
// fn test_encrypt() {
//     use aes_gcm::{
//         aead::{Aead, AeadCore, KeyInit, OsRng},
//         Aes256Gcm, Key, Nonce,
//     };

//     use base64ct::{Base64UrlUnpadded, Encoding};
//     use serde_json::Value;

//     const JWE: &str = "\
//     eyJhbGciOiJFQ0RILUVTIiwiZW5jIjoiQTI1NkdDTSIsImVwayI6eyJjcnYiOiJQLTUyMSIsImt0eSI6IkVDI\
//     iwieCI6IkFMRkNUQ2s0YWdlRDlsUjlJWXVDVVpmbGFpN0wwNjJveUc5Q1FadFozLUhuanpYcWlJT2hCVnJBVH\
//     JmdHQ1VEhSa2NiOVlSbDdnMnNqQmFxdGJIM1VhbE4iLCJ5IjoiQVQxby1falFBUFB1TWs2blFNM2dXOEVxaGV\
//     0Vmxxb3NPLXhjMWlFcDdoTDBOQUdFN1hCYkpUQTh2b05MZWw1bWxkVFJJRDUtclBKSG13WVp0UkNDeWVfcSJ9\
//     fQ..YV2pQ8H5sCIEGEas.WpRgDKhTDf8.V0ZyG9OeGc68IZoGugqVEA";

//     // Undo JWE compact serialization
//     let mut split = JWE.split('.');
//     let header = split.next().unwrap();
//     let encrypted_key = split.next().unwrap();
//     assert!(encrypted_key.is_empty());
//     let iv = split.next().unwrap();
//     let ciphertext = split.next().unwrap();
//     let auth_tag = split.next().unwrap();
//     assert!(split.next().is_none());

//     let header = Base64UrlUnpadded::decode_vec(header).unwrap();
//     let header = std::str::from_utf8(&header).unwrap();
//     println!("header: {header}");

//     let header_json: Value = serde_json::from_str(header).unwrap();
//     let epk: Jwk =
//         serde_json::from_value(header_json.as_object().unwrap().get("epk").unwrap().clone())
//             .unwrap();

//     // // public key used as encryption
//     // const SAMPLE_ENC_JWK: &str = r#"{
//     //     "crv": "P-521",
//     //     "kty": "EC",
//     //     "x": "AbkDg4XtZlIWV-gkfQd6YYx7T7sMBds_xk-YANmBucBCPL4CMmiJP0VS6A0GvbimkZANrjmnC2PGwYvhVxY4StWd",
//     //     "y": "AeIkvpdwKd-8l5sl01u-rP9ebNRvpgK3bSKCvI2BhhwLO7KD-EI8IFBC3_x8_hkpurNXhD5t2t8dInT37O3Y4Vr2"
//     // }"#;

//     // let adv: Advertisment = serde_json::from_str(SAMPLE_JWS).unwrap();
//     // let (keys, thp) = adv.validate_into_keys(None).unwrap();
//     // let mut gk = keys.make_tang_enc_key::<32>("wxyz", thp).unwrap();

//     // // Configure things to match up with Clevis, and use a fixed EPC for repeated tests
//     // gk.meta.enc = Some("A256GCM".into());
//     // gk.meta.epk = serde_json::from_str(SAMPLE_EPK).unwrap();

//     // // This output is `jwe_base` in our command
//     // let mut val = serde_json::to_value(&gk.meta).unwrap();
//     // val.as_object_mut().unwrap().remove("epk");
//     // let jwe_base = serde_json::json!({"protected": val});
//     // println!("{}", serde_json::to_string(&jwe_base).unwrap());

//     // let key: &Key<Aes256Gcm> = gk.encryption_key.as_bytes().into();
//     // // let nonce: & Nonce<Aes256Gcm::NonceSize> =

//     panic!()
// }
