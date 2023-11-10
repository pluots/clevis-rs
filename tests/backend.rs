#![cfg(feature = "_backend")]

use std::assert_eq;

use clevis::{GeneratedKey, KeyMeta, TangClient};

const TEST_URL: Option<&str> = option_env!("TEST_TANG_URL");

fn make_client() -> TangClient {
    TangClient::new(TEST_URL.unwrap_or("localhost:11697"), None)
}

fn json_pretty(s: &str) -> String {
    serde_json::to_string_pretty(&serde_json::from_str::<serde_json::Value>(s).unwrap()).unwrap()
}

#[test]
fn test_roundtrip() {
    let client = make_client();

    // --- provisioning ---
    let GeneratedKey {
        encryption_key,
        signing_thumbprint: _,
        meta,
    } = client.create_secure_key::<10>().unwrap();
    let meta_str = meta.to_json();

    println!("{}", json_pretty(&meta_str));

    // --- recovery ---

    let new_meta = KeyMeta::from_json(&meta_str).unwrap();
    let newkey = client.recover_secure_key::<10>(&new_meta).unwrap();

    assert_eq!(encryption_key.as_bytes(), newkey.as_bytes());
}
