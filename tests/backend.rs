#![cfg(feature = "_backend")]

use clevis::TangClient;

const TEST_URL: &str = env!("TEST_TANG_URL");

fn make_client() -> TangClient {
    TangClient::new(TEST_URL, None)
}

#[test]
fn test_fetch_key() {
    let client = make_client();
    client.fetch_keys().unwrap();
}
