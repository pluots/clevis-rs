use super::*;

/// Sample JWS as provided from a tang server
pub const SAMPLE_JWS: &str = concat!(
    r#"{"payload": ""#,
    // The payload contains `{"keys": [...]}` with the two keys below
    "eyJrZXlzIjogW3siYWxnIjogIkVDTVIiLCAia3R5IjogIkVDIiwgImNydiI6ICJQLTUyMSIsICJ4IjogIkFGa3preGxGa\
    EpMWlMtOXZQeGkwbV83T1d6NVRKWGotZ2JFaVd1am40RHNHM1pzU3pMRWt3MGdlQXFTb29NN01sSS1IRDJuOGpxOTNWS1h\
    xZm5mcGg2VjgiLCAieSI6ICJBUTFfQm5RdWNEc2NESl9VZll0ZVE4TUVnNzF5Z3cteDdnWDlRWkxyMzlReHJEOEVfbDYxc\
    EhReFdaX3VFMTk1dDlvdGhTVmtqRi1DMXU1QjhmdFQ2YkRUIiwgImtleV9vcHMiOiBbImRlcml2ZUtleSJdfSwgeyJhbGc\
    iOiAiRVM1MTIiLCAia3R5IjogIkVDIiwgImNydiI6ICJQLTUyMSIsICJ4IjogIkFHdWFRZ1h0Ni1LUVoyYTlFMVRtODlLa\
    TZjeFBKXzdBYTAxOS1yUVY5ZGRTbDZ2M1oyMWVHMTBLc055ckVuSG0wdlRDd0JXVnRtWkc5Mlh4YUdRay1Ua1giLCAieSI\
    6ICJBWFJaZV95NXJqSjBSQXZ0NzNoWUNNbnptZ0JfblBNU1h2Ym5jTDZsMEg2SFJaU1lDLXZPWi1hYk5CcHpLcFBtb1JHZ\
    zdjX01USjhnY0xjRzU1aS1PYkVwIiwgImtleV9vcHMiOiBbInZlcmlmeSJdfV19",
    // Protected only contains `{"alg":"ES512","cty":"jwk-set+json"}`
    r#"", "protected": "eyJhbGciOiJFUzUxMiIsImN0eSI6Imp3ay1zZXQranNvbiJ9","#,
    r#" "signature": ""#,
    // Binary signature
    "ABhpt-sM13vNSbVWU9RA8m6fyJ95LJ1RZvuCHBfLBHhZPBWndiUJNonkkTeoe9dB-QICJLsZmRHVGenpUv-gzWruAY0JY\
    FQJ-8groU96HVvhMzDOTL37yzkvVOQprf27S-gBf2Q4Rl09Nm4aHajSRngICjwF1PcXS9cRUVh_Nsx0tcEK",
    r#""}"#,
);

/// Tang server internals
const SAMPLE_JWK_DERIVE: &str = r#"{
    "alg": "ECMR",
    "kty": "EC",
    "crv": "P-521",
    "x": "AFkzkxlFhJLZS-9vPxi0m_7OWz5TJXj-gbEiWujn4DsG3ZsSzLEkw0geAqSooM7MlI-HD2n8jq93VKXqfnfph6V8",
    "y": "AQ1_BnQucDscDJ_UfYteQ8MEg71ygw-x7gX9QZLr39QxrD8E_l61pHQxWZ_uE195t9othSVkjF-C1u5B8ftT6bDT",
    "d": "ADF8n-jGhS41zhG0IQ6WQbdrB5NQDeduQMjB_wBA3s1rIFTT4ybl0pg08tyo77-sDAtue9x2I58-2JnJIHiQG5P7",
    "key_ops": ["deriveKey"]
}"#;

const SAMPLE_JWK_VERIFY: &str = r#"{
    "alg": "ES512",
    "kty": "EC",
    "crv": "P-521",
    "x": "AGuaQgXt6-KQZ2a9E1Tm89Ki6cxPJ_7Aa019-rQV9ddSl6v3Z21eG10KsNyrEnHm0vTCwBWVtmZG92XxaGQk-TkX",
    "y": "AXRZe_y5rjJ0RAvt73hYCMnzmgB_nPMSXvbncL6l0H6HRZSYC-vOZ-abNBpzKpPmoRGg7c_MTJ8gcLcG55i-ObEp",
    "d": "AVb6rUlxKkeuew9hjgXthD_Oc44QCYN6Q61oGs-BsFB9yamBm-DrQiQn5xGMLn-R0vsTbzw8ucyUkaI_gl4q-zhT",
    "key_ops": ["sign", "verify"]
}"#;

const SAMPLE_JWK_DERIVE_THP: &str = "DTryOiC-dpmMBftuUMf5nBpDjBMK9Ri4rcGvBq3rFRU";
const SAMPLE_JWK_VERIFY_THP: &str = "wUNL__gwORwHmgKjKvVnK2rCFEWOu1oM65na-9iVcqA";

#[test]
fn test_verify() {
    // Ensure we can extract and validate the keys
    let adv: Advertisment = serde_json::from_str(SAMPLE_JWS).unwrap();
    let _ = adv.clone().validate_into_keys(None).unwrap();
    let _ = adv.validate_into_keys(Some("foo")).unwrap_err();
}

#[test]
fn test_thumbprint() {
    let jwk: Jwk = serde_json::from_str(SAMPLE_JWK_DERIVE).unwrap();
    assert_eq!(
        jwk.make_thumbprint(ThpHashAlg::Sha256).as_ref(),
        SAMPLE_JWK_DERIVE_THP
    );
    let jwk: Jwk = serde_json::from_str(SAMPLE_JWK_VERIFY).unwrap();
    assert_eq!(
        jwk.make_thumbprint(ThpHashAlg::Sha256).as_ref(),
        SAMPLE_JWK_VERIFY_THP
    );
}

#[test]
fn test_exchange_key() {
    let adv: Advertisment = serde_json::from_str(SAMPLE_JWS).unwrap();
    let (keys, thp) = adv.validate_into_keys(None).unwrap();
    let ProvisionedData {
        encryption_key: _,
        signing_thumbprint,
        meta,
    } = keys.make_tang_enc_key::<10>("foobar", thp.clone()).unwrap();
    assert_eq!(signing_thumbprint, thp);

    // Make sure we have all the correct top-level keys
    let mut expected_keys = vec!["alg", "clevis", "enc", "epk", "kid"];
    expected_keys.sort_unstable();

    let val = serde_json::to_value(&meta).unwrap();
    let mut keys = val.as_object().unwrap().keys().collect::<Vec<_>>();
    keys.sort_unstable();
    assert_eq!(keys, expected_keys);

    println!("{}", serde_json::to_string_pretty(&meta).unwrap());
}
