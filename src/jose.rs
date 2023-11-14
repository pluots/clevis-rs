use std::fmt;

use base64ct::{Base64Url, Base64UrlUnpadded, Encoding};
use elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ModulusSize, ToEncodedPoint};
use elliptic_curve::zeroize::Zeroizing;
#[cfg(test)]
use elliptic_curve::SecretKey;
use elliptic_curve::{
    AffinePoint, Curve, CurveArithmetic, FieldBytes, FieldBytesSize, JwkParameters, PublicKey,
};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
#[cfg(test)]
use zeroize::Zeroize;

use crate::key_exchange::{create_enc_key, recover_enc_key};
use crate::util::{b64_to_bytes, b64_to_str};
use crate::{EncryptionKey, Error, Result};

/// Representation of a tang advertisment response which is a JWS of available keys.
///
/// This is what is produced when you GET `tang_url/adv`.
#[derive(Clone, Deserialize)]
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
    ///
    /// If a thumbprint is specified, only use a verify key with that thumbprint. Otherwise,
    /// use any verify key.

    fn validate(&self, jwks: &JwkSet, thumbprint: Option<&str>) -> Result<Box<str>> {
        let (verify_jwk, thp) = if let Some(thp) = thumbprint {
            (jwks.get_key_by_id(thp)?, Box::from(thp))
        } else {
            let verify_jwk = jwks.get_key_by_op("verify")?;
            (verify_jwk, verify_jwk.make_thumbprint(ThpHashAlg::Sha256))
        };

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

        verify_jwk.verify(&to_verify, &self.signature)?;
        Ok(thp)
    }

    /// Validate the advertisment and extract its keys
    pub fn validate_into_keys(self, thumbprint: Option<&str>) -> Result<(JwkSet, Box<str>)> {
        let jwks: JwkSet = serde_json::from_str(&self.payload)?;
        let thp = self.validate(&jwks, thumbprint)?;
        Ok((jwks, thp))
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

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Jwk {
    #[serde(flatten)]
    pub inner: JwkInner,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_ops: Option<Vec<Box<str>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alg: Option<Box<str>>,
    // #[serde(flatten)]
    // pub extra: HashMap<Box<str>, serde_json::Value>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "kty", rename_all = "UPPERCASE")]
pub enum JwkInner {
    Ec(EcJwk),
    Rsa(RsaJwk),
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EcJwk {
    pub crv: Box<str>,
    pub x: Box<str>,
    /// Only required for the `P-` curves
    #[serde(skip_serializing_if = "Option::is_none")]
    pub y: Option<Box<str>>,
    /// Private key part
    #[serde(skip_serializing_if = "Option::is_none")]
    pub d: Option<Zeroizing<Box<str>>>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RsaJwk {
    pub e: Box<str>,
    pub n: Box<str>,
}

impl Jwk {
    /// Jwk thumbprint as described in RFC7638 section 3.1.
    fn make_thumbprint(&self, alg: ThpHashAlg) -> Box<str> {
        match &self.inner {
            JwkInner::Ec(ec_key) => ec_key.make_thumbprint(alg),
            JwkInner::Rsa(rsa_key) => rsa_key.make_thumbprint(alg),
        }
    }

    /// Return the EC JWK if that is the correct type, an algorithm error otherwise
    pub(crate) fn as_ec(&self) -> Result<&EcJwk> {
        match &self.inner {
            JwkInner::Ec(key) => Ok(key),
            JwkInner::Rsa(_) => Err(Error::Algorithm("RSA".into())),
        }
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match &self.inner {
            JwkInner::Ec(v) => v.verify(message, signature),
            JwkInner::Rsa(_) => Err(Error::Algorithm("RSA".into())),
        }
    }
}

impl fmt::Display for Jwk {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut to_fmt = self.clone();

        // Hide the secret key
        if let JwkInner::Ec(EcJwk {
            d: Some(ref mut val),
            ..
        }) = to_fmt.inner
        {
            *val = Zeroizing::new("****".into());
        };

        f.write_str(&serde_json::to_string(&to_fmt).unwrap())
    }
}

fn encode_base64url_fe<C: Curve>(field: &FieldBytes<C>) -> Box<str> {
    Base64Url::encode_string(field).into()
}

fn decode_base64url_fe<C: Curve>(s: &str) -> Result<FieldBytes<C>> {
    let mut result = FieldBytes::<C>::default();
    Base64Url::decode(s, &mut result).map_err(|_| Error::EllipitcCurve)?;
    Ok(result)
}

impl EcJwk {
    /// Convert to a usable `PublicKey`
    pub(crate) fn to_pub<C>(&self) -> Result<PublicKey<C>>
    where
        C: CurveArithmetic + JwkParameters,
        AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        assert_eq!(self.crv.as_ref(), C::CRV);

        let Some(ref y) = self.y else {
            return Err(Error::InvalidPublicKey(Jwk::from(self.clone()).into()));
        };

        let x = decode_base64url_fe::<C>(&self.x)?;
        let y = decode_base64url_fe::<C>(y)?;
        let affine = EncodedPoint::<C>::from_affine_coordinates(&x, &y, false);

        PublicKey::from_sec1_bytes(affine.as_bytes()).map_err(Into::into)
    }

    pub(crate) fn from_pub<C>(key: &PublicKey<C>) -> Self
    where
        C: CurveArithmetic + JwkParameters,
        AffinePoint<C>: ToEncodedPoint<C>,
        FieldBytesSize<C>: ModulusSize,
    {
        let point = key.as_affine().to_encoded_point(false);
        let x = encode_base64url_fe::<C>(point.x().expect("unexpected identity point"));
        let y = encode_base64url_fe::<C>(point.y().expect("unexpected identity point"));
        Self {
            crv: C::CRV.into(),
            x,
            y: Some(y),
            d: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn to_priv<C>(&self) -> Result<SecretKey<C>>
    where
        C: CurveArithmetic,
    {
        let Some(d) = &self.d else {
            panic!("expected private key but got public")
        };

        let mut d_bytes = decode_base64url_fe::<C>(d.as_ref())?;
        let result = SecretKey::<C>::from_slice(&d_bytes)?;
        d_bytes.zeroize();

        Ok(result)
    }

    pub(crate) fn get_curve(&self) -> Result<JwkCurve> {
        match self.crv.as_ref() {
            "P-256" => Ok(JwkCurve::P256),
            "P-284" => Ok(JwkCurve::P384),
            "P-521" => Ok(JwkCurve::P521),
            other => Err(Error::Algorithm(other.into())),
        }
    }

    pub(crate) fn verify(&self, message: &[u8], signature: &[u8]) -> Result<()> {
        match self.get_curve()? {
            JwkCurve::P256 => self.verify_p256(message, signature),
            JwkCurve::P384 => self.verify_p384(message, signature),
            JwkCurve::P521 => self.verify_p521(message, signature),
        }
    }

    pub(crate) fn make_thumbprint(&self, alg: ThpHashAlg) -> Box<str> {
        let to_enc = json! {{
            "crv": &self.crv,
            "kty": "EC",
            "x": &self.x,
            "y": &self.y
        }};
        alg.hash_data_to_string(to_enc.to_string().as_bytes())
    }

    // FIXME: switch these to use generics once p521 uses the `ecdsa` crate traits

    fn verify_p256(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        use p256::ecdsa::signature::Verifier;
        use p256::ecdsa::{Signature, VerifyingKey};
        let pubkey = self.to_pub::<p256::NistP256>()?;
        let verify_key = VerifyingKey::from_affine(*pubkey.as_affine())?;
        let signature = Signature::from_slice(sig)?;
        verify_key
            .verify(msg, &signature)
            .map_err(|_| Error::FailedVerification)
    }

    fn verify_p384(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        use p384::ecdsa::signature::Verifier;
        use p384::ecdsa::{Signature, VerifyingKey};
        let pubkey = self.to_pub::<p384::NistP384>()?;
        let verify_key = VerifyingKey::from_affine(*pubkey.as_affine())?;
        let signature = Signature::from_slice(sig)?;
        verify_key
            .verify(msg, &signature)
            .map_err(|_| Error::FailedVerification)
    }

    fn verify_p521(&self, msg: &[u8], sig: &[u8]) -> Result<()> {
        use p521::ecdsa::signature::Verifier;
        use p521::ecdsa::{Signature, VerifyingKey};
        let pubkey = self.to_pub::<p521::NistP521>()?;
        let verify_key = VerifyingKey::from_affine(*pubkey.as_affine())?;
        let signature = Signature::from_slice(sig)?;
        verify_key
            .verify(msg, &signature)
            .map_err(|_| Error::FailedVerification)
    }
}

impl From<EcJwk> for Jwk {
    fn from(value: EcJwk) -> Self {
        Jwk {
            inner: JwkInner::Ec(value),
            key_ops: None,
            alg: None,
            // extra: HashMap::new(),
        }
    }
}

impl TryFrom<Jwk> for EcJwk {
    type Error = Error;

    fn try_from(value: Jwk) -> std::result::Result<Self, Self::Error> {
        match value.inner {
            JwkInner::Ec(ec_key) => Ok(ec_key),
            JwkInner::Rsa(_) => Err(Error::Algorithm("RSA".into())),
        }
    }
}

/// A verification algorithm
#[derive(Clone, Copy, Debug)]
pub(crate) enum JwkCurve {
    P256,
    P384,
    P521,
}

impl RsaJwk {
    fn make_thumbprint(&self, alg: ThpHashAlg) -> Box<str> {
        let to_enc = json! {{ "e": &self.e, "kty": "RSA", "n": &self.n }};
        alg.hash_data_to_string(to_enc.to_string().as_bytes())
    }
}

/// The response from a Tang server, containing a list of possible keys to use for derivation
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct JwkSet {
    keys: Vec<Jwk>,
}

impl JwkSet {
    /// Get a single key that contains an operation
    fn get_key_by_op(&self, op_name: &str) -> Result<&Jwk> {
        self.keys
            .iter()
            .find(|key| {
                key.key_ops.as_ref().map_or(false, |ops| {
                    ops.iter().any(|op| op.eq_ignore_ascii_case(op_name))
                })
            })
            .ok_or(Error::MissingKeyOp(op_name.into()))
    }

    pub(crate) fn get_key_by_id(&self, kid: &str) -> Result<&Jwk> {
        for key in &self.keys {
            let thp_sha256 = key.make_thumbprint(ThpHashAlg::Sha256);
            if thp_sha256.as_ref() == kid {
                return Ok(key);
            }
            let thp_sha1 = key.make_thumbprint(ThpHashAlg::Sha1);
            if thp_sha1.as_ref() == kid {
                return Ok(key);
            }
        }
        Err(Error::MissingPublicKey)
    }

    pub(crate) fn make_tang_enc_key<const N: usize>(
        &self,
        url: &str,
        signing_thumbprint: Box<str>,
    ) -> Result<ProvisionedData<N>> {
        let derive_jwk = self.get_key_by_op("deriveKey")?.clone();
        let derive_jwk = derive_jwk.as_ec()?;

        let (epk, encryption_key) = create_enc_key(derive_jwk)?;
        let clevis = ClevisParams {
            pin: "tang".into(),
            tang: TangParams {
                adv: self.clone(),
                url: url.into(),
            },
        };
        let meta = KeyMeta {
            alg: "ECDH-ES".into(),
            clevis,
            enc: None,
            epk: epk.into(),
            kid: derive_jwk.make_thumbprint(ThpHashAlg::Sha256),
        };

        Ok(ProvisionedData {
            encryption_key,
            signing_thumbprint,
            meta,
        })
    }
}

/// The key types we support
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ThpHashAlg {
    Sha1,
    Sha256,
}

impl ThpHashAlg {
    fn hash_data_to_string(self, data: &[u8]) -> Box<str> {
        match self {
            ThpHashAlg::Sha1 => {
                let mut hasher = sha1::Sha1::new();
                hasher.update(data);
                Base64UrlUnpadded::encode_string(&hasher.finalize())
            }
            ThpHashAlg::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(data);
                Base64UrlUnpadded::encode_string(&hasher.finalize())
            }
        }
        .into_boxed_str()
    }
}

/// Data that is produced as a result of the provisioning (key generation) step.
pub struct ProvisionedData<const KEYBYTES: usize> {
    /// Use this key to encrypt data
    pub encryption_key: EncryptionKey<KEYBYTES>,
    /// The thumbprint used for signing. Future keys can be requested using this thumbprint.
    pub signing_thumbprint: Box<str>,

    /// Metadata required to regenerate an encryption key.
    ///
    /// Both this metadata and a connection to the Tang server are needed to recover the
    /// key for use with encryption. This data can be stored in JSON form.
    ///
    /// <div class="warning">
    ///     ⚠️ WARNING:
    ///     Anybody who has access to both this metadata and the Tang server can recover
    ///     the encryption keys. Treat this data with respect!
    /// </div>
    pub meta: KeyMeta,
}

/// Data that must be stored to retrieve a key.
///
/// <div class="warning">
///     ⚠️ WARNING:
///     Note that while this data does not contain the encryption key, it should still not
///     be exposed. Any device that can read this metadata could potentially decrypt
///     the ciphertext if it has access to the Tang server.
/// </div>
#[derive(Debug, Deserialize, Serialize)]
pub struct KeyMeta {
    /// Key exchange algorithm. Typically Elliptic Curve Diffie-Hellman Ephemeral Static
    /// (ECDH-ES) with the concat KDF.
    alg: Box<str>,
    clevis: ClevisParams,
    /// Encryption algorithm
    enc: Option<Box<str>>,
    /// Our public key that is used to create the encryption key
    epk: Jwk,
    /// Key ID of the derive key, i.e. key used to generate the secret (not signing key)
    kid: Box<str>,
}

#[derive(Debug, Deserialize, Serialize)]
struct ClevisParams {
    /// This is always `tang` I think...
    pin: Box<str>,
    tang: TangParams,
}

#[derive(Debug, Deserialize, Serialize)]
struct TangParams {
    /// Keys from the initial tang response
    adv: JwkSet,
    /// Tang URL
    url: Box<str>,
}

impl KeyMeta {
    /// Serialize this data to a JSON string
    #[must_use]
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("serialization failure")
    }

    /// Deserialize this data from a JSON string
    pub fn from_json(val: &str) -> Result<Self> {
        serde_json::from_str(val).map_err(Into::into)
    }

    pub(crate) fn recover_key<const N: usize>(
        &self,
        server_key_exchange: impl FnOnce(&str, &Jwk) -> Result<Jwk>,
    ) -> Result<EncryptionKey<N>> {
        let c_pub_jwk = &self.epk.as_ec()?;
        let kid = &self.kid;
        let s_pub_jwk = self.clevis.tang.adv.get_key_by_id(kid)?.as_ec()?;

        recover_enc_key(c_pub_jwk, s_pub_jwk, |x_pub_jwk| {
            server_key_exchange(kid, x_pub_jwk)
        })
    }
}

#[cfg(test)]
#[path = "jose_tests.rs"]
mod tests;
