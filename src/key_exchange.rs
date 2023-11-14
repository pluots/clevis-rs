use crate::jose::{EcJwk, Jwk, JwkCurve};
use crate::{Error, Result};
use elliptic_curve::ecdh;
use elliptic_curve::ecdh::SharedSecret;
use elliptic_curve::group::Curve as GroupCurve;
use elliptic_curve::point::AffineCoordinates;
use elliptic_curve::rand_core::OsRng;
use elliptic_curve::sec1::FromEncodedPoint;
use elliptic_curve::sec1::ModulusSize;
use elliptic_curve::sec1::ToEncodedPoint;
use elliptic_curve::subtle::ConstantTimeEq;
use elliptic_curve::zeroize::Zeroizing;
use elliptic_curve::AffinePoint;
use elliptic_curve::Curve;
use elliptic_curve::CurveArithmetic;
use elliptic_curve::FieldBytesSize;
use elliptic_curve::JwkParameters;
use elliptic_curve::ProjectivePoint;
use elliptic_curve::PublicKey;
use elliptic_curve::SecretKey;

/// A zeroizing wrapper around a generated encryption key
#[derive(Clone, Debug)]
pub struct EncryptionKey<const KEYBYTES: usize>(Zeroizing<[u8; KEYBYTES]>);

impl<const KEYBYTES: usize> EncryptionKey<KEYBYTES> {
    /// Return a reference to the secret key. Treat this data with respect!
    #[must_use]
    pub fn as_bytes(&self) -> &[u8; KEYBYTES] {
        &self.0
    }
}

impl<const KEYBYTES: usize> ConstantTimeEq for EncryptionKey<KEYBYTES> {
    fn ct_eq(&self, other: &Self) -> elliptic_curve::subtle::Choice {
        self.0.ct_eq(other.0.as_ref())
    }
}

impl<const KEYBYTES: usize> PartialEq for EncryptionKey<KEYBYTES> {
    fn eq(&self, other: &Self) -> bool {
        self.ct_eq(other).into()
    }
}

/// Perform key generation in accordance with tang protocol
///
/// Rough description, capitals are public:
///
/// - Take in a server public JWK `S` (internally the server has `S = [s]G`)
/// - Create a client keypair `c` and `C`
/// - Perform half of ECDH with client private key and server public key to get `K = [c]S`. `K` is the
///   key used to encrypt data, and also satisfies `K = [cs]G`
pub fn create_enc_key<const N: usize>(s_pub_jwk: &EcJwk) -> Result<(EcJwk, EncryptionKey<N>)> {
    match s_pub_jwk.get_curve()? {
        JwkCurve::P256 => create_enc_key_inner::<p256::NistP256, N>(s_pub_jwk),
        JwkCurve::P384 => create_enc_key_inner::<p384::NistP384, N>(s_pub_jwk),
        JwkCurve::P521 => create_enc_key_inner::<p521::NistP521, N>(s_pub_jwk),
    }
}

pub fn recover_enc_key<const N: usize>(
    c_pub_jwk: &EcJwk,
    s_pub_jwk: &EcJwk,
    server_key_exchange: impl FnOnce(&Jwk) -> Result<Jwk>,
) -> Result<EncryptionKey<N>> {
    // Wrapper to turn our EcJwks into Jwks. I think we need to set the `alg` parameter
    let key_exchange = |ec_jwk: &EcJwk| -> Result<EcJwk> {
        let mut jwk: Jwk = ec_jwk.clone().into();
        jwk.alg = Some("ECMR".into());
        server_key_exchange(&jwk).and_then(EcJwk::try_from)
    };

    match c_pub_jwk.get_curve()? {
        JwkCurve::P256 => {
            recover_enc_key_inner::<p256::NistP256, N>(c_pub_jwk, s_pub_jwk, key_exchange)
        }
        JwkCurve::P384 => {
            recover_enc_key_inner::<p384::NistP384, N>(c_pub_jwk, s_pub_jwk, key_exchange)
        }
        JwkCurve::P521 => {
            recover_enc_key_inner::<p521::NistP521, N>(c_pub_jwk, s_pub_jwk, key_exchange)
        }
    }
}

/// Generate an encryption key from a public key using Tang's algorithm:
///
/// - Generate an ephemeral key
/// - Extract the key using HKDF
fn create_enc_key_inner<C, const KEYBYTES: usize>(
    remote_jwk: &EcJwk,
) -> Result<(EcJwk, EncryptionKey<KEYBYTES>)>
where
    C: CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let serv_kpub = remote_jwk.to_pub()?;

    let cli_kpriv = ecdh::EphemeralSecret::<C>::random(&mut OsRng);
    let jwk = EcJwk::from_pub(&cli_kpriv.public_key());
    let shared = cli_kpriv.diffie_hellman(&serv_kpub);

    Ok((jwk, secret_to_key(shared)))
}

/// Recreate an encryption key from metadata
///
/// From the clevis docs:
///
/// To recover `dJWK` after discarding it, the client generates a third
/// ephemeral key (`eJWK`). Using `eJWK`, the client performs elliptic curve group
/// addition of `eJWK` and `cJWK`, producing `xJWK`. The client POSTs `xJWK` to the server.
///
/// The server then performs its half of the ECDH key exchange using `xJWK` and `sJWK`,
/// producing `yJWK`. The server returns `yJWK` to the client.
///
/// The client then performs half of an ECDH key exchange between `eJWK` and `sJWK`,
/// producing `zJWK`. Subtracting `zJWK` from `yJWK` produces `dJWK` again.
//
/// Expressed mathematically (capital = private key):
///
/// ```text
/// e = g * E # eJWK
/// x = c + e # xJWK
/// y = x * S # yJWK (Server operation)
/// z = s * E # zJWK
/// K = y - z # dJWK
/// ```
fn recover_enc_key_inner<C, const KEYBYTES: usize>(
    c_pub_jwk: &EcJwk,
    s_pub_jwk: &EcJwk,
    server_key_exchange: impl FnOnce(&EcJwk) -> Result<EcJwk>,
) -> Result<EncryptionKey<KEYBYTES>>
where
    C: CurveArithmetic + JwkParameters,
    AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
    FieldBytesSize<C>: ModulusSize,
{
    let c_pub = c_pub_jwk.to_pub::<C>()?;
    let s_pub = s_pub_jwk.to_pub::<C>()?;

    // e = g * E
    let e_priv = SecretKey::<C>::random(&mut OsRng);
    let e_pub = e_priv.public_key();

    // x = c + e
    let x_pub = ecmr_add(&c_pub, &e_pub)?;
    let x_pub_jwk = EcJwk::from_pub(&x_pub);

    // y = x * S, server operation
    let y_pub_jwk = server_key_exchange(&x_pub_jwk)?;
    let y_pub = y_pub_jwk.to_pub::<C>()?;

    // z = s * E
    let z_pub = diffie_hellman(&e_priv, &s_pub)?;

    let k_pub = ecmr_sub(&y_pub, &z_pub)?;

    let k: SharedSecret<C> = k_pub.as_affine().x().into();

    Ok(secret_to_key(k))
}

/// Reimplementation of `elliptic_curve::ecdh::diffie_hellman` that works with our types easier
///
/// This is standard ECDH, and first mode of the so-called "ECMR" algorithm
fn diffie_hellman<C>(
    secret_key: &SecretKey<C>, // "local" key
    public_key: &PublicKey<C>, // "remote" key
) -> Result<PublicKey<C>>
where
    C: CurveArithmetic,
{
    let public_point: ProjectivePoint<C> = (*public_key.as_affine()).into();
    let secret_point: AffinePoint<C> =
        (public_point * secret_key.to_nonzero_scalar().as_ref()).to_affine();
    PublicKey::from_affine(secret_point).map_err(Into::into)
}

/// Point addition, per ECMR <https://www.mankier.com/1/jose-jwk-exc>
///
/// That doc specifies that local is public and remote is private, but seems like
/// that shouldn't be necessary.
pub fn ecmr_add<C>(local: &PublicKey<C>, remote: &PublicKey<C>) -> Result<PublicKey<C>>
where
    C: CurveArithmetic,
{
    let local_point: ProjectivePoint<C> = (*local.as_affine()).into();
    let remote_point: ProjectivePoint<C> = (*remote.as_affine()).into();
    PublicKey::from_affine((local_point + remote_point).to_affine())
        .map_err(|_| Error::IdentityPointCreated)
}

// FIXME: subtraction doesn't match up with `jose` for some reason, but appears otherwise correct.
// My guess is that it isn't actually doing subtraction, but I am not sure what it is doing instead...
/// Point subtraction, per ECMR in <https://www.mankier.com/1/jose-jwk-exc>
pub fn ecmr_sub<C>(local: &PublicKey<C>, remote: &PublicKey<C>) -> Result<PublicKey<C>>
where
    C: CurveArithmetic,
{
    let local_point: ProjectivePoint<C> = (*local.as_affine()).into();
    let remote_point: ProjectivePoint<C> = (*remote.as_affine()).into();
    PublicKey::from_affine((local_point - remote_point).to_affine())
        .map_err(|_| Error::IdentityPointCreated)
}

#[allow(clippy::needless_pass_by_value)]
fn secret_to_key<C: Curve, const KEYBYTES: usize>(
    secret: SharedSecret<C>,
) -> EncryptionKey<KEYBYTES> {
    let mut enc_key = EncryptionKey(Zeroizing::new([0u8; KEYBYTES]));

    // FIXME: is SHA256 always correct?
    concat_kdf::derive_key_into::<sha2::Sha256>(secret.raw_secret_bytes(), &[], enc_key.0.as_mut())
        .unwrap();
    enc_key
}

// #[allow(unused)]
// fn jwk_to_priv<C>(jwk: &Jwk) -> Result<SecretKey<C>>
// where
//     C: JwkParameters + ValidatePublicKey,
//     FieldBytesSize<C>: ModulusSize,
// {
//     let errfn = || Error::InvalidPublicKey(jwk.clone());
//     let json = serde_json::json! {{
//         "crv": jwk.parameter("crv").ok_or_else(errfn)?,
//         "kty": jwk.parameter("kty").ok_or_else(errfn)?,
//         "d": jwk.parameter("d").ok_or_else(errfn)?,
//         "x": jwk.parameter("x").ok_or_else(errfn)?,
//         "y": jwk.parameter("y").ok_or_else(errfn)?,
//     }};
//     SecretKey::from_jwk_str(&json.to_string()).map_err(|_| Error::InvalidPublicKey(jwk.clone()))
// }

// fn jwk_from_pub<C>(key: &PublicKey<C>) -> Jwk
// where
//     C: CurveArithmetic + JwkParameters,
//     AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
//     FieldBytesSize<C>: ModulusSize,
// {
//     serde_json::from_str(key.to_jwk_string().as_ref()).expect("dependency generated an invalid JWK")
// }

// #[allow(unused)]
// fn jwk_from_priv<C>(key: &SecretKey<C>) -> Jwk
// where
//     C: CurveArithmetic + JwkParameters,
//     AffinePoint<C>: FromEncodedPoint<C> + ToEncodedPoint<C>,
//     FieldBytesSize<C>: ModulusSize,
// {
//     serde_json::from_str(key.to_jwk_string().as_ref()).expect("dependency generated an invalid JWK")
// }

#[cfg(test)]
#[path = "key_exchange_tests.rs"]
mod tests;
