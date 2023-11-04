use std::{fmt, io, str::Utf8Error};

use josekit::jwk::Jwk;

pub type Result<T, E = Error> = core::result::Result<T, E>;

#[derive(Debug)]
pub enum Error {
    Server(Box<ureq::Error>),
    Algorithm(Box<str>, &'static str),
    IoError(io::Error),
    MissingKeyOp(Box<str>),
    JsonMissingKey(Box<str>),
    JsonKeyType(Box<str>),
    Utf8(Utf8Error),
    Base64(base64ct::Error),
    Json(serde_json::Error),
    Jose(josekit::JoseError),
    KeyType(Box<str>),
    VerifyKey,
    InvalidPublicKey(Jwk),
    EllipitcCurve(elliptic_curve::Error),
    MissingPublicKey,
    IdentityPointCreated,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Server(e) => write!(f, "server error: {e}"),
            Self::Algorithm(v, c) => write!(f, "invalid algorithm {v} for {c}"),
            Error::IoError(e) => write!(f, "io error {e}"),
            Error::MissingKeyOp(e) => write!(f, "no key operation {e}"),
            Error::Json(e) => write!(f, "json serde error: {e}"),
            Self::JsonMissingKey(v) => write!(f, "missing key {v}"),
            Self::JsonKeyType(v) => write!(f, "invalid key type {v} in JSON"),
            Error::Utf8(e) => write!(f, "utf8 error {e}"),
            Error::Base64(e) => write!(f, "base64 error {e}"),
            Self::VerifyKey => write!(f, "missing a key marked 'verify'"),
            Self::KeyType(v) => write!(f, "unsupported key type {v}"),
            Error::Jose(e) => write!(f, "jose error {e}"),
            Error::InvalidPublicKey(key) => write!(f, "invalid public key {key}"),
            Error::EllipitcCurve(_) => write!(f, "elliptic curve cryptography"),
            Error::MissingPublicKey => write!(f, "could not locate a key with the correct key ID"),
            Error::IdentityPointCreated => write!(f, "math resulted an an identity key"),
        }
    }
}

impl std::error::Error for Error {}

impl From<ureq::Error> for Error {
    fn from(value: ureq::Error) -> Self {
        Error::Server(value.into())
    }
}

impl From<io::Error> for Error {
    fn from(value: io::Error) -> Self {
        Error::IoError(value)
    }
}

impl From<Utf8Error> for Error {
    fn from(value: Utf8Error) -> Self {
        Self::Utf8(value)
    }
}

impl From<base64ct::Error> for Error {
    fn from(value: base64ct::Error) -> Self {
        Self::Base64(value)
    }
}

impl From<serde_json::Error> for Error {
    fn from(value: serde_json::Error) -> Self {
        Self::Json(value)
    }
}

impl From<josekit::JoseError> for Error {
    fn from(value: josekit::JoseError) -> Self {
        Self::Jose(value)
    }
}

impl From<elliptic_curve::Error> for Error {
    fn from(value: elliptic_curve::Error) -> Self {
        Self::EllipitcCurve(value)
    }
}
