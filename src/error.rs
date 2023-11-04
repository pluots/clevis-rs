use std::{fmt, io, str::Utf8Error};

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
    VerifyKey,
    KeyType(Box<str>),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::VerifyKey => write!(f, "missing a key marked 'verify'"),
            Self::KeyType(v) => write!(f, "unsupported key type {v}"),
            Self::JsonMissingKey(v) => write!(f, "missing key {v}"),
            Self::JsonKeyType(v) => write!(f, "invalid key type {v} in JSON"),
            Self::Algorithm(v, c) => write!(f, "invalid algorithm {v} for {c}"),
            _ => write!(f, ""),
        }
    }
}

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
