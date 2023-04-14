use std::{io, str::Utf8Error};

pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
pub enum Error {
    Server(ureq::Error),
    IoError(io::Error),
    MissingKeyOp(&'static str),
    Utf8(Utf8Error),
    Base64(base64::DecodeError),
}

impl From<ureq::Error> for Error {
    fn from(value: ureq::Error) -> Self {
        Error::Server(value)
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

impl From<base64::DecodeError> for Error {
    fn from(value: base64::DecodeError) -> Self {
        Self::Base64(value)
    }
}
