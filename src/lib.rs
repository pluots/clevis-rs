#![warn(clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]

mod error;
mod jose;
mod key_exchange;
mod tang_interface;
mod util;

pub use error::{Error, Result};
pub use jose::{GeneratedKey, JwkSet, KeyMeta};
pub use key_exchange::EncryptionKey;
pub use tang_interface::TangClient;
