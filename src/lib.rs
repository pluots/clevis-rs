#![allow(unused)]

mod decrypt;
mod encrypt;
mod error;
mod tang_interface;
mod util;

pub use decrypt::DecryptConfig;
pub use encrypt::{EncryptConfig, EncryptSource};

// pub use tang_interface::{fetch_public_key, fetch_public_keys, recover_key};
pub use tang_interface::TangClient;

pub use error::{Error, Result};

#[cfg(test)]
mod tests;
