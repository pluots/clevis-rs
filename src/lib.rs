//! A Rust implementation of the Tang portion of Clevis, specified in
//! <https://github.com/latchset/clevis>.
//!
//! This is still under development, but works reasonibly well.
//!
//! ```
//! # fn main() {
//! # #[cfg(feature = "_backend")] test();
//! # }
//! #
//! # fn test() {
//! use clevis::{KeyMeta, TangClient};
//!
//! /// 32-byte (256 bit) key, such as for AES256-GCM
//! const KEY_BYTES: usize = 32;
//!
//! /* key provisioning */
//!
//! // create a key suitible for encryption (i.e. has gone through a KDF)
//! let out = TangClient::new("localhost:11697", None)
//!     .create_secure_key::<KEY_BYTES>()
//!     .expect("failed to generate key");
//!
//! // use this key to encrypt data
//! let original_key = out.encryption_key;
//!
//! // this must be stored to get the encryption key back for decryption
//! // WARNING: this information should be considered secret, since any device that can
//! // access this and the tang server can retrieve the encryption key. Treat it with
//! // respect!
//! let meta_str = out.meta.to_json();
//!
//! /* key recovery */
//!
//! let new_meta = KeyMeta::from_json(&meta_str).expect("invalid metadata");
//! let new_key = new_meta
//!     .client(None)
//!     .recover_secure_key::<KEY_BYTES>(&new_meta)
//!     .expect("failed to retrieve key");
//!
//! assert_eq!(original_key, new_key);
//! # }
//! ```

#![warn(clippy::pedantic)]
#![allow(clippy::missing_panics_doc)]
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::must_use_candidate)]

mod error;
mod jose;
mod key_exchange;
mod tang_interface;
mod util;

pub use error::{Error, Result};
pub use jose::{KeyMeta, ProvisionedData};
pub use key_exchange::EncryptionKey;
pub use tang_interface::TangClient;
