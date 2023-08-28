//! # Encoding and Decoding Utilities
//! This module provides various utilities for lazily encoding and decoding data.
//! This includes Base64, Hamming, Hexadecimal conversions, and a few utility functions.
//!
//! The functionalities are organized into separate submodules:
//!
//! - [`base64`]: Provides functions to encode and decode data in Base64 format.
//! - [`hamming`]: Includes methods to calculate and manipulate Hamming distances.
//! - [`hex`]: Contains methods for converting data to and from hexadecimal representation.
//! - [`utils`]: A set of utility functions and helpers used across the other modules.
//!
//! Each submodule contains more specific documentation about its purpose and usage.
//!
//! # Examples
//!  
//! ```rust
//! use kaidoku::encode::{base64, hamming, hex, utils};
//!
//! // Example usage of the base64 submodule
//! let data = b"Hello, World!";
//! let mut encoder = base64::ByteToBase64Encoder::new(data.iter().cloned());
//! let encoded: String = encoder.collect();
//!
//! // Example usage of the hex submodule
//! let encoder = hex::ByteToHexEncoder::new(vec![0x6f, 0x6f, 0x6d].into_iter());
//! let encoded_string = encoder.collect::<Result<String, hex::HexEncodingError>>().unwrap();
//!
//! // Example usage of the hamming submodule
//! let a = "this is a test".bytes();
//! let b = "wokka wokka!!!".bytes();
//!
//! let actual_hamming_distance = hamming::distance(a, b).unwrap();
//!
//! // Example usage of the utils submodule
//! let c = '漢';
//! let bytes = utils::char_to_bytes(c);
//! ```
//!
//! Please check each submodule for more detailed examples and documentation.

pub mod base64;
pub mod hamming;
pub mod hex;
pub mod utils;
