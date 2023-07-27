//! # Encoding and Decoding Utilities
//! This module provides various utilities for encoding and decoding data.
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
//! use encode::{base64, hamming, hex, utils};
//!
//! // Example usage of the base64 submodule
//! let base64_encoded = base64::encode("Hello, world!");
//! println!("{}", base64_encoded);
//!
//! // Example usage of the hamming submodule
//! let distance = hamming::distance("this is a test".bytes(), "wokka wokka!!!".bytes()).unwrap();
//! println!("{}", distance);
//!
//! // Example usage of the hex submodule
//! let hex_encoded = hex::encode("Hello, world!");
//! println!("{}", hex_encoded);
//!
//! // Example usage of the utils submodule
//! let bytes = utils::char_to_bytes('A');
//! println!("{:?}", bytes);
//! ```
//!
//! Please check each submodule for more detailed examples and documentation.

pub mod base64;
pub mod hamming;
pub mod hex;
pub mod utils;
