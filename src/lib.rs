#![warn(missing_docs)]
#![deny(warnings)]

//! # fuin
//!
//! `fuin` provides cryptographic protocols meant for secure communication.
//! The project is unaudited, and intended for educational and experimental purposes.
//! Please do not use this software in production under any circumstances.

extern crate alloc; // extern crate declaration still required post rust 2018 for no_std environments

pub mod attack;
pub mod crypto;
pub mod encode;
pub mod rng;
