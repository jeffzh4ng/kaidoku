//! This module provides utilities for calculating the Hamming distance
//! between two sequences of bytes.
//!
//! The main functionality is provided by the `distance` function, which
//! calculates the Hamming distance by treating the input sequences as
//! Vernam cipher keys and counting the number of differing bits.
//!
//! This module also defines a `HammingDistanceError` for error handling,
//! specifically when the sequences do not have equal lengths.
//!
//! # Examples
//!
//! ```rust
//! use kaidoku::encode::hamming::distance;
//!
//! let a = "this is a test".bytes();
//! let b = "wokka wokka!!!".bytes();
//!
//! let expected_hamming_distance = 37;
//! let actual_hamming_distance = distance(a, b).unwrap();
//!
//! assert_eq!(expected_hamming_distance, actual_hamming_distance);
//! ```

use crate::cipher;

use thiserror::Error;

/// Error type for Hamming distance calculations.
///
/// This type is a wrapper around the `VernamCipherError` provided by the
/// `cipher::vernam` module. It represents errors that may occur during the
/// process of calculating the Hamming distance between two sequences of bytes.
#[non_exhaustive]
#[derive(Debug, Error)]
pub enum HammingDistanceError {
    /// Wrapper around the Vernam cipher error
    #[error(transparent)]
    VernamError(#[from] cipher::stream::VernamCipherError),
}

/// Calculate the Hamming distance between two sequences of bytes.
///
/// The Hamming distance is calculated by treating the input sequences as
/// Vernam cipher keys and counting the number of differing bits.
///
/// # Examples
///
/// ```rust
/// use kaidoku::encode::hamming::distance;
///
/// let a = "this is a test".bytes();
/// let b = "wokka wokka!!!".bytes();
///
/// let expected_hamming_distance = 37;
/// let actual_hamming_distance = distance(a, b).unwrap();
///
/// assert_eq!(expected_hamming_distance, actual_hamming_distance);
/// ```
pub fn distance<I, J>(a: I, b: J) -> Result<usize, HammingDistanceError>
where
    I: Iterator<Item = u8>,
    J: Iterator<Item = u8>,
{
    let xor_cipher = cipher::stream::VernamCipher::new(a, b)
        .collect::<Result<Vec<u8>, cipher::stream::VernamCipherError>>()?;

    // we can use the hamming weight (population count of the XOR) to calculate the hamming distance
    // the number of 1s in the XOR is the number of bits that are different between the two inputs
    // for more, take a look at https://en.wikipedia.org/wiki/Hamming_weight
    let hamming_distance = xor_cipher.into_iter().fold(0, |hamming_weight, byte| {
        hamming_weight + byte.count_ones() as usize
    });

    Ok(hamming_distance)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn sanity_check() {
        let a = "this is a test".bytes();
        let b = "wokka wokka!!!".bytes();

        let expected_hamming_distance = 37;
        let actual_hamming_distance = distance(a, b).unwrap();

        assert_eq!(expected_hamming_distance, actual_hamming_distance);
    }
}
