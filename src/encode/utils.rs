//! This module provides utilities for sister encode modules.

/// Converts a `char` to its UTF-8 byte representation.
///
/// # Examples
///
/// ```
/// use kaidoku::encode::utils;
///
/// let c = '漢';
/// let bytes = utils::char_to_bytes(c);
/// assert_eq!(bytes, vec![0xe6, 0xbc, 0xa2, 0x0]);
/// ```
///
/// # Note
///
/// This function will always return a Vec<u8> of length 4, even if the UTF-8 representation of the character could fit in fewer bytes.
/// For characters that require less than 4 bytes, the remaining bytes will be set to zero.
pub fn char_to_bytes(c: char) -> Vec<u8> {
    let mut bytes = [0u8; 4]; // buffer of byte 4 is large enough to encode any char
    c.encode_utf8(&mut bytes);
    bytes.into()
}
