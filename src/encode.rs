use std::io;

use crate::crypto;

pub mod base64;
pub mod hex;

pub fn hamming_distance<I, J>(a: I, b: J) -> Result<usize, io::Error>
where
    I: Iterator<Item = u8>,
    J: Iterator<Item = u8>,
{
    let xor_cipher = crypto::XorCipher::new(a, b).collect::<Result<Vec<u8>, io::Error>>()?;

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
        let actual_hamming_distance = hamming_distance(a, b).unwrap();

        assert_eq!(expected_hamming_distance, actual_hamming_distance);
    }
}
