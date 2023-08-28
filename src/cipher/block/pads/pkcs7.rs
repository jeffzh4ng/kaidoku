use generic_array::{ArrayLength, GenericArray};

use super::super::Block;
use super::Padder;

// A Padder that implements pre-IETF CMS PKCS7 padding defined by RSA (the company)
// see: https://datatracker.ietf.org/doc/html/rfc2315#section-10.3

// For algorithms that assume input length is a multiple of k bytes, where k > 1,
// define a method for handling inputs whose length != 0 mod k. For such algorithms,
// the method shall be to pad the input at the trailing end with k - (l mod k)
// bytes all having value k - (l mod k) where l is the length of the input.

//     01 -- if l mod k = k-1
//   02 02 -- if l mod k = k-2
//             .
//             .
//             .
// k k ... k k -- if l mod k = 0

// The padding can be removed unambiguously since all input is
// padded and no padding string is a suffix of another. This
// padding method is well-defined if and only if k < 256;

#[derive(Default)]
pub struct Pkcs7 {}

impl Pkcs7 {
    pub fn new() -> Self {
        Pkcs7 {}
    }
}

impl<N: ArrayLength<u8>> Padder<N> for Pkcs7 {
    fn pad(&self, plaintext: Vec<u8>) -> Vec<Block<N>> {
        let mut byte_stream = plaintext;
        let block_size = N::to_usize();
        let remainder = byte_stream.len() % block_size;

        let padding = if remainder == 0 {
            block_size
        } else {
            block_size - remainder
        };

        byte_stream.resize(byte_stream.len() + padding, padding as u8); // TODO: constrain max block size is 256
        byte_stream
            .chunks_exact(block_size)
            .map(|chunk| {
                let mut block = GenericArray::default();
                block.copy_from_slice(chunk);
                block
            })
            .collect()
    }

    fn unpad(&self, ciphertext: Vec<Block<N>>) -> Vec<u8> {
        let ciphertext_len = ciphertext.len();
        let last_block = &ciphertext[ciphertext_len - 1];
        let last_byte = last_block[last_block.len() - 1];
        // println!("moose: {ciphertext_len}, {last_byte}");

        let byte_stream = ciphertext
            .into_iter()
            .flat_map(|block| block.as_slice().to_vec())
            .take(ciphertext_len * N::to_usize() - last_byte as usize);

        byte_stream.collect()
    }
}

#[cfg(test)]
mod tests {
    use generic_array::typenum;

    use super::*;

    #[test]
    fn test_pkcs7_pad_exact() {
        let plaintext = vec![0u8; 16]; // exactly one block (128 bits)
        let padder = Pkcs7 {};
        let padded: Vec<GenericArray<u8, typenum::U16>> = padder.pad(plaintext);
        assert_eq!(padded.len(), 2); // should have two blocks now, one with data and one with padding

        // last block should be entirely padding
        assert_eq!(padded[1].as_slice(), &[16u8; 16]);
    }

    #[test]
    fn test_pkcs7_pad_partial() {
        let plaintext = vec![0u8; 10]; // less than one block (80 bits)
        let padder = Pkcs7 {};
        let padded: Vec<GenericArray<u8, typenum::U16>> = padder.pad(plaintext);
        assert_eq!(padded.len(), 1); // should have one block now

        // last 6 bytes of the block should be padding
        assert_eq!(
            padded[0].as_slice(),
            &[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 6, 6, 6, 6, 6]
        );
    }

    #[test]
    fn test_pkcs7_unpad() {
        let ciphertext: Vec<GenericArray<u8, typenum::U16>> = vec![
            GenericArray::clone_from_slice(&[0u8; 16]),
            GenericArray::clone_from_slice(&[16u8; 16]),
        ];
        let padder = Pkcs7 {};
        let unpadded = padder.unpad(ciphertext);

        // should remove the entire last block of padding, leaving just the original data
        assert_eq!(unpadded, vec![0u8; 16]);
    }

    #[test]
    fn test_pkcs7_unpad_partial() {
        let block: GenericArray<u8, typenum::U16> =
            GenericArray::clone_from_slice(&[0u8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 6, 6, 6, 6, 6, 6]);
        let ciphertext = vec![block];
        let padder = Pkcs7 {};
        let unpadded = padder.unpad(ciphertext);

        // should remove the last 6 bytes of padding, leaving just the original data.
        assert_eq!(unpadded, vec![0u8; 10]);
    }
}
