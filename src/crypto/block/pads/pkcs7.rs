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
// methods for larger k are an open issue for further study.
pub struct Pkcs7 {}

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
        let last_block = ciphertext[ciphertext.len() - 1];
        let last_byte = last_block[last_block.len() - 1];

        let byte_stream = ciphertext
            .into_iter()
            .flat_map(|b| b.as_slice())
            .take(ciphertext.len() - last_byte as usize)
            .cloned(); // TODO: is there a way to get [T] instead of [&T] from GenericArray<u8, N>

        byte_stream.collect()
    }
}
