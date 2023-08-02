use generic_array::{ArrayLength, GenericArray};

use super::super::Block;
use super::Padder;

// A Padder that implements X9.23 padding defined by ANSI X9.23 (withdrawn CBC enhancement)
// see: https://www.ibm.com/docs/en/linux-on-systems?topic=processes-ansi-x923-cipher-block-chaining

// ANSI X9.23 padding and PKCS7 padding are functionally equivalent. The last byte
// of both padding schemes encodes the length of the padding stream. ANSI X9.23
// differs insofar as the remaining padding bytes are random (usually 0x00).
// e.g. byte stream with block size 8 bytes (64 bits)
// ... | DD DD DD DD DD DD DD DD | DD DD DD DD 00 00 00 04 |
pub struct AnsiX923 {}

impl<N: ArrayLength<u8>> Padder<N> for AnsiX923 {
    fn pad(&self, plain_text: Vec<u8>) -> Vec<Block<N>> {
        let mut byte_stream = plain_text;
        let block_size = N::to_usize();
        let remainder = byte_stream.len() % block_size;

        let padding = if remainder == 0 {
            block_size
        } else {
            block_size - remainder
        };

        byte_stream.resize(byte_stream.len() + padding - 1, 0x00);
        byte_stream.push(padding as u8); // TODO: constrain max block size is 256
        byte_stream
            .chunks_exact(block_size)
            .map(|chunk| {
                let mut block = GenericArray::default();
                block.copy_from_slice(chunk);
                block
            })
            .collect()
    }

    fn unpad(&self, cipher_text: Vec<Block<N>>) -> Vec<u8> {
        let last_block = cipher_text[cipher_text.len() - 1];
        let last_byte = last_block[last_block.len() - 1];

        let byte_stream = cipher_text
            .into_iter()
            .flat_map(|b| b.as_slice())
            .take(cipher_text.len() - last_byte as usize)
            .cloned(); // TODO: is there a way to get [T] instead of [&T] from GenericArray<u8, N>

        byte_stream.collect()
    }
}
