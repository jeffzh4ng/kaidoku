use generic_array::{ArrayLength, GenericArray};

use super::super::Block;
use super::Padder;

struct Iso7816 {}

impl<N: ArrayLength<u8>> Padder<N> for Iso7816 {
    fn pad(&self, plaintext: Vec<u8>) -> Vec<Block<N>> {
        let mut byte_stream = plaintext;
        let block_size = N::to_usize();
        let remainder = byte_stream.len() % block_size;

        let padding = if remainder == 0 {
            block_size
        } else {
            block_size - remainder
        };

        byte_stream.push(0x80);
        byte_stream.resize(byte_stream.len() + padding - 1, 0x00 as u8);
        byte_stream
            .chunks_exact(block_size)
            .map(|c| {
                let mut block = GenericArray::default();
                block.copy_from_slice(c);
                block
            })
            .collect()
    }

    fn unpad(&self, ciphertext: Vec<Block<N>>) -> Vec<u8> {
        let byte_stream = ciphertext
            .into_iter()
            .flat_map(|b| b.as_slice())
            .take_while(|&byte| *byte == 0x00)
            .take(1); // the 0x80 delimeter padding byte

        todo!()
    }
}
