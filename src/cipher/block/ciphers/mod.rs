use generic_array::ArrayLength;

use super::Block;

pub mod aes;
pub mod des;

pub trait BlockCipher<N: ArrayLength<u8>> {
    fn new(key: Vec<u8>) -> Self;
    fn encrypt_block(&self, block: Block<N>) -> Block<N>;
    fn decrypt_block(&self, block: Block<N>) -> Block<N>;
}
