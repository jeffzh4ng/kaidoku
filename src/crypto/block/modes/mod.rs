use super::ciphers::BlockCipher;
use super::pads::Padder;
use super::Block;

pub mod ecb;

pub trait BlockMode<N, C, P>
where
    N: generic_array::ArrayLength<u8>,
    C: BlockCipher<N>,
    P: Padder<N>,
{
    fn new(cipher: C, padder: P) -> Self;
    fn encrypt(&mut self, plaintext: Vec<u8>) -> Vec<Block<N>>;
    fn decrypt(&mut self, ciphertext: Vec<Block<N>>) -> Vec<u8>;
}
