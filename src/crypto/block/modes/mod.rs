use super::ciphers::BlockCipher;
use super::pads::{Padder, UnpaddedBytes};

pub mod ecb;

pub trait BlockMode<C, P>
where
    C: BlockCipher,
    P: Padder<C>,
{
    fn new(cipher: C, padder: P) -> Self;
    fn encrypt(&mut self, plaintext: UnpaddedBytes) -> Vec<C::Block>;
    fn decrypt(&mut self, ciphertext: Vec<C::Block>) -> UnpaddedBytes;
}
