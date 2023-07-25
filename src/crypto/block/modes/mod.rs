use super::ciphers::BlockCipher;
use super::pads::Padder;

pub mod ecb;

pub trait BlockMode<C, P>
where
    C: BlockCipher,
    P: Padder,
{
    fn new(cipher: C, padder: P) -> Self;
    fn encrypt(&mut self, plaintext: Vec<C::Block>) -> Vec<C::Block>;
    fn decrypt(&mut self, ciphertext: Vec<C::Block>) -> Vec<C::Block>;
}
