use std::marker;

use generic_array::ArrayLength;

use super::super::ciphers::BlockCipher;
use super::super::pads::Padder;
use super::super::Block;
use super::BlockMode;

pub struct Ecb<N, C, P>
where
    N: ArrayLength<u8>,
    C: BlockCipher<N>,
    P: Padder<N>,
{
    cipher: C,
    padder: P,
    _marker: marker::PhantomData<N>, // required since N ties C and P together without being used directly
}

impl<N: ArrayLength<u8>, C: BlockCipher<N>, P: Padder<N>> BlockMode<N, C, P> for Ecb<N, C, P> {
    fn new(cipher: C, padder: P) -> Self {
        Ecb {
            cipher,
            padder,
            _marker: marker::PhantomData,
        }
    }

    fn encrypt(&mut self, plaintext: Vec<u8>) -> Vec<Block<N>> {
        let ciphertext_blocks = self
            .padder
            .pad(plaintext)
            .iter()
            .map(|plaintext_block| self.cipher.encrypt_block(*plaintext_block))
            .collect();

        ciphertext_blocks
    }

    fn decrypt(&mut self, ciphertext: Vec<Block<N>>) -> Vec<u8> {
        let plaintext_blocks = ciphertext
            .iter()
            .map(|ciphertext_block| self.cipher.decrypt_block(*ciphertext_block))
            .collect();

        self.padder.unpad(plaintext_blocks)
    }
}
