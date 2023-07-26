use super::super::ciphers::BlockCipher;
use super::super::pads::{Padder, UnpaddedBytes};
use super::BlockMode;

pub struct Ecb<C: BlockCipher, P: Padder<C>> {
    cipher: C,
    padder: P,
}

impl<C, P> BlockMode<C, P> for Ecb<C, P>
where
    C: BlockCipher,
    P: Padder<C>,
{
    fn new(cipher: C, padder: P) -> Self {
        Ecb { cipher, padder }
    }

    fn encrypt(&mut self, plaintext: UnpaddedBytes) -> Vec<C::Block> {
        let ciphertext_blocks = self
            .padder
            .pad(plaintext)
            .iter()
            .map(|plaintext_block| self.cipher.encrypt_block(plaintext_block))
            .collect();

        ciphertext_blocks
    }

    fn decrypt(&mut self, ciphertext: Vec<C::Block>) -> UnpaddedBytes {
        let plaintext_blocks = ciphertext
            .iter()
            .map(|ciphertext_block| self.cipher.decrypt_block(ciphertext_block))
            .collect();

        self.padder.unpad(plaintext_blocks)
    }
}
