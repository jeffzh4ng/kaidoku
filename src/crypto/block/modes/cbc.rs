use std::marker;

use generic_array::{ArrayLength, GenericArray};

use super::BlockMode;
use crate::crypto::{
    block::{ciphers::BlockCipher, pads::Padder, Block},
    stream::{VernamCipher, VernamCipherError},
};

struct Cbc<N, C, P>
where
    N: ArrayLength<u8>,
    C: BlockCipher<N>,
    P: Padder<N>,
{
    iv: Vec<u8>,
    cipher: C,
    padder: P,
    _marker: marker::PhantomData<N>,
}

impl<N, C, P> BlockMode<N, C, P> for Cbc<N, C, P>
where
    N: ArrayLength<u8>,
    C: BlockCipher<N>,
    P: Padder<N>,
{
    fn new(cipher: C, padder: P) -> Self {
        todo!()
    }

    fn encrypt(&mut self, plaintext: Vec<u8>) -> Vec<Block<N>> {
        let mut prev_ciphertext = GenericArray::default(); // FIXME: naming. should be called block as well
        prev_ciphertext.copy_from_slice(&self.iv);

        let ciphertext_blocks = self
            .padder
            .pad(plaintext)
            .iter()
            .map(|plaintext_block| {
                let plaintext_block = plaintext_block.clone().into_iter(); // FIXME: cloning GenericArray to satisfy borrow checker on VernamCipher
                let prev_ciphertext_block = prev_ciphertext.into_iter();
                let xord_plaintext_block =
                    VernamCipher::new(plaintext_block, prev_ciphertext_block)
                        .collect::<Result<Vec<u8>, VernamCipherError>>()
                        .unwrap(); // TODO: possibly change error type or provide SAFETY annotation

                let mut xord_plaintext_generic_block: Block<N> = GenericArray::default(); // TODO: look into generic_array's API, see if there's a more idiomatic way of doing this
                xord_plaintext_generic_block.copy_from_slice(&xord_plaintext_block);

                let ciphertext_block = self.cipher.encrypt_block(xord_plaintext_generic_block);
                prev_ciphertext = ciphertext_block;

                ciphertext_block
            })
            .collect();

        ciphertext_blocks
    }

    fn decrypt(&mut self, cipher_text: Vec<Block<N>>) -> Vec<u8> {
        let mut prev_ciphertext = GenericArray::default();
        prev_ciphertext.copy_from_slice(&self.iv);

        let plaintext_blocks = cipher_text
            .into_iter()
            .map(|b| {
                let diffused_plaintext_block = self.cipher.decrypt_block(b);
                let undiffused_plaintext_block = VernamCipher::new(
                    diffused_plaintext_block.clone().into_iter(),
                    prev_ciphertext.clone().into_iter(),
                )
                .collect::<Result<Vec<u8>, VernamCipherError>>()
                .unwrap();

                prev_ciphertext = b;

                undiffused_plaintext_block
            })
            .flat_map(|plaintext_block| plaintext_block)
            .collect();

        plaintext_blocks
    }
}
