use std::marker;

use generic_array::{ArrayLength, GenericArray};

use super::super::ciphers::BlockCipher;
use super::super::pads::Padder;
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

impl<N, C, P> Ecb<N, C, P>
where
    N: ArrayLength<u8>,
    C: BlockCipher<N>,
    P: Padder<N>,
{
    pub fn new(cipher: C, padder: P) -> Self {
        Ecb {
            cipher,
            padder,
            _marker: marker::PhantomData,
        }
    }
}

impl<N, C, P> BlockMode<N, C, P> for Ecb<N, C, P>
where
    N: ArrayLength<u8>,
    C: BlockCipher<N>,
    P: Padder<N>,
{
    fn encrypt(&mut self, plaintext: Vec<u8>) -> Vec<u8> {
        let ciphertext_blocks = self
            .padder
            .pad(plaintext)
            .into_iter()
            .map(|plaintext_block| self.cipher.encrypt_block(plaintext_block))
            .flat_map(|b| b.as_slice().to_vec())
            .collect();

        ciphertext_blocks
    }

    fn decrypt(&mut self, ciphertext: Vec<u8>) -> Vec<u8> {
        let plaintext_blocks = ciphertext
            .chunks_exact(N::to_usize()) // TODO: what do if input has remainder
            .map(|chunk| GenericArray::clone_from_slice(chunk))
            .map(|ciphertext_block| self.cipher.decrypt_block(ciphertext_block))
            .collect();

        self.padder.unpad(plaintext_blocks)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::cipher::block::{ciphers, pads};

    #[test]
    fn test_encrypt_half_block() {
        let key = b"YELLOW SUBMARINE";
        let cipher = ciphers::aes::Aes::new(key.to_vec());
        let padder = pads::pkcs7::Pkcs7::new();
        let mut ecb = Ecb::new(cipher, padder);

        let plaintext = b"ABCDEFGH";
        let encrypted = ecb.encrypt(plaintext.to_vec());

        #[rustfmt::skip]
        let expected_output = [
            0x11, 0x38, 0xF7, 0x44,
            0xA4, 0x1E, 0x80, 0xA5,
            0xC1, 0x84, 0xAC, 0xF0,
            0x2F, 0x6A, 0xD8, 0x22    
        ];
        assert_eq!(encrypted, expected_output);
    }

    #[test]
    fn test_encrypt_one_block() {
        let key = b"YELLOW SUBMARINE";
        let cipher = ciphers::aes::Aes::new(key.to_vec());
        let padder = pads::pkcs7::Pkcs7::new();
        let mut ecb = Ecb::new(cipher, padder);

        let plaintext = b"ABCDEFGHIJKLMNOP";
        let encrypted = ecb.encrypt(plaintext.to_vec());
        #[rustfmt::skip]
        let expected_output = [
            0xf5, 0x45, 0xc0, 0x06,
            0x06, 0x91, 0x26, 0xd9,
            0xc0, 0xf9, 0x3f, 0xa7,
            0xdd, 0x89, 0xab, 0x98,
            // encrypted padding (entire block)
            0x60, 0xfa, 0x36, 0x70,
            0x7e, 0x45, 0xf4, 0x99,
            0xdb, 0xa0, 0xf2, 0x5b,
            0x92, 0x23, 0x01, 0xa5,
        ];

        assert_eq!(encrypted, expected_output);
    }

    #[test]
    fn test_encrypt_two_blocks() {
        let key = b"YELLOW SUBMARINE";
        let cipher = ciphers::aes::Aes::new(key.to_vec());
        let padder = pads::pkcs7::Pkcs7::new();
        let mut ecb = Ecb::new(cipher, padder);

        let plaintext = b"ABCDEFGHIJKLMNOPABCDEFGHIJKLMNOP";
        let encrypted = ecb.encrypt(plaintext.to_vec());
        #[rustfmt::skip]
        let expected_output = [
            // block one
            0xf5, 0x45, 0xc0, 0x06,
            0x06, 0x91, 0x26, 0xd9,
            0xc0, 0xf9, 0x3f, 0xa7,
            0xdd, 0x89, 0xab, 0x98,
            // block two
            0xf5, 0x45, 0xc0, 0x06,
            0x06, 0x91, 0x26, 0xd9,
            0xc0, 0xf9, 0x3f, 0xa7,
            0xdd, 0x89, 0xab, 0x98,
            // encrypted padding (entire block)
            0x60, 0xfa, 0x36, 0x70,
            0x7e, 0x45, 0xf4, 0x99,
            0xdb, 0xa0, 0xf2, 0x5b,
            0x92, 0x23, 0x01, 0xa5,
        ];

        assert_eq!(encrypted, expected_output);
    }
}
