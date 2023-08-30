use std::marker;

use generic_array::{ArrayLength, GenericArray};
use rand::RngCore;

use super::BlockMode;
use crate::cipher::{
    block::{ciphers::BlockCipher, pads::Padder},
    stream::{VernamCipher, VernamCipherError},
};

struct Cbc<N, R, C, P>
where
    N: ArrayLength<u8>,
    R: RngCore,
    C: BlockCipher<N>,
    P: Padder<N>,
{
    rng: R,
    cipher: C,
    padder: P,
    _marker: marker::PhantomData<N>, // required since N ties C and P together without being used directly
}

impl<N, R, C, P> Cbc<N, R, C, P>
where
    N: ArrayLength<u8>,
    R: RngCore,
    C: BlockCipher<N>,
    P: Padder<N>,
{
    pub fn new(rng: R, cipher: C, padder: P) -> Self {
        Cbc {
            rng,
            cipher,
            padder,
            _marker: marker::PhantomData,
        }
    }
}

impl<N, R, C, P> BlockMode<N, C, P> for Cbc<N, R, C, P>
where
    N: ArrayLength<u8>,
    R: RngCore,
    C: BlockCipher<N>,
    P: Padder<N>,
{
    fn encrypt(&mut self, plaintext: Vec<u8>) -> Vec<u8> {
        let mut iv = vec![0u8; N::to_usize()];
        self.rng.fill_bytes(iv.as_mut_slice());
        let mut prev_ciphertext = GenericArray::clone_from_slice(iv.as_slice());

        let ciphertext_blocks = self
            .padder
            .pad(plaintext)
            .into_iter()
            .map(|plaintext_block| {
                let a = prev_ciphertext.clone().into_iter();
                let b = plaintext_block.into_iter();
                let xor = VernamCipher::new(b, a)
                    .collect::<Result<Vec<u8>, VernamCipherError>>()
                    .unwrap(); // TODO: possibly change error type or provide SAFETY annotation

                let encrypted_block = self
                    .cipher
                    .encrypt_block(GenericArray::clone_from_slice(&xor));
                prev_ciphertext = encrypted_block.clone();

                encrypted_block
            })
            .flat_map(|b| b.as_slice().to_vec())
            .collect();

        ciphertext_blocks
    }

    fn decrypt(&mut self, _ciphertext: Vec<u8>) -> Vec<u8> {
        unimplemented!()

        // let mut prev_ciphertext = GenericArray::default();
        // prev_ciphertext.copy_from_slice(&self.iv);

        // let plaintext_blocks = ciphertext
        //     .chunks_exact(N::to_usize())
        //     .map(|chunk| GenericArray::clone_from_slice(chunk))
        //     .map(|b| {
        //         let diffused_plaintext_block = self.cipher.decrypt_block(b);
        //         let undiffused_plaintext_block = VernamCipher::new(
        //             diffused_plaintext_block.clone().into_iter(),
        //             prev_ciphertext.clone().into_iter(),
        //         )
        //         .collect::<Result<Vec<u8>, VernamCipherError>>()
        //         .unwrap();

        //         prev_ciphertext = b;

        //         undiffused_plaintext_block
        //     })
        //     .flat_map(|plaintext_block| plaintext_block)
        //     .collect();

        // plaintext_blocks
    }
}

#[cfg(test)]
mod tests {
    use rand::SeedableRng;

    use super::*;
    use crate::{
        cipher::block::{ciphers, pads},
        rng::MT,
    };

    #[test]
    fn test_encrypt_one_block() {
        let seed = 1131464071u32;
        let rng = MT::from_seed(seed.to_be_bytes());

        let key = b"YELLOW SUBMARINE";
        let cipher = ciphers::aes::Aes::new(key.to_vec());
        let padder = pads::pkcs7::Pkcs7::new();

        let mut cbc = Cbc::new(rng, cipher, padder);

        let plaintext = b"ABCDEFGHIJKLMNOP";
        let encrypted = cbc.encrypt(plaintext.to_vec());

        println!("{:?}", encrypted);
        // #[rustfmt::skip]
        // let expected_output = [
        //     0xf5, 0x45, 0xc0, 0x06,
        //     0x06, 0x91, 0x26, 0xd9,
        //     0xc0, 0xf9, 0x3f, 0xa7,
        //     0xdd, 0x89, 0xab, 0x98,
        //     // encrypted padding (entire block)
        //     0x60, 0xfa, 0x36, 0x70,
        //     0x7e, 0x45, 0xf4, 0x99,
        //     0xdb, 0xa0, 0xf2, 0x5b,
        //     0x92, 0x23, 0x01, 0xa5,
        // ];

        // assert_eq!(encrypted, expected_output);
    }
}
