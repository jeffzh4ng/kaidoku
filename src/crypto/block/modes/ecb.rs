use super::super::ciphers::BlockCipher;
use super::super::pads::Padder;
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
        Ecb { cipher, padder } // cipher is now part of the ECB struct
    }

    fn encrypt(&mut self, plaintext: Vec<C::Block>) -> Vec<C::Block> {
        let padded_plaintext = self.padder.pad(plaintext);
        for block in padded_plaintext {
            // self.cipher.encrypt_block(&mut block);
        }
        todo!()
    }

    fn decrypt(&mut self, ciphertext: Vec<C::Block>) -> Vec<C::Block> {
        let mut plaintext = Vec::with_capacity(ciphertext.len());

        for block in ciphertext {
            // let mut decrypted = *block;
            // self.cipher.decrypt_block(&mut block);
            // plaintext.push(decrypted);
        }
        plaintext
    }
}
