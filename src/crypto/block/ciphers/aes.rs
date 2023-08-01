use std::marker;

use generic_array::ArrayLength;

use super::Block;
use super::BlockCipher;

enum KeyLength {
    Length128,
    Length192,
    Length256,
}

struct Aes<N: ArrayLength<u8>> {
    key_length: KeyLength,
    _marker: marker::PhantomData<N>,
}

impl<N: ArrayLength<u8>> BlockCipher<N> for Aes<N> {
    fn new(key: Vec<u8>) -> Self {
        let key_length = match key.len() {
            16 => KeyLength::Length128,
            24 => KeyLength::Length192,
            32 => KeyLength::Length256,
            _ => {
                // error out
                todo!()
            }
        };

        Aes {
            key_length,
            _marker: marker::PhantomData,
        }
    }

    fn encrypt_block(&self, block: Block<N>) -> Block<N> {
        let round_keys = self.key_expansion(self.key);

        for round in 1..10 {
            self.sub_bytes(block);
            self.shift_rows(block);
            self.mix_cols(block);
            self.add_round_key(block, round_keys[round]);
        }

        self.sub_bytes(block);
        self.shift_rows(block);
        self.add_round_key(block, round_keys[10]);

        todo!()
    }

    fn decrypt_block(&self, block: Block<N>) -> Block<N> {
        todo!()
    }
}

impl<N: ArrayLength<u8>> Aes<N> {
    fn key_expansion(&self, key: Block<N>) -> Vec<Block<N>> {
        todo!()
    }
    fn sub_bytes(&self, block: Block<N>) {}
    fn shift_rows(&self, block: Block<N>) {}
    fn mix_cols(&self, block: Block<N>) {}
    fn add_round_key(&self, block: Block<N>, key: Block<N>) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foo() {
        assert_eq!(1, 1);
    }
}
