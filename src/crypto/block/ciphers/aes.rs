use super::BlockCipher;

pub struct Aes128 {
    key: [u8; 16],
}

impl BlockCipher for Aes128 {
    type Block = [u8; 16]; // 16 bytes = 128 bits
    type Key = [u8; 16]; // 16 bytes = 128 bits

    fn new(key: Self::Key) -> Self {
        Aes128 { key }
    }

    fn encrypt_block(&self, block: &mut Self::Block) {
        let round_keys = self.key_expansion(&self.key);

        for round in 1..10 {
            self.sub_bytes(block);
            self.shift_rows(block);
            self.mix_cols(block);
            self.add_round_key(block, &round_keys[round]);
        }

        self.sub_bytes(block);
        self.shift_rows(block);
        self.add_round_key(block, &round_keys[10]);

        todo!()
    }

    fn decrypt_block(&self, block: &mut Self::Block) {
        todo!()
    }
}

impl Aes128 {
    fn key_expansion(&self, key: &[u8; 16]) -> Vec<[u8; 16]> {
        todo!()
    }
    fn sub_bytes(&self, block: &mut [u8; 16]) {}
    fn shift_rows(&self, block: &mut [u8; 16]) {}
    fn mix_cols(&self, block: &mut [u8; 16]) {}
    fn add_round_key(&self, block: &mut [u8; 16], key: &[u8; 16]) {}
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foo() {
        assert_eq!(1, 1);
    }
}
