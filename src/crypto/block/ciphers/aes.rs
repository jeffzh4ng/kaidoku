use generic_array::typenum;

use crate::crypto::stream::VernamCipher;
use crate::crypto::stream::VernamCipherError;

use super::Block;
use super::BlockCipher;

enum KeyLength {
    Length128,
    Length192,
    Length256,
}

struct Aes {
    key: Vec<u8>,
    key_length: KeyLength,
}

impl BlockCipher<typenum::U128> for Aes {
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

        Aes { key, key_length }
    }

    fn encrypt_block(&self, block: Block<typenum::U128>) -> Block<typenum::U128> {
        let mut encrypted_block = block;

        let rounds = match self.key_length {
            KeyLength::Length128 => 10,
            KeyLength::Length192 => 12,
            KeyLength::Length256 => 14,
        };

        let round_keys = self.key_expansion(&self.key);
        encrypted_block = self.add_round_key(encrypted_block, round_keys[0]);

        // final round (no mix cols) comes after looping
        for round in 0..rounds - 1 {
            encrypted_block = self.sub_bytes(encrypted_block);
            encrypted_block = self.shift_rows(encrypted_block);
            encrypted_block = self.mix_cols(encrypted_block);
            encrypted_block = self.add_round_key(encrypted_block, round_keys[round]);
        }

        encrypted_block = self.sub_bytes(encrypted_block);
        encrypted_block = self.shift_rows(encrypted_block);
        encrypted_block = self.add_round_key(encrypted_block, round_keys[10]);

        encrypted_block
    }

    fn decrypt_block(&self, block: Block<typenum::U128>) -> Block<typenum::U128> {
        todo!()
    }
}

impl Aes {
    fn key_expansion(&self, key: &Vec<u8>) -> Vec<Block<typenum::U128>> {
        todo!()
    }

    // TODO: are round keys always 128 bits?
    fn add_round_key(
        &self,
        input: Block<typenum::U128>,
        key: Block<typenum::U128>,
    ) -> Block<typenum::U128> {
        let a = input.into_iter();
        let b = key.into_iter();
        let xor_cipher = VernamCipher::new(a, b);

        let output = xor_cipher
            .collect::<Result<Vec<u8>, VernamCipherError>>()
            .unwrap(); // SAFETY: VermamCipherError only contains unequal input length, which can't happen since both input and key are typed with typenum::U128

        output.into_iter().collect()
    }

    fn sub_bytes(&self, input: Block<typenum::U128>) -> Block<typenum::U128> {
        let mut output = input.clone();

        for i in 0..input.len() {
            output[i] = SBOX[input[i] as usize];
        }

        output
    }

    // shifting aka *rotation*
    fn shift_rows(&self, input: Block<typenum::U128>) -> Block<typenum::U128> {
        let mut output = input.clone();

        // row 2 << 1
        let temp = output[4];
        output[4] = output[5];
        output[5] = output[6];
        output[6] = output[7];
        output[7] = temp;

        // row 3 << 2
        let (temp_one, temp_two) = (output[8], output[9]);

        output[8] = output[10];
        output[9] = output[11];
        output[10] = temp_one;
        output[11] = temp_two;

        // row 4 << 3
        let temp = output[15];
        output[15] = output[14];
        output[14] = output[13];
        output[13] = output[12];
        output[12] = temp;

        output
    }

    fn mix_cols(&self, input: Block<typenum::U128>) -> Block<typenum::U128> {
        // for col in 0..4 {
        //     for i in 0..4 {}
        // }
        todo!()
    }
}

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foo() {
        assert_eq!(1, 1);
    }
}
