use generic_array::typenum::U8;

use crate::cipher::block::Block;

use super::BlockCipher;

// Des implements BlockCipher for the Data Encryption Standard (DES) as defined
// in the U.S. Federal Information Processing Standards Publication 46-3
pub struct Des {
    key: [u8; 64],
}

const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

impl BlockCipher<U8> for Des {
    fn new(key: Vec<u8>) -> Self {
        if key.len() != 56 {
            todo!()
        }

        Des {
            key: key.try_into().unwrap(),
        }
    }

    fn encrypt_block(&self, block: Block<U8>) -> Block<U8> {
        let round_keys = [0u64; 16]; // sixteen 48 bit keys packed into u64s

        let key = self.permuted_choice_one(self.key);
        for key_round in 0..=16 {
            let mut key_left: u32 = key.into_iter().take(28).collect(); // 28 bit half packed into u32
            let mut key_right: u32 = key.into_iter().take(28).collect(); // 28 bit half packed into u32

            key_left = key_left.rotate_left(SHIFTS[key_round] as u32);
            key_right = key_right.rotate_left(SHIFTS[key_round] as u32);

            let round_key = self.permuted_choice_two(key_left, key_right);
        }

        let left = block.into_iter().take(4);
        let right = block.into_iter().take(4);

        for encrypt_round in 0..=16 {
            let temp = right;
            // substitution

            // permutation
        }

        todo!()
    }

    fn decrypt_block(&self, block: Block<U8>) -> crate::cipher::block::Block<U8> {
        todo!()
    }
}

impl Des {
    fn permuted_choice_one(&self, key: [u8; 64]) -> [u8; 56] {
        let mut output = [0u8; 56];

        for i in 0..=56 {
            output[i] = key[PC1[i] as usize];
        }

        output
    }

    fn permuted_choice_two(&self, key_left: u32, key_right: u32) -> [u8; 48] {
        let mut output = [0u8; 48];

        // 24 vs 28?

        for i in 0..=48 {
            output[i] = PC2[i] as usize;
        }

        output
    }
}

#[rustfmt::skip]
const PC1: [u8; 56] = [
    57, 49, 41, 33, 25, 17, 9,
    1, 58, 50, 42, 34, 26, 18,
    10, 2, 59, 51, 43, 35, 27,
    19, 11, 3, 60, 52, 44, 36,

    63, 55, 47, 39, 31, 23, 15,
    7, 62, 54, 46, 38, 30, 22,
    14, 6, 61, 53, 45, 37, 29,
    21, 13, 5, 28, 20, 12, 4,
];

#[rustfmt::skip]
const PC2: [u8; 48] = [
    14, 17, 11, 24, 1, 5,
    3, 28, 15, 6, 21, 10,
    23, 19, 12, 4, 26, 8,
    16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
];
