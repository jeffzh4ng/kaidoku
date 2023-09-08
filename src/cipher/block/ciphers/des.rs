use generic_array::{
    typenum::{U4, U6, U8},
    GenericArray,
};

use crate::cipher::{
    block::Block,
    stream::{VernamCipher, VernamCipherError},
};

use super::BlockCipher;

// Des implements BlockCipher for the Data Encryption Standard (DES) as defined
// in the U.S. Federal Information Processing Standards Publication 46-3
pub struct Des {
    key: [u8; 64],
}

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
        // 0. generate round keys
        let round_keys = [0u64; 16]; // sixteen 48 bit keys packed into u64s
        let round_keys = self.key_expansion();

        // 1. initial permutation, which is undone by final permutation at the end
        // of the routine. These have no cryptography significance, rather,
        // they were included to facilitate loading blocks in and out of
        // mid 1970's 8-bit based hardware.
        let permuted_block = self.initial_permutation(block);

        let mut left = permuted_block.into_iter().take(4).collect();
        let mut right = permuted_block.into_iter().take(4).collect();

        // 2. apply the round function 16 times
        for r in 0..=16 {
            // apply f to right with k_i
            let pseudo_key = self.f(right, round_keys[r]);

            // xor the pseudo key with left
            let temp = right;
            let xor_cipher = VernamCipher::new(left.into_iter(), pseudo_key.into_iter());
            let output = xor_cipher
                .collect::<Result<Vec<u8>, VernamCipherError>>()
                .unwrap();

            // swap
            right = output;
            left = temp;
        }

        let final_block = left.append(&mut right);
        let inverted_permuted_block = self.final_permutation(block);

        todo!()
    }

    fn decrypt_block(&self, block: Block<U8>) -> crate::cipher::block::Block<U8> {
        todo!()
    }
}

impl Des {
    fn key_expansion(&self) -> Vec<Block<U6>> {
        todo!()
    }

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
            // output[i] = PC2[i] as usize;
        }

        output
    }

    fn initial_permutation(&self, block: Block<U8>) -> Block<U8> {
        let mut output = [0u8; 64];

        for (i, _) in block.into_iter().enumerate() {
            output[i] = block[IP[i] as usize];
        }

        GenericArray::clone_from_slice(&output)
    }

    fn final_permutation(&self, block: Block<U8>) -> Block<U8> {
        let mut output = [0u8; 64];

        for i in 0..block.len() {
            output[i] = block[FP[i] as usize];
        }

        GenericArray::clone_from_slice(&output)
    }

    fn f(&self, right: Block<U4>, round_key: Block<U6>) -> Block<U4> {
        // 1. expansion (32->48)
        let mut expanded_right = [0u8; 48];
        for i in 0..right.len() {
            expanded_right[i] = E[right[i] as usize];
        }

        // 2. add round key
        let xor_cipher = VernamCipher::new(expanded_right.into_iter(), round_key.into_iter());
        let result = xor_cipher
            .collect::<Result<Vec<u8>, VernamCipherError>>()
            .unwrap(); // TODO: safety, or encode lengths to avoid returning Result

        // 3. substitution

        // 4. permutation
        let mut permuted_block = [0u8; 32];
        for i in 0..48 {
            permuted_block[i] = P[substituded_block[i] as usize]
        }

        GenericArray::clone_from_slice(&permuted_block)
    }
}

const SHIFTS: [u8; 16] = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1];

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

#[rustfmt::skip]
const IP: [u8; 64] = [
    58,	50,	42,	34,	26,	18,	10,	2,
    60,	52,	44,	36,	28,	20,	12,	4,
    62,	54,	46,	38,	30,	22,	14,	6,
    64,	56,	48,	40,	32,	24,	16,	8,
    57,	49,	41,	33,	25,	17,	9,	1,
    59,	51,	43,	35,	27,	19,	11,	3,
    61,	53,	45,	37,	29,	21,	13,	5,
    63,	55,	47,	39,	31,	23,	15,	7,
];

#[rustfmt::skip]

const FP: [u8; 64] = [
    40,	8,	48,	16,	56,	24,	64,	32,
    39,	7,	47,	15,	55,	23,	63,	31,
    38,	6,	46,	14,	54,	22,	62,	30,
    37,	5,	45,	13,	53,	21,	61,	29,
    36,	4,	44,	12,	52,	20,	60,	28,
    35,	3,	43,	11,	51,	19,	59,	27,
    34,	2,	42,	10,	50,	18,	58,	26,
    33,	1,	41,	9,	49,	17,	57,	25,
];

#[rustfmt::skip]
const E: [u8; 48] = [
    32,	1,	2,	3,	4,	5,
    4,	5,	6,	7,	8,	9,
    8,	9,	10,	11,	12,	13,
    12,	13,	14,	15,	16,	17,
    16,	17,	18,	19,	20,	21,
    20,	21,	22,	23,	24,	25,
    24,	25,	26,	27,	28,	29,
    28,	29,	30,	31,	32,	1,
];

#[rustfmt::skip]
const P: [u8; 32] = [
    16,	7,	20,	21,	29,	12,	28,	17,
    1,	15,	23,	26,	5,	18,	31,	10,
    2,	8,	24,	14,	32,	27,	3,	9,
    19,	13,	30,	6,	22,	11,	4,	25,
];
