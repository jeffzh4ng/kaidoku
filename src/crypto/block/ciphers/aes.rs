use generic_array::typenum;
use generic_array::GenericArray;

use crate::crypto::stream::VernamCipher;
use crate::crypto::stream::VernamCipherError;

use super::Block;
use super::BlockCipher;

enum KeyLength {
    Length128,
    Length192,
    Length256,
}

// AES is based on a design principle known as a substitution–permutation network,
// and is efficient in both software and hardware. Unlike its predecessor DES,
// AES does not use a Feistel network. AES is a variant of Rijndael, with a fixed
// block size of 128 bits, and a key size of 128, 192, or 256 bits.

// By contrast, Rijndael per se is specified with block and key sizes that may be
// any multiple of 32 bits, with a minimum of 128 and a maximum of 256 bits. Most
// AES calculations are done in a particular finite field.

// AES operates on a 4 × 4 column-major order array of 16 bytes b0, b1, ..., b15
// termed the state.

// =============================================================================
// High-level description of the algorithm
// =============================================================================
// 1. KeyExpansion – round keys are derived from the cipher key using the AES key
// schedule. AES requires a separate 128-bit round key block for each round plus one more.

// 2. Initial round key addition:
// AddRoundKey – each byte of the state is combined with a byte of the round key
//               using bitwise xor.

// 3. Rounds (9, 11 or 13)
// ---1. SubBytes – a non-linear substitution step where each byte is replaced
//                  with another according to a lookup table.
// ---2. ShiftRows – a transposition step where the last three rows of the state
//                   are shifted cyclically a certain number of steps.
// ---3. MixColumns – a linear mixing operation which operates on the columns of
//                    the state, combining the four bytes in each column.
// ---4. AddRoundKey

// 4. Final round (making 10, 12 or 14 rounds in total):
// ---1. SubBytes
// ---2. ShiftRows
// ---3. AddRoundKey
struct Aes {
    key: Vec<u8>,
    key_length: KeyLength,
}

impl BlockCipher<typenum::U16> for Aes {
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

    fn encrypt_block(&self, block: Block<typenum::U16>) -> Block<typenum::U16> {
        // 1. key expansion
        let rounds = match self.key_length {
            KeyLength::Length128 => 10,
            KeyLength::Length192 => 12,
            KeyLength::Length256 => 14,
        };
        let round_keys = self.key_expansion(&self.key, rounds);

        // 2. initial round key addition
        let mut encrypted_block = block;
        encrypted_block = self.add_round_key(encrypted_block, round_keys[0]);

        // 3. 9, 11, or 13 rounds
        for round in 0..rounds - 1 {
            encrypted_block = self.sub_bytes(encrypted_block);
            encrypted_block = self.shift_rows(encrypted_block);
            encrypted_block = self.mix_cols(encrypted_block);
            // using round + 1 as index since the 0th roudn key was used to XOR the plaintext
            encrypted_block = self.add_round_key(encrypted_block, round_keys[round + 1]);
        }

        // 4. final round (making 10, 12, or 14 rounds total)
        encrypted_block = self.sub_bytes(encrypted_block);
        encrypted_block = self.shift_rows(encrypted_block);
        encrypted_block = self.add_round_key(encrypted_block, round_keys[10]);

        encrypted_block
    }

    fn decrypt_block(&self, block: Block<typenum::U16>) -> Block<typenum::U16> {
        todo!()
    }
}

impl Aes {
    // AES uses a key schedule to expand a short key into a number of separate
    // round keys. The three AES variants have a different number of rounds.
    // Each variant requires a separate 128-bit round key for each round plus one
    // more. The key schedule produces the needed round keys from the initial key.

    // see more: https://en.wikipedia.org/wiki/AES_key_schedule
    fn key_expansion(&self, key: &Vec<u8>, rounds: usize) -> Vec<Block<typenum::U16>> {
        // let mut round_keys = Vec::new();

        // let key_words = self.key_words(key);

        // for i in 0..rounds + 1 {
        //     // rounds + 1 keys required
        //     round_keys.push(GenericArray::from_slice(&[0u8; 16]));
        // }

        // 1. rotword

        // 2. subword

        // 3. rcon

        todo!()
    }

    fn key_words(&self, key: &Vec<u8>) -> [u32; 4] {
        [
            u32::from_be_bytes([key[0x0], key[0x1], key[0x2], key[0x3]]),
            u32::from_be_bytes([key[0x4], key[0x5], key[0x6], key[0x7]]),
            u32::from_be_bytes([key[0x8], key[0x9], key[0xa], key[0xb]]),
            u32::from_be_bytes([key[0xc], key[0xd], key[0xe], key[0xf]]),
        ]
    }

    fn add_round_key(
        &self,
        input: Block<typenum::U16>,
        key: Block<typenum::U16>,
    ) -> Block<typenum::U16> {
        let a = input.into_iter();
        let b = key.into_iter();
        let xor_cipher = VernamCipher::new(a, b);

        let output = xor_cipher
            .collect::<Result<Vec<u8>, VernamCipherError>>()
            .unwrap(); // SAFETY: VermamCipherError only contains unequal input length, which can't happen since both input and key are typed with typenum::U16

        output.into_iter().collect()
    }

    // In the SubBytes step, each byte, a_{i,j} in the state array is replaced with
    // a SubByte S(a_{i,j}) using an 8-bit substitution box. Note that before round
    // 0, the state array is simply the plaintext/input.

    // ***This operation provides the non-linearity in the cipher.***

    // The S-box used is derived from the multiplicative inverse over GF(2^8), known
    // to have good non-linearity properties. To avoid attacks based on simple
    // algebraic properties, the S-box is constructed by combining
    // 1. the inverse function
    // 2. invertible affine transformation

    // The S-box is also chosen to avoid any fixed points (and so is a derangement),
    // i.e., S(a_{i,j}) != a_{i,j}
    // and also any opposite fixed points, i.e. S(a_{i,j}) XOR a_{i,j} != FF_{16}
    fn sub_bytes(&self, input: Block<typenum::U16>) -> Block<typenum::U16> {
        let mut output = input;

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

// The S-box maps an 8-bit input, c, to an 8-bit output, s = S(c). Both the input and output are interpreted as polynomials over GF(2). First, the input is mapped to its multiplicative inverse in GF(2^8) = GF(2) [x]/(x8 + x4 + x3 + x + 1), Rijndael's finite field. Zero, as the identity, is mapped to itself. This transformation is known as the Nyberg S-box after its inventor Kaisa Nyberg. The multiplicative inverse is then transformed using the following affine transformation:
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

const fn gf_mult() {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sub_bytes() {
        let aes = Aes {
            key: Vec::new(),
            key_length: KeyLength::Length128,
        };

        let plaintext = *b"The quick brown ";
        let plaintext_block = generic_array::GenericArray::clone_from_slice(&plaintext);

        let plaintext_subbed_block = aes.sub_bytes(plaintext_block);
        let actual_output = plaintext_subbed_block.as_slice();
        let expected_output: [u8; 16] = [
            0x20, 0x45, 0x4d, 0xb7, 0xa3, 0x9d, 0xf9, 0xfb, 0x7f, 0xb7, 0xaa, 0x40, 0xa8, 0xf5,
            0x9f, 0xb7,
        ];

        assert_eq!(actual_output, expected_output);
    }
}
