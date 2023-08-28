use generic_array::typenum::U16;
use generic_array::GenericArray;

use crate::crypto::stream::VernamCipher;
use crate::crypto::stream::VernamCipherError;

use super::Block;
use super::BlockCipher;

#[derive(Copy, Clone)]
enum KeyLength {
    Length128 = 128,
    Length192 = 192,
    Length256 = 256,
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

// =============================================================================
// Algorithm security
// =============================================================================

// According to NSA,
// The design and strength of all key lengths of the AES algorithm (i.e., 128, 192 and 256)
// are sufficient to protect classified information up to the SECRET level.
// TOP SECRET information will require use of either the 192 or 256 key lengths.
// The implementation of AES in products intended to protect national security
// systems and/or information must be reviewed and certified by NSA prior to their
// acquisition and use.

// By 2006, the best known attacks were on 7 rounds for 128-bit keys, 8 rounds
// for 192-bit keys, and 9 rounds for 256-bit keys.
// see more: https://www.schneier.com/academic/archives/2001/01/improved_cryptanalys.html

struct Aes {
    key: Vec<u8>,
    key_length: KeyLength,
}

impl BlockCipher<U16> for Aes {
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

    fn encrypt_block(&self, block: Block<U16>) -> Block<U16> {
        // 1. key expansion
        let rounds = match self.key_length {
            KeyLength::Length128 => 10,
            KeyLength::Length192 => 12,
            KeyLength::Length256 => 14,
        };
        let round_keys = self.key_expansion(rounds);

        // 2. initial round key addition
        let mut encrypted_block = block;
        encrypted_block = self.add_round_key(encrypted_block, round_keys[0]);

        // 3. round ranges from 1..[9, 11, or 13]
        for round in 1..rounds {
            encrypted_block = self.sub_bytes(encrypted_block);
            encrypted_block = self.shift_rows(encrypted_block);
            encrypted_block = self.mix_cols(encrypted_block);
            encrypted_block = self.add_round_key(encrypted_block, round_keys[round]);
        }

        // 4. final round (making 10, 12, or 14 rounds total)
        encrypted_block = self.sub_bytes(encrypted_block);
        encrypted_block = self.shift_rows(encrypted_block);
        encrypted_block = self.add_round_key(encrypted_block, round_keys[rounds]);

        encrypted_block
    }

    fn decrypt_block(&self, block: Block<U16>) -> Block<U16> {
        todo!()
    }
}

impl Aes {
    // AES uses a key schedule to expand a short key into a number of separate
    // round keys. The three AES variants have a different number of rounds.
    // Each variant requires a separate 128-bit round key for each round plus one
    // more. The key schedule produces the needed round keys from the initial key.
    // Using different keys for each round to protect against slide attacks[0]

    // [0]: https://en.wikipedia.org/wiki/Slide_attack

    // see more: https://en.wikipedia.org/wiki/AES_key_schedule
    fn key_expansion(&self, rounds: usize) -> Vec<Block<U16>> {
        let words_per_key_size = self.key_length as usize / 32; // 4, 6, or 8
        let word_length = 4 * (rounds + 1); // because round_keys are always 128 bits, 4*32=128
        let mut u32_words = vec![0; word_length];
        let mut i = 0;

        // 1. K0 is set to the root key
        // so build u32 words from the key's u8s and set them
        while i < words_per_key_size {
            let word = u32::from_be_bytes([
                self.key[i * 4],
                self.key[i * 4 + 1],
                self.key[i * 4 + 2],
                self.key[i * 4 + 3],
            ]);

            u32_words[i] = word;
            i += 1;
        }

        // 2. build 128 bit round keys from K1 -> K10/12/14
        // since the key schedule operates on 32 bit words, we have to gen {4*rounds} words
        let mut prev;
        while i < u32_words.len() {
            prev = u32_words[i - 1];
            if i % words_per_key_size == 0 {
                // TODO why -1?
                prev = self.sub_word(prev.rotate_left(8)) ^ RCON[i / words_per_key_size];
            } else if words_per_key_size > 6 && i % words_per_key_size == 4 {
                prev = self.sub_word(prev);
            }

            u32_words[i] = u32_words[i - words_per_key_size] ^ prev;
            i += 1;
        }

        // 3. coalesce the {4 * rounds} u32 words into 10/12/14 u8 round keys
        let round_key_buffers = u32_words
            .chunks(4) // since round keys are 128 bits
            .map(|chunked_key_words| {
                // Vec::from(u32::to_be_bytes(chunked_key_words))) will not work
                // b/c chunked_key-wirds is a &[u32], so we .iter.flat_map(|&|)
                chunked_key_words
                    .iter()
                    .flat_map(|&word| u32::to_be_bytes(word).to_vec())
                    .collect::<Vec<u8>>()
            })
            .map(|buffered_round_key| {
                GenericArray::<u8, U16>::clone_from_slice(&buffered_round_key)
            })
            .collect();

        round_key_buffers
    }

    fn sub_word(&self, word: u32) -> u32 {
        let mut bytes = u32::to_be_bytes(word);
        for i in 0..bytes.len() {
            bytes[i] = SBOX[bytes[i] as usize]; // SAFETY: u8 will never be larger than 32 bits
        }

        u32::from_be_bytes(bytes)
    }

    // The AddRoundKey step combines a round key with the state with the XOR operation.
    // For each round, a round key is derived from the main key using Rijndael's
    // key schedule; each round key is the same size as the state.
    fn add_round_key(&self, input: Block<U16>, key: Block<U16>) -> Block<U16> {
        let a = input.into_iter();
        let b = key.into_iter();
        let xor_cipher = VernamCipher::new(a, b);

        let output = xor_cipher
            .collect::<Result<Vec<u8>, VernamCipherError>>()
            .unwrap(); // SAFETY: VermamCipherError only contains unequal input length
                       // which can't happen since both input and key are typed with U16

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

    // see more: https://en.wikipedia.org/wiki/Rijndael_S-box
    fn sub_bytes(&self, input: Block<U16>) -> Block<U16> {
        let mut output = input;

        for i in 0..input.len() {
            output[i] = SBOX[input[i] as usize];
        }

        output
    }

    // The ShiftRows step operates on the rows of the state; it cyclically shifts
    // the bytes in each row by a certain offset. For AES, the first row is left
    // unchanged. Each byte of the second row is shifted one to the left.
    // Similarly, the third and fourth rows are shifted by offsets of two and
    // three respectively.

    // In this way, each column of the output state of the ShiftRows step is
    // composed of bytes from each column of the input state. The importance of
    // this step is to avoid the columns being encrypted independently, in which
    // case AES would degenerate into four independent block ciphers.

    fn shift_rows(&self, input: Block<U16>) -> Block<U16> {
        let mut output = input;

        // memory
        // 0  1  2  3
        // 4  5  6  7
        // 8  9  10 11
        // 12 13 14 15

        // logical
        // 0  4  8  12
        // 1  5  9  13
        // 2  6 10  14
        // 3  7 11  15

        // multiplying by 5 allows us to
        // 1. skip over rows (memory) i.e., 4*5%16= 20%16=4. 5*5%16= 25&16=9
        // 2. rotate based on column (memory)
        for i in 0..input.len() {
            output[i] = input[(i * 5) % 16];
        }

        output
    }

    // In the MixColumns step, the four bytes of each column (32 bits) of the state
    // are combined using an invertible linear transformation.Together with ShiftRows,
    // MixColumns provides diffusion in the cipher.

    // see more: https://en.wikipedia.org/wiki/Rijndael_MixColumns
    fn mix_cols(&self, input: Block<U16>) -> Block<U16> {
        let mut output = GenericArray::default();

        for i in 0..4 {
            // logical columns are layed out as rows in memory
            let index_start = i * 4;
            let col = [
                input[index_start],
                input[index_start + 1],
                input[index_start + 2],
                input[index_start + 3],
            ];
            let mixed_col = self.mix_col(col);

            output[index_start..index_start + 4].copy_from_slice(&mixed_col);
        }

        output
    }

    // mix_col mixes a single column 2 state by applying an invertible linear
    // transformation. In particular, the column is used as a vector and is
    // multiplied by the following circulant[0] MDS matrix[1] under Rijndael's finite field.

    // 2 3 1 1
    // 1 2 3 1
    // 1 1 2 3
    // 3 1 1 2

    // This operation is similar to the Hill Cipher[2]

    // [0]: https://en.wikipedia.org/wiki/Circulant_matrix
    // [1]: https://en.wikipedia.org/wiki/MDS_matrix
    // [2]: https://en.wikipedia.org/wiki/Hill_cipher

    fn mix_col(&self, input: [u8; 4]) -> [u8; 4] {
        let mut output = [0u8; 4];

        output[0] =
            self.gf_mult(0x02, input[0]) ^ self.gf_mult(0x03, input[1]) ^ input[2] ^ input[3];
        output[1] =
            input[0] ^ self.gf_mult(0x02, input[1]) ^ self.gf_mult(0x03, input[2]) ^ input[3];
        output[2] =
            input[0] ^ input[1] ^ self.gf_mult(0x02, input[2]) ^ self.gf_mult(0x03, input[3]);
        output[3] =
            self.gf_mult(0x03, input[0]) ^ input[1] ^ input[2] ^ self.gf_mult(0x02, input[3]);

        output
    }

    // gf_mult multiplies two bytes which represent the coefficients of polynomials
    // under GF(2^8) with modulus x^8 + x^4 + x^3 + x + 1, Rijdael's finite field

    // at the start and end of the algorithm, and the start and end of each
    // iteration, this invariant is true: a b + p is the product
    // - this is obviously true when the algorithm starts
    // - and when the algorithm terminates, a or b will be zero so p will contain the product.

    // see more
    // - https://en.wikipedia.org/wiki/Finite_field_arithmetic#Rijndael's_(AES)_finite_field
    // - https://en.wikipedia.org/wiki/Multiplication_algorithm#Russian_peasant_multiplication
    fn gf_mult(&self, mut a: u8, mut b: u8) -> u8 {
        let mut p = 0;

        for _ in 0..8 {
            // 1. if the rightmost bit of b is set, XOR the product p by a.
            //    - this is polynomial addition
            if (b & 0x1) != 0 {
                p ^= a;
            }

            // 2. shift b one bit to the right, discarding the rightmost bit, and
            //    making the leftmost bit have a value of zero
            //    - this divides the polynomial by x, discarding the x0 term.
            b >>= 1;

            // 3. Keep track of whether the leftmost bit of a is set to one
            let carry = (a & 0x80) != 0;

            // 4. shift a one bit to the left, discarding the leftmost bit, and
            //    making the new rightmost bit zero.
            //    - this multiplies the polynomial by x,
            //    - but we still need to take account of carry, the coefficient of x^7
            a <<= 1;

            // 5. if carry had a value of one, XOR a with 0x1b (00011011 in binary).
            //    0x1b corresponds to the irreducible polynomial with the high term
            //    eliminated.
            //    - conceptually, the high term of the irreducible polynomial and
            //      carry add modulo 2 to 0.
            if carry {
                a ^= 0x1b;
            }
        }

        p // p now has the product
    }
}

// The S-box maps an 8-bit input, c, to an 8-bit output, s = S(c).
// Both the input and output are interpreted as polynomials over GF(2).

// 1. First, the input is mapped to its multiplicative inverse in GF(2^8) = GF(2)
// [x]/(x8 + x4 + x3 + x + 1), Rijndael's finite field. Zero, as the identity, is mapped to itself.
// This transformation is known as the Nyberg S-box after its inventor Kaisa Nyberg.

// 2. The multiplicative inverse is then transformed using an affine transformation.
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

const RCON: [u32; 11] = [
    0x00_00_00_00,
    0x01_00_00_00,
    0x02_00_00_00,
    0x04_00_00_00,
    0x08_00_00_00,
    0x10_00_00_00,
    0x20_00_00_00,
    0x40_00_00_00,
    0x80_00_00_00,
    0x1B_00_00_00,
    0x36_00_00_00,
];

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_add_round_key() {
        #[rustfmt::skip]
        let state = [
            0xe1, 0x53, 0x30, 0x22,
            0xb7, 0xdb, 0xf3, 0xa3,
            0x4c, 0xa2, 0x06, 0xd4,
            0x3d, 0x72, 0xc4, 0xdf,
        ];
        let state_input = GenericArray::clone_from_slice(&state);
        let key = *b"abcdefghijklmnop";
        let key_input = GenericArray::clone_from_slice(&key);

        let aes = Aes {
            key: Vec::new(),
            key_length: KeyLength::Length128,
        };

        let actual_output = aes.add_round_key(state_input, key_input);
        #[rustfmt::skip]
        let expected_output = [
            0x80, 0x31, 0x53, 0x46,
            0xd2, 0xbd, 0x94, 0xcb,
            0x25, 0xc8, 0x6d, 0xb8,
            0x50, 0x1c, 0xab, 0xaf,
        ];

        assert_eq!(actual_output.as_slice(), expected_output);
    }

    #[test]
    fn test_sub_bytes() {
        let aes = Aes {
            key: Vec::new(),
            key_length: KeyLength::Length128,
        };

        let plaintext = *b"The quick brown ";
        let plaintext_block = GenericArray::clone_from_slice(&plaintext);

        let actual_output = aes.sub_bytes(plaintext_block);
        #[rustfmt::skip]
        let expected_output: [u8; 16] = [
            0x20, 0x45, 0x4d, 0xb7,
            0xa3, 0x9d, 0xf9, 0xfb,
            0x7f, 0xb7, 0xaa, 0x40,
            0xa8, 0xf5, 0x9f, 0xb7,
        ];

        assert_eq!(actual_output.as_slice(), expected_output);
    }

    #[test]
    fn test_shift_rows() {
        #[rustfmt::skip]
        let input = [
            0x20, 0x45, 0x4d, 0xb7,
            0xa3, 0x9d, 0xf9, 0xfb,
            0x7f, 0xb7, 0xaa, 0x40,
            0xa8, 0xf5, 0x9f, 0xb7,
        ];
        let input_state = GenericArray::clone_from_slice(&input);

        let aes = Aes {
            key: Vec::new(),
            key_length: KeyLength::Length128,
        };

        let actual_output = aes.shift_rows(input_state);
        #[rustfmt::skip]
        let expected_output = [
            0x20, 0x9d, 0xaa, 0xb7,
            0xa3, 0xb7, 0x9f, 0xb7,
            0x7f, 0xf5, 0x4d, 0xfb,
            0xa8, 0x45, 0xf9, 0x40,
        ];

        assert_eq!(actual_output.as_slice(), expected_output);
    }

    #[test]
    fn test_mix_col() {
        let inputs = [
            [0xdb, 0x13, 0x53, 0x45],
            [0xf2, 0x0a, 0x22, 0x5c],
            [0x01, 0x01, 0x01, 0x01],
            [0xc6, 0xc6, 0xc6, 0xc6],
            [0xd4, 0xd4, 0xd4, 0xd5],
            [0x2d, 0x26, 0x31, 0x4c],
        ];
        let aes = Aes {
            key: Vec::new(),
            key_length: KeyLength::Length128,
        };

        let expected_outputs = [
            [0x8e, 0x4d, 0xa1, 0xbc],
            [0x9f, 0xdc, 0x58, 0x9d],
            [0x01, 0x01, 0x01, 0x01],
            [0xc6, 0xc6, 0xc6, 0xc6],
            [0xd5, 0xd5, 0xd7, 0xd6],
            [0x4d, 0x7e, 0xbd, 0xf8],
        ];

        for i in 0..inputs.len() {
            let actual_output = aes.mix_col(inputs[i]);
            assert_eq!(actual_output, expected_outputs[i]);
        }
    }

    #[test]
    fn test_mix_cols() {
        let input = [
            0x20, 0x9d, 0xaa, 0xb7, 0xa3, 0xb7, 0x9f, 0xb7, 0x7f, 0xf5, 0x4d, 0xfb, 0xa8, 0x45,
            0xf9, 0x40,
        ];
        let input_state = GenericArray::clone_from_slice(&input);

        let aes = Aes {
            key: Vec::new(),
            key_length: KeyLength::Length128,
        };

        let actual_output = aes.mix_cols(input_state);
        #[rustfmt::skip]
        let expected_output = [
            0xe1, 0x53, 0x30, 0x22,
            0xb7, 0xdb, 0xf3, 0xa3,
            0x4c, 0xa2, 0x06, 0xd4,
            0x3d, 0x72, 0xc4, 0xdf,
        ];

        assert_eq!(actual_output.as_slice(), expected_output);
    }

    #[test]
    fn encrypt_block() {
        let key = *b"YELLOW SUBMARINE";
        let aes = Aes::new(key.to_vec());

        let plaintext = b"ABCDEFGHIJKLMNOP";
        let plaintext_block = GenericArray::clone_from_slice(plaintext);
        let encrypted_block = aes.encrypt_block(plaintext_block);

        #[rustfmt::skip]
        let expected_output = [
            0xf5, 0x45, 0xc0, 0x06,
            0x06, 0x91, 0x26, 0xd9,
            0xc0, 0xf9, 0x3f, 0xa7,
            0xdd, 0x89, 0xab, 0x98,
        ];

        assert_eq!(encrypted_block.as_slice(), expected_output);
    }
}
