use rand::{Error, RngCore, SeedableRng};

// n: degree of recurrence
const N: usize = 624;

// F: used when initializing state
const F: u128 = 1812433253;

// m: middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
const M: usize = 397;
// r: separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w − 1
const R: u32 = 31;
const LOWER_MASK: u32 = (1 << R) - 1;
const UPPER_MASK: u32 = !LOWER_MASK;

// a: coefficients of the rational normal form twist matrix
const A: u32 = 2567483615; // 9908B0DF_16

// s, t: TGFSR(R) tempering bit shifts
const S: u32 = 7;
const T: u32 = 15;

// b, c: TGFSR(R) tempering bitmasks
const B: u32 = 2636928640; // 9D2C5680_16
const C: u32 = 4022730752; // EFC60000_16

// u, d, l: additional tempering bit shifts/masks
const U: u32 = 11;
const D: u32 = 4294967295; // FFFFFFFF_16
const L: u32 = 18;

// 2^(nw-r) - 1 is a Mersenne Prime
// if n = 624, w = 32, r = 31, then 2^(nw-r) - 1 = 2^(19937) - 1
// thus, MT19937

// The Mersenne Twister is a general-purpose pseudorandom number generator (PRNG)
// developed in 1997 by Makoto Matsumoto (松本 眞) and Takuji Nishimura (西村 拓士).
// Its name derives from the fact that its period length is chosen to be a Mersenne prime.
// -> https://en.wikipedia.org/wiki/Mersenne_Twister
pub struct MT {
    state: [u32; N], // word size for MT19937 is 32 bits
    i: usize,
}

impl RngCore for MT {
    fn next_u32(&mut self) -> u32 {
        // twist every 624 numbers
        if self.i >= N {
            if self.i > N {
                // MT generator was never seeded
                // -> seed with constant value since RngCore.next_u32 cannot fail.

                // TODO
            }

            self.twist();
        }

        // extract a tempered value based on self.state[i]
        let mut y = self.state[self.i];
        y = y ^ ((y >> U) & D);
        y = y ^ ((y << S) & B);
        y = y ^ ((y << T) & C);
        y = y ^ (y >> L);

        self.i += 1;

        y
    }

    fn next_u64(&mut self) -> u64 {
        (self.next_u32() as u64) << 32 | self.next_u32() as u64
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            let random_u32 = self.next_u32();
            let bytes = random_u32.to_be_bytes();
            chunk.copy_from_slice(&bytes[0..chunk.len()]);
        }
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl MT {
    fn twist(&mut self) {
        // generate the next n values from the series x_i
        for i in 0..N {
            let x = (self.state[i] & UPPER_MASK) + (self.state[(i + 1) % N] & LOWER_MASK);

            let mut x_a = x >> 1;
            if x % 2 != 0 {
                // ==> lowest bit of x is 1
                x_a ^= A;
            }
            self.state[i] = self.state[(i + M) % N] ^ x_a;
        }

        self.i = 0;
    }
}

impl SeedableRng for MT {
    type Seed = [u8; 4];

    fn from_seed(seed: Self::Seed) -> Self {
        let mut mt = MT {
            state: [0; N],
            i: N,
        };

        let seed_packed = u32::from_be_bytes(seed);
        mt.state[0] = seed_packed;

        // x_i = f[x_i+1 XOR ((x_i-1) >> (w-2)) ] + i
        for i in 1..N {
            let rhs = mt.state[i - 1] >> (32 - 2);
            let xor = (mt.state[i - 1] ^ rhs) as u128;
            let x_i = xor * F + i as u128;
            mt.state[i] = x_i as u32; // keeps only the least significant 32 bits
        }

        mt
    }
}

#[cfg(test)]
mod tests {
    use std::{
        fs,
        io::{self, BufRead},
        path,
    };

    use super::*;

    #[test]
    fn known_answer_test() {
        let seed = 1131464071u32;
        let seed_bytes = seed.to_be_bytes();
        let mut mt = MT::from_seed(seed_bytes);

        let path = path::Path::new(
            "/Users/jeff/Documents/repos/fuin/src/rand/mt_test_vector_1131464071.txt",
        );
        let display = path.display();
        let file = match fs::File::open(path) {
            Err(why) => panic!("couldn't open {}: {}", display, why),
            Ok(file) => file,
        };

        for line in io::BufReader::new(file).lines() {
            match line {
                Err(why) => panic!("error reading line: {}", why),
                Ok(line) => {
                    let mut buf = [0u8; 4];
                    mt.fill_bytes(&mut buf);
                    let actual_random_number = u32::from_be_bytes(buf);

                    let expected_random_number: u32 = line.parse().expect("Invalid u32");
                    assert_eq!(expected_random_number, actual_random_number)
                }
            }
        }
    }
}
