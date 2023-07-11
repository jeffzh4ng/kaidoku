use rand::{Error, RngCore, SeedableRng};

// n: degree of recurrence
const N: usize = 624;

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

// The Mersenne Twister is a general-purpose pseudorandom number generator (PRNG)
// developed in 1997 by Makoto Matsumoto (松本 眞) and Takuji Nishimura (西村 拓士).
// Its name derives from the fact that its period length is chosen to be a Mersenne prime.
// -> https://en.wikipedia.org/wiki/Mersenne_Twister
pub struct MersenneTwister {
    state: [u32; 32], // word size for MT19937 is 32 bits
    i: usize,
}

impl RngCore for MersenneTwister {
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
        todo!()
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        todo!()
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

impl MersenneTwister {
    fn new() -> Self {
        MersenneTwister {
            state: [0; 32],
            i: N + 1,
        }
    }

    fn twist(&mut self) {
        // generate the next n values from the series x_i
        for _ in 0..N {
            let x = (self.state[self.i] & UPPER_MASK) + (self.state[(self.i + 1) % N] & LOWER_MASK);

            let mut x_a = x >> 1;
            if x % 2 != 0 {
                // ==> lowest bit of x is 1
                x_a ^= A;
            }
            self.state[self.i] = self.state[(self.i + M) % N] ^ x_a;
        }

        self.i = 0;
    }
}

impl SeedableRng for MersenneTwister {
    type Seed = [u8; 32];

    fn from_seed(seed: Self::Seed) -> Self {
        let mt = MersenneTwister {
            state: [0; 32],
            i: N + 1,
        };

        mt.state[0] = seed;

        for i in 1..N {
            mt.state[i] = (mt.state[i - 1] ^ (mt.state[i - 1] >> (W - 2)) * f) + i;
        }

        mt
    }
}
