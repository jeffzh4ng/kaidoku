use rand::{Error, RngCore, SeedableRng};

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
    n: u32,
}

impl RngCore for MersenneTwister {
    fn next_u32(&mut self) -> u32 {
        // twist every n numbers
        if self.i as u32 >= self.n {
            if self.i as u32 > self.n {
                // error
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
    fn twist(&mut self) {
        // generate the next n values from the series x_i
        todo!()
    }
}

// impl SeedableRng for MersenneTwister {}
