use rand::{Error, RngCore};

// RC4 (Rivest Cipher 4, also known as ARC4 or ARCFOUR, meaning Alleged RC4).
// While it is remarkable for its simplicity and speed in software, multiple
// vulnerabilities have been discovered in RC4, rendering it insecure.
// -> https://en.wikipedia.org/wiki/RC4

pub struct RC4 {
    state: Vec<u8>,
    i: u8,
    j: u8,
}

// Many stream ciphers are based on linear-feedback shift registers (LFSRs), which,
// while efficient in hardware, are less so in software. The design of RC4 avoids
// the use of LFSRs and is ideal for software implementation, as it requires only byte manipulations.

// It uses 256 bytes of memory for the state array, S[0] through S[255], k bytes
// of memory for the key, key[0] through key[k−1], and integer variables, i, j, and K.
impl RngCore for RC4 {
    fn next_u32(&mut self) -> u32 {
        self.i = self.i.wrapping_add(1); // add 1 mod 256
        self.j = self.j.wrapping_add(self.state[self.i as usize]); // add i mod 256

        // swap
        self.state.swap(self.i as usize, self.j as usize);

        // sum S[i] and S[i], and then use the sum as index to output K
        let sum = self.state[self.i as usize].wrapping_add(self.state[self.j as usize]);
        let k = self.state[sum as usize];
        k.into()
    }

    fn next_u64(&mut self) -> u64 {
        todo!()
    }

    fn fill_bytes(&mut self, _dest: &mut [u8]) {}

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

// impl SeedableRng for RC4 {
//     type Seed = [u8; 32];

//     fn from_seed(seed: Self::Seed) -> Self {
//         let mut S = Vec::new();

//         for i in 0..256 {
//             S[i] = i as u8;
//         }

//         let mut j = 0;
//         for i in 0..256 {
//             j = (j + S[i] + seed[i % seed_length]) % 256;
//             S.swap(i, j);
//         }

//         todo!()
//     }
// }
