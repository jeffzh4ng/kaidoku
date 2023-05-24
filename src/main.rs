use std::io;

fn main() {
    println!(
        " 
    .d888           d8b          
    d88P            Y8P          
    888                          
    888888 888  888 888 88888b
    888    888  888 888 888 \"88b 
    888    888  888 888 888  888 
    888    Y88b 888 888 888  888 
    888     \"Y88888 888 888  888
    "
    );

    println!("=========================================================");

    println!("Set 1: Basics");
    println!("---");
    println!("1. convert hex to base64");
    let hex = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    match hex_decoder(hex) {
        Ok(decoder) => {
            let b64 = bytes_to_base64(decoder);
            println!("input: {:?}", hex);
            println!("output: {:?}", b64);
            println!("---");
        }
        Err(e) => {
            println!("error: {:?}", e);
        }
    }
}

fn hex_decoder(s: &str) -> Result<DecodedHex, io::Error> {
    if !s.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Non-ASCII character found",
        ));
    }

    // if s mod 3 != 0 {
    // pad it zero one or two bytes of zero
    // }

    return Ok(DecodedHex {
        bytes: s.as_bytes(),
        index: 0,
    });
}

struct DecodedHex<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Iterator for DecodedHex<'a> {
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        let (bytes, i) = (self.bytes, self.index);

        if i < bytes.len() {
            let high_nibble = self.hex_to_nibble(bytes[i]);
            let low_nibble = if i + 1 < bytes.len() {
                self.hex_to_nibble(bytes[i + 1])
            } else {
                0b00000000
            };

            self.index += 2;
            Some(high_nibble << 4 | low_nibble)
        } else {
            None
        }
    }
}

impl DecodedHex<'_> {
    fn hex_to_nibble(&self, c: u8) -> u8 {
        match c {
            b'0' => 0x0,
            b'1' => 0x1,
            b'2' => 0x2,
            b'3' => 0x3,
            b'4' => 0x4,
            b'5' => 0x5,
            b'6' => 0x6,
            b'7' => 0x7,
            b'8' => 0x8,
            b'9' => 0x9,
            b'a' | b'A' => 0xA,
            b'b' | b'B' => 0xB,
            b'c' | b'C' => 0xC,
            b'd' | b'D' => 0xD,
            b'e' | b'E' => 0xE,
            b'f' | b'F' => 0xF,
            _ => panic!("invalid hex character"),
        }
    }
}

fn bytes_to_base64(decoded_hex: DecodedHex) -> String {
    const B64_MAP: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn three_bytes_to_four_b64s(three_bytes_packed: u32) -> Vec<char> {
        let mask = 0b111111;
        let one = three_bytes_packed >> 18;
        let two = (three_bytes_packed >> 12) & mask;
        let three = (three_bytes_packed >> 6) & mask;
        let four = three_bytes_packed & mask;

        // convert u32s to base64 chars
        let one = B64_MAP.chars().nth(one as usize).unwrap();
        let two = B64_MAP.chars().nth(two as usize).unwrap();
        let three = B64_MAP.chars().nth(three as usize).unwrap();
        let four = B64_MAP.chars().nth(four as usize).unwrap();

        Vec::from([one, two, three, four])
    }

    let mut b64_chars = Vec::new();
    // since each b64 character is 6 bits, we can parse four b64 characters from three bytes
    // thus, process bytes in groups of three
    // and merge three bytes = 24 bits into a u32
    let bytes = decoded_hex.collect::<Vec<u8>>();
    for three_bytes in bytes.chunks(3) {
        let mut three_bytes_packed: u32 = 0;
        for b in three_bytes {
            three_bytes_packed <<= 8;
            three_bytes_packed |= *b as u32;
        }

        // convert u32 (24 bits packed with 8 zeros on the left) into four base64 chars
        let four_b64_chars = three_bytes_to_four_b64s(three_bytes_packed);

        b64_chars.extend(four_b64_chars);
    }

    // convert b64 characters into String
    b64_chars.into_iter().collect()
}
