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
    let hex = "6d49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    if let Ok(hex_to_byte_decoder) = hex_decoder(hex) {
        let byte_to_base64_encoder = ByteToBase64Encoder {
            hex_to_byte_decoder,
            index: 0,
        };

        let base64 = byte_to_base64_encoder
            .into_iter()
            .flatten()
            .collect::<String>();

        println!("{base64}");
    }
}

fn hex_decoder(s: &str) -> Result<HexToByteDecoder, io::Error> {
    if !s.is_ascii() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Non-ASCII character found",
        ));
    }

    return Ok(HexToByteDecoder {
        bytes: s.as_bytes(),
        index: 0,
    });
}

struct HexToByteDecoder<'a> {
    bytes: &'a [u8],
    index: usize,
}

impl<'a> Iterator for HexToByteDecoder<'a> {
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

impl ExactSizeIterator for HexToByteDecoder<'_> {
    fn len(&self) -> usize {
        self.bytes.len()
    }
}

impl HexToByteDecoder<'_> {
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

struct ByteToBase64Encoder<'a> {
    hex_to_byte_decoder: HexToByteDecoder<'a>,
    index: usize,
}

impl Iterator for ByteToBase64Encoder<'_> {
    type Item = [char; 4];

    fn next(&mut self) -> Option<Self::Item> {
        // add padding if required
        let padding = if self.index == 0 {
            self.hex_to_byte_decoder.len() % 3
        } else {
            0
        };

        let mut three_bytes_packed = 0;
        for _ in 0..padding {
            three_bytes_packed <<= 8;
        }

        // since each b64 character is 6 bits, we can parse four b64 characters from three bytes
        // thus, process bytes in groups of three
        // and merge three bytes = 24 bits into a u32

        for _ in 0..3 - padding {
            let byte = self.hex_to_byte_decoder.next()?;
            three_bytes_packed <<= 8;
            three_bytes_packed |= byte as u32;
        }

        // convert u32 (24 bits packed with 8 zeros on the left) into four base64 chars
        let four_b64_chars = self.three_bytes_to_four_b64s(three_bytes_packed);

        self.index += 1;
        Some(four_b64_chars)
    }
}

const B64_MAP: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
impl ByteToBase64Encoder<'_> {
    fn three_bytes_to_four_b64s(&self, three_bytes_packed: u32) -> [char; 4] {
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

        [one, two, three, four]
    }
}
