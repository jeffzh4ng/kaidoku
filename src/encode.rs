use std::io;

pub struct HexToByteDecoder<'a> {
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

impl<'a> HexToByteDecoder<'a> {
    pub fn new(s: &'a str) -> Result<Self, io::Error> {
        if !s.is_ascii() {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Non-ASCII character found",
            ));
        }

        for c in s.chars() {
            if !c.is_ascii_hexdigit() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Invalid hex character found",
                ));
            }
        }

        return Ok(HexToByteDecoder {
            bytes: s.as_bytes(),
            index: 0,
        });
    }

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

pub struct ByteToBase64Encoder<'a> {
    hex_to_byte_decoder: HexToByteDecoder<'a>,
    index: usize,
}

impl Iterator for ByteToBase64Encoder<'_> {
    type Item = [char; 4];

    fn next(&mut self) -> Option<Self::Item> {
        // since each b64 character is 6 bits, we can parse four b64 characters from three bytes (24 bits)
        // thus, process bytes in groups of three
        // and merge three bytes = 24 bits into a u32
        let mut three_bytes_packed = 0;
        let mut byte_count = 0;
        for _ in 0..3 {
            if let Some(byte) = self.hex_to_byte_decoder.next() {
                three_bytes_packed <<= 8;
                three_bytes_packed |= byte as u32;
                byte_count += 1;
            } else {
                // if the decoder was empty to begin with, return None
                if byte_count == 0 {
                    return None;
                }

                // o/w, shift the bits to the left
                // this is bc three_bytes_to_four_b64s expects 24 bits packed into a u32
                // kind of hacky but ¯\_(ツ)_/¯
                for _ in 0..(3 - byte_count) {
                    three_bytes_packed <<= 8;
                }

                // and then continue with the bytes we have
                break;
            }
        }

        // convert u32 (24 bits packed with 8 zeros on the left) into four base64 chars
        let four_b64_chars = self.three_bytes_to_four_b64s(three_bytes_packed, byte_count);

        self.index += 1;
        Some(four_b64_chars)
    }
}

const B64_MAP: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
impl<'a> ByteToBase64Encoder<'a> {
    pub fn new(hex_to_byte_decoder: HexToByteDecoder<'a>) -> Self {
        ByteToBase64Encoder {
            hex_to_byte_decoder,
            index: 0,
        }
    }

    fn three_bytes_to_four_b64s(&self, three_bytes_packed: u32, byte_count: i32) -> [char; 4] {
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

        // pad with '=' if necessary
        let mut four_b64_chars = [one, two, three, four];
        if byte_count == 1 {
            four_b64_chars[2] = '=';
            four_b64_chars[3] = '=';
        } else if byte_count == 2 {
            four_b64_chars[3] = '=';
        }

        four_b64_chars
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decoder_invalid_ascii() {
        let input = "こんにちは";
        assert!(HexToByteDecoder::new(input).is_err());
    }

    #[test]
    fn hex_decoder_invalid_hex() {
        let input = "6G";
        assert!(HexToByteDecoder::new(input).is_err());
    }

    #[test]
    fn hex_decoder_zero_bytes() {
        let input = "";
        let decoder = HexToByteDecoder::new(input).unwrap();
        let actual_output = decoder.collect::<Vec<u8>>();
        let expected_output: Vec<u8> = Vec::new();

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn hex_decoder_one_byte() {
        let input = "6d";
        let decoder = HexToByteDecoder::new(input).unwrap();
        let actual_output = decoder.collect::<Vec<u8>>();
        let expected_output = Vec::from([0x6d]);

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn hex_decoder_two_bytes() {
        let input = "6f6d";
        let decoder = HexToByteDecoder::new(input).unwrap();
        let actual_output = decoder.collect::<Vec<u8>>();
        let expected_output = Vec::from([0x6f, 0x6d]);

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn hex_decoder_three_bytes() {
        let input = "6f6f6d";
        let decoder = HexToByteDecoder::new(input).unwrap();
        let actual_output = decoder.collect::<Vec<u8>>();
        let expected_output = Vec::from([0x6f, 0x6f, 0x6d]);

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_zero_byte() {
        let encoder = ByteToBase64Encoder::new(HexToByteDecoder::new("").unwrap());
        let actual_output = encoder.flatten().collect::<String>();
        let expected_output = "";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_one_byte() {
        let encoder = ByteToBase64Encoder::new(HexToByteDecoder::new("6d").unwrap());
        let actual_output = encoder.flatten().collect::<String>();
        let expected_output = "bQ==";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_two_bytes() {
        let encoder = ByteToBase64Encoder::new(HexToByteDecoder::new("6f6d").unwrap());
        let actual_output = encoder.flatten().collect::<String>();
        let expected_output = "b20=";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_three_bytes() {
        let encoder = ByteToBase64Encoder::new(HexToByteDecoder::new("6f6f6d").unwrap());
        let actual_output = encoder.flatten().collect::<String>();
        let expected_output = "b29t";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_many_bytes() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
        let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        let actual_output = ByteToBase64Encoder::new(HexToByteDecoder::new(input).unwrap())
            .flatten()
            .collect::<String>();

        assert_eq!(expected_output, actual_output);
    }
}
