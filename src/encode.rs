use std::io;

pub struct HexToByteDecoder<I>
where
    I: Iterator<Item = char>,
{
    input: I,
}

impl<I> HexToByteDecoder<I>
where
    I: Iterator<Item = char> + Clone,
{
    pub fn new(input: I) -> Result<Self, io::Error> {
        // collecting now so we can perform validation before instantiation
        let s = input.clone().collect::<String>();

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

        Ok(HexToByteDecoder { input })
    }
}

impl<I> HexToByteDecoder<I>
where
    I: Iterator<Item = char>,
{
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

impl<I> Iterator for HexToByteDecoder<I>
where
    I: Iterator<Item = char>,
{
    type Item = u8;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(c) = self.input.next() {
            let high_nibble = self.hex_to_nibble(c as u8); // TODO: verify this cast is correct
            let low_nibble = if let Some(c) = self.input.next() {
                self.hex_to_nibble(c as u8)
            } else {
                0b00000000
            };

            Some(high_nibble << 4 | low_nibble)
        } else {
            None
        }
    }
}

pub struct ByteToHexEncoder<I> {
    input: I,
    output: [Option<char>; 1],
}

impl<I> ByteToHexEncoder<I>
where
    I: Iterator<Item = u8>,
{
    pub fn new(bytes: I) -> Self {
        ByteToHexEncoder {
            input: bytes,
            output: [None; 1],
        }
    }
}

impl<I> Iterator for ByteToHexEncoder<I>
where
    I: Iterator<Item = u8>,
{
    type Item = char;
    fn next(&mut self) -> Option<Self::Item> {
        if let Some(c) = self.output.iter_mut().find_map(|c| c.take()) {
            // return the next character from the output buffer, if any are present.
            return Some(c);
        }

        if let Some(byte) = self.input.next() {
            let high_nibble = byte >> 4;
            let low_nibble = byte & 0b00001111;

            self.output = [Some(self.nibble_to_hex_char(low_nibble))];
            Some(self.nibble_to_hex_char(high_nibble))
        } else {
            None
        }
    }
}

const HEX_CHARS: &[char] = &[
    '0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f',
];
impl<I> ByteToHexEncoder<I> {
    fn nibble_to_hex_char(&self, nibble: u8) -> char {
        assert!(nibble < 16);
        HEX_CHARS[nibble as usize]
    }
}

pub struct ByteToBase64Encoder<I>
where
    I: Iterator<Item = u8>,
{
    input: I,
    index: usize,
}

impl<I> Iterator for ByteToBase64Encoder<I>
where
    I: Iterator<Item = u8>,
{
    type Item = [char; 4];

    fn next(&mut self) -> Option<Self::Item> {
        // since each b64 character is 6 bits, we can parse four b64 characters from three bytes (24 bits)
        // thus, process bytes in groups of three
        // and merge three bytes = 24 bits into a u32
        let mut three_bytes_packed = 0;
        let mut byte_count = 0;
        for _ in 0..3 {
            if let Some(byte) = self.input.next() {
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
impl<I> ByteToBase64Encoder<I>
where
    I: Iterator<Item = u8>,
{
    pub fn new(input: I) -> Self {
        ByteToBase64Encoder { input, index: 0 }
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
        assert!(HexToByteDecoder::new(input.chars()).is_err());
    }

    #[test]
    fn hex_decoder_invalid_hex() {
        let input = "6G";
        assert!(HexToByteDecoder::new(input.chars()).is_err());
    }

    #[test]
    fn hex_decoder_zero_bytes() {
        let input = "";
        let decoder = HexToByteDecoder::new(input.chars()).unwrap();
        let actual_output = decoder.collect::<Vec<u8>>();
        let expected_output: Vec<u8> = Vec::new();

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn hex_decoder_one_byte() {
        let input = "6d";
        let decoder = HexToByteDecoder::new(input.chars()).unwrap();
        let actual_output = decoder.collect::<Vec<u8>>();
        let expected_output = Vec::from([0x6d]);

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn hex_decoder_two_bytes() {
        let input = "6f6d";
        let decoder = HexToByteDecoder::new(input.chars()).unwrap();
        let actual_output = decoder.collect::<Vec<u8>>();
        let expected_output = Vec::from([0x6f, 0x6d]);

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn hex_decoder_three_bytes() {
        let input = "6f6f6d";
        let decoder = HexToByteDecoder::new(input.chars()).unwrap();
        let actual_output = decoder.collect::<Vec<u8>>();
        let expected_output = Vec::from([0x6f, 0x6f, 0x6d]);

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_zero_byte() {
        let encoder = ByteToBase64Encoder::new(HexToByteDecoder::new("".chars()).unwrap());
        let actual_output = encoder.flatten().collect::<String>();
        let expected_output = "";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_one_byte() {
        let input = "6d";
        let hex_decoder = HexToByteDecoder::new(input.chars()).unwrap();
        let base64_encoder = ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.flatten().collect::<String>();
        let expected_output = "bQ==";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_two_bytes() {
        let input = "6f6d";
        let hex_decoder = HexToByteDecoder::new(input.chars()).unwrap();
        let base64_encoder = ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.flatten().collect::<String>();
        let expected_output = "b20=";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_three_bytes() {
        let input = "6f6f6d";
        let hex_decoder = HexToByteDecoder::new(input.chars()).unwrap();
        let base64_encoder = ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.flatten().collect::<String>();
        let expected_output = "b29t";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_many_bytes() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

        let hex_decoder = HexToByteDecoder::new(input.chars()).unwrap();
        let base64_encoder = ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.flatten().collect::<String>();
        let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(expected_output, actual_output);
    }
}
