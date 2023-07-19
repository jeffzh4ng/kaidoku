use std::{io, vec};

const B64_MAP: &[u8] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/".as_bytes();

#[derive(Copy, Clone, Debug)]
enum DecodedByte {
    Value(u8),
    Padding,
}

pub struct Base64ToByteDecoder<I> {
    input: I,
    output: [Option<DecodedByte>; 2],
}

impl<I> Base64ToByteDecoder<I>
where
    I: Iterator<Item = char>,
{
    pub fn new(input: I) -> Self {
        Base64ToByteDecoder {
            input,
            output: [None, None],
        }
    }
}

impl<I> Iterator for Base64ToByteDecoder<I>
where
    I: Iterator<Item = char>,
{
    type Item = Result<u8, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(DecodedByte::Value(byte)) = self.output.iter_mut().find_map(|b| b.take()) {
            return Some(Ok(byte));
        }

        // process four b64 chars at a time
        let mut four_b64_ascii_chars = vec![];
        let mut padding_count = 0;

        // read in four b64 chars
        for i in 0..4 {
            if let Some(c) = self.input.next() {
                if c == '=' {
                    padding_count += 1;
                }

                four_b64_ascii_chars.push(c as u8);
            } else {
                if i == 0 {
                    return None; // exit on empty input
                }

                // add padding for missing chars
                padding_count += 1;
                four_b64_ascii_chars.push(b'=');
            }
        }

        if padding_count > 2 {
            return Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid padding.",
            )));
        }

        // convert four base64 chars into three bytes
        let three_bytes = match self.four_b64s_to_three_bytes(four_b64_ascii_chars, padding_count) {
            Ok(bytes) => bytes,
            Err(e) => return Some(Err(e)),
        };

        self.output = [Some(three_bytes[1]), Some(three_bytes[2])];
        match three_bytes[0] {
            DecodedByte::Value(byte) => Some(Ok(byte)),
            DecodedByte::Padding => Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid padding.",
            ))),
        }
    }
}

impl<I> Base64ToByteDecoder<I>
where
    I: Iterator<Item = char>,
{
    // bQ==
    // 011011 010000 000000 000000
    // 01101101

    // b20=
    // 011011 11 0110 110100
    // 01101111 01101101

    // b29t
    // 011011 11(0110 1111)01 101101
    // 01101111 01101111 01101101

    fn four_b64s_to_three_bytes(
        &self,
        four_b64s: Vec<u8>,
        padding_count: i32,
    ) -> Result<[DecodedByte; 3], io::Error> {
        let mut four_bytes = vec![];
        for i in 0..4 - padding_count {
            let b = if four_b64s[i as usize] == b'=' {
                255
            } else {
                B64_MAP
                    .iter()
                    .position(|&b64_char| b64_char == four_b64s[i as usize])
                    .ok_or(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "Invalid padding.",
                    ))
                    .unwrap() as u8
            };

            four_bytes.push(b);
        }
        four_bytes.resize(four_bytes.len() + padding_count as usize, 255); // garbage bytes

        // convert four bytes to three
        let byte_one = four_bytes[0] << 2 | four_bytes[1] >> 4;
        let byte_two = four_bytes[1] << 4 | four_bytes[2] >> 2;
        let byte_three = four_bytes[2] << 6 | four_bytes[3];

        // encoding padding bytes as indexes > max(b64) = 63
        // the caller (iterator) will ignore these bytes
        if padding_count == 2 {
            Ok([
                DecodedByte::Value(byte_one),
                DecodedByte::Padding,
                DecodedByte::Padding,
            ])
        } else if padding_count == 1 {
            Ok([
                DecodedByte::Value(byte_one),
                DecodedByte::Value(byte_two),
                DecodedByte::Padding,
            ])
        } else {
            Ok([
                DecodedByte::Value(byte_one),
                DecodedByte::Value(byte_two),
                DecodedByte::Value(byte_three),
            ])
        }
    }
}

pub struct ByteToBase64Encoder<I>
where
    I: Iterator<Item = u8>,
{
    input: I,
    output: [Option<char>; 3],
}

impl<I> Iterator for ByteToBase64Encoder<I>
where
    I: Iterator<Item = u8>,
{
    type Item = char;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(c) = self.output.iter_mut().find_map(|c| c.take()) {
            // return the next character from the output buffer, if any are present.
            return Some(c);
        }

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
        self.output = [
            Some(four_b64_chars[1]),
            Some(four_b64_chars[2]),
            Some(four_b64_chars[3]),
        ];

        Some(four_b64_chars[0])
    }
}

impl<I> ByteToBase64Encoder<I>
where
    I: Iterator<Item = u8>,
{
    pub fn new(input: I) -> Self {
        ByteToBase64Encoder {
            input,
            output: [None; 3],
        }
    }

    fn three_bytes_to_four_b64s(&self, three_bytes_packed: u32, byte_count: i32) -> [char; 4] {
        let mask = 0b111111;
        let one = three_bytes_packed >> 18;
        let two = (three_bytes_packed >> 12) & mask;
        let three = (three_bytes_packed >> 6) & mask;
        let four = three_bytes_packed & mask;

        // convert u32s to base64 chars
        let one = B64_MAP[one as usize] as char;
        let two = B64_MAP[two as usize] as char;
        let three = B64_MAP[three as usize] as char;
        let four = B64_MAP[four as usize] as char;

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
    use std::io;

    use crate::encode::{base64, hex};

    #[test]
    fn base64_decoder_zero_chars() {
        let input = "";
        let base64_decoder = base64::Base64ToByteDecoder::new(input.chars());
        let actual_output = base64_decoder
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();
        let expected_output: Vec<u8> = vec![];

        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn base64_decoder_one_char_without_padding() {
        let input = "b";
        let base64_decoder = base64::Base64ToByteDecoder::new(input.chars());
        let actual_output = base64_decoder.collect::<Result<Vec<u8>, io::Error>>();

        assert!(actual_output.is_err());
    }

    #[test]
    fn base64_decoder_one_char_with_padding() {
        let input = "b===";
        let base64_decoder = base64::Base64ToByteDecoder::new(input.chars());
        let actual_output = base64_decoder.collect::<Result<Vec<u8>, io::Error>>();

        assert!(actual_output.is_err());
    }

    // bQ==
    // 011011 010000 000000 000000
    // 01101101

    // b20=
    // 011011 110110 110100
    // 01101111 01101101

    // b29t
    // 011011 11(0110 1111)01 101101
    // 01101111 01101111 01101101

    #[test]
    fn base64_decoder_two_char_with_padding() {
        let input = "bQ==";
        let base64_decoder = base64::Base64ToByteDecoder::new(input.chars());
        let actual_output = base64_decoder
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();
        let expected_output: Vec<u8> = vec![0x6d];

        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn base64_decoder_two_char_without_padding() {
        let input = "bQ";
        let base64_decoder = base64::Base64ToByteDecoder::new(input.chars());
        let actual_output = base64_decoder
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();
        let expected_output: Vec<u8> = vec![0x6d];

        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn base64_decoder_three_char_with_padding() {
        let input = "b20=";
        let base64_decoder = base64::Base64ToByteDecoder::new(input.chars());
        let actual_output = base64_decoder
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();
        let expected_output: Vec<u8> = vec![0x6f, 0x6d];

        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn base64_decoder_three_char_without_padding() {
        let input = "b20";
        let base64_decoder = base64::Base64ToByteDecoder::new(input.chars());
        let actual_output = base64_decoder
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();
        let expected_output: Vec<u8> = vec![0x6f, 0x6d];

        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn base64_decoder_four_char_with_padding() {
        let input = "b29t";
        let base64_decoder = base64::Base64ToByteDecoder::new(input.chars());
        let actual_output = base64_decoder
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();
        let expected_output: Vec<u8> = vec![0x6f, 0x6f, 0x6d];

        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn base64_decoder_four_char_without_padding() {
        let input = "b29t";
        let base64_decoder = base64::Base64ToByteDecoder::new(input.chars());
        let actual_output = base64_decoder
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();
        let expected_output: Vec<u8> = vec![0x6f, 0x6f, 0x6d];

        assert_eq!(actual_output, expected_output);
    }

    #[test]
    fn base64_encoder_zero_byte() {
        let input = "";
        let hex_decoder = hex::HexToByteDecoder::new(input.chars())
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap()
            .into_iter();

        let base64_encoder = base64::ByteToBase64Encoder::new(hex_decoder);
        let actual_output = base64_encoder.collect::<String>();
        let expected_output = "";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_one_byte() {
        let input = "6d";
        let hex_decoder: std::vec::IntoIter<u8> = hex::HexToByteDecoder::new(input.chars())
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap()
            .into_iter();

        let base64_encoder = base64::ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.collect::<String>();
        let expected_output = "bQ==";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_two_bytes() {
        let input = "6f6d";
        let hex_decoder = hex::HexToByteDecoder::new(input.chars())
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap()
            .into_iter();

        let base64_encoder = base64::ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.collect::<String>();
        let expected_output = "b20=";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_three_bytes() {
        let input = "6f6f6d";
        let hex_decoder = hex::HexToByteDecoder::new(input.chars())
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap()
            .into_iter();

        let base64_encoder = base64::ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.collect::<String>();
        let expected_output = "b29t";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_many_bytes() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

        let hex_decoder = hex::HexToByteDecoder::new(input.chars())
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap()
            .into_iter();

        let base64_encoder = base64::ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.collect::<String>();
        let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(expected_output, actual_output);
    }
}
