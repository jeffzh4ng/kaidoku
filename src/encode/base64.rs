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
    use crate::encode::{base64, hex};

    #[test]
    fn base64_encoder_zero_byte() {
        let input = "";
        let encoder =
            base64::ByteToBase64Encoder::new(hex::HexToByteDecoder::new(input.chars()).unwrap());
        let actual_output = encoder.flatten().collect::<String>();
        let expected_output = "";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_one_byte() {
        let input = "6d";
        let hex_decoder = hex::HexToByteDecoder::new(input.chars()).unwrap();
        let base64_encoder = base64::ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.flatten().collect::<String>();
        let expected_output = "bQ==";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_two_bytes() {
        let input = "6f6d";
        let hex_decoder = hex::HexToByteDecoder::new(input.chars()).unwrap();
        let base64_encoder = base64::ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.flatten().collect::<String>();
        let expected_output = "b20=";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_three_bytes() {
        let input = "6f6f6d";
        let hex_decoder = hex::HexToByteDecoder::new(input.chars()).unwrap();
        let base64_encoder = base64::ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.flatten().collect::<String>();
        let expected_output = "b29t";

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn base64_encoder_many_bytes() {
        let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";

        let hex_decoder = hex::HexToByteDecoder::new(input.chars()).unwrap();
        let base64_encoder = base64::ByteToBase64Encoder::new(hex_decoder);

        let actual_output = base64_encoder.flatten().collect::<String>();
        let expected_output = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t";

        assert_eq!(expected_output, actual_output);
    }
}
