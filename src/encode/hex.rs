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
    pub fn new(input: I) -> Self {
        HexToByteDecoder { input }
    }
}

impl<I> HexToByteDecoder<I>
where
    I: Iterator<Item = char>,
{
    fn hex_to_nibble(&self, c: u8) -> Result<u8, io::Error> {
        match c {
            b'0' => Ok(0x0),
            b'1' => Ok(0x1),
            b'2' => Ok(0x2),
            b'3' => Ok(0x3),
            b'4' => Ok(0x4),
            b'5' => Ok(0x5),
            b'6' => Ok(0x6),
            b'7' => Ok(0x7),
            b'8' => Ok(0x8),
            b'9' => Ok(0x9),
            b'a' | b'A' => Ok(0xA),
            b'b' | b'B' => Ok(0xB),
            b'c' | b'C' => Ok(0xC),
            b'd' | b'D' => Ok(0xD),
            b'e' | b'E' => Ok(0xE),
            b'f' | b'F' => Ok(0xF),
            _ => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid nibble",
            )),
        }
    }
}

impl<I> Iterator for HexToByteDecoder<I>
where
    I: Iterator<Item = char>,
{
    type Item = Result<u8, io::Error>;

    fn next(&mut self) -> Option<Self::Item> {
        if let Some(c) = self.input.next() {
            if !c.is_ascii() {
                return Some(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "Input is not ascii.",
                )));
            }

            let high_nibble = self.hex_to_nibble(c as u8);
            let low_nibble = if let Some(c) = self.input.next() {
                self.hex_to_nibble(c as u8)
            } else {
                Ok(0b00000000)
            };

            match (high_nibble, low_nibble) {
                (Err(e), _) | (_, Err(e)) => Some(Err(e)),
                (Ok(high_nibble), Ok(low_nibble)) => Some(Ok(high_nibble << 4 | low_nibble)),
            }
        } else {
            None
        }
    }
}

pub struct ByteToHexEncoder<I> {
    input: I,
    output: [Option<Result<char, io::Error>>; 1],
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
    type Item = Result<char, io::Error>;
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
    fn nibble_to_hex_char(&self, nibble: u8) -> Result<char, io::Error> {
        if nibble > 15 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Invalid nibble",
            ));
        }

        Ok(HEX_CHARS[nibble as usize])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_decoder_invalid_ascii() {
        let input = "こんにちは";
        assert!(HexToByteDecoder::new(input.chars())
            .collect::<Result<Vec<u8>, io::Error>>()
            .is_err());
    }

    #[test]
    fn hex_decoder_invalid_hex() {
        let input = "6G";
        assert!(HexToByteDecoder::new(input.chars())
            .collect::<Result<Vec<u8>, io::Error>>()
            .is_err());
    }

    #[test]
    fn hex_decoder_zero_bytes() {
        let input = "";
        let decoder = HexToByteDecoder::new(input.chars());
        let actual_output = decoder.collect::<Result<Vec<u8>, io::Error>>().unwrap();
        let expected_output: Vec<u8> = Vec::new();

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn hex_decoder_one_byte() {
        let input = "6d";
        let decoder = HexToByteDecoder::new(input.chars());
        let actual_output = decoder.collect::<Result<Vec<u8>, io::Error>>().unwrap();
        let expected_output = Vec::from([0x6d]);

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn hex_decoder_two_bytes() {
        let input = "6f6d";
        let decoder = HexToByteDecoder::new(input.chars());
        let actual_output = decoder.collect::<Result<Vec<u8>, io::Error>>().unwrap();
        let expected_output = Vec::from([0x6f, 0x6d]);

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn hex_decoder_three_bytes() {
        let input = "6f6f6d";
        let decoder = HexToByteDecoder::new(input.chars());
        let actual_output = decoder.collect::<Result<Vec<u8>, io::Error>>().unwrap();
        let expected_output = Vec::from([0x6f, 0x6f, 0x6d]);

        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn hex_encoder_one_byte() {
        let single_byte = [u8::from_str_radix("6d", 16).unwrap()];
        let input = single_byte.iter().cloned();

        let encoder = ByteToHexEncoder::new(input);
        let actual_output = encoder.collect::<Result<String, io::Error>>().unwrap();

        let expected_output = "6d";
        assert_eq!(expected_output, actual_output);
    }

    #[test]
    fn hex_encoder_two_bytes() {
        let two_bytes = [
            u8::from_str_radix("6f", 16).unwrap(),
            u8::from_str_radix("6d", 16).unwrap(),
        ];
        let input = two_bytes.iter().cloned();

        let encoder = ByteToHexEncoder::new(input);
        let actual_output = encoder.collect::<Result<String, io::Error>>().unwrap();

        let expected_output = "6f6d";
        assert_eq!(expected_output, actual_output);
    }
}
