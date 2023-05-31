use std::{io, iter};

pub struct XorCipher<I, J>
where
    I: Iterator<Item = u8>,
    J: Iterator<Item = u8>,
{
    input_a: iter::Peekable<I>,
    input_b: iter::Peekable<J>,
}

impl<I, J> XorCipher<I, J>
where
    I: Iterator<Item = u8>,
    J: Iterator<Item = u8>,
{
    pub fn new(input_a: I, input_b: J) -> Self {
        XorCipher {
            input_a: input_a.peekable(),
            input_b: input_b.peekable(),
        }
    }
}

impl<I, J> Iterator for XorCipher<I, J>
where
    I: Iterator<Item = u8>,
    J: Iterator<Item = u8>,
{
    type Item = Result<u8, io::Error>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.input_a.peek().is_some() && self.input_b.peek().is_some() {
            let a = self.input_a.next().unwrap();
            let b = self.input_b.next().unwrap();
            Some(Ok(a ^ b))
        } else if self.input_a.peek().is_none() && self.input_b.peek().is_none() {
            None
        } else {
            Some(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Uneven length",
            )))
        }
    }
}

#[cfg(test)]
mod tests {
    use std::io;

    use super::*;
    use crate::encode::hex::{self, HexToByteDecoder};

    #[test]
    fn xor_cipher_sanity_check() {
        let hex_decoder_a = HexToByteDecoder::new("1c0111001f010100061a024b53535009181c".chars())
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap()
            .into_iter();

        let hex_decoder_b = HexToByteDecoder::new("686974207468652062756c6c277320657965".chars())
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap()
            .into_iter();

        let xor_cipher = XorCipher::new(hex_decoder_a, hex_decoder_b);
        let actual_output = xor_cipher.collect::<Result<Vec<u8>, io::Error>>().unwrap();
        let actual_output_hex = hex::ByteToHexEncoder::new(actual_output.into_iter());

        let expected_output_hex = "746865206b696420646f6e277420706c6179";
        assert_eq!(
            expected_output_hex,
            actual_output_hex
                .collect::<Result<String, io::Error>>()
                .unwrap()
        )
    }
    #[test]
    fn xor_cipher_uneven_length() {
        let hex_decoder_a = HexToByteDecoder::new("F0".chars())
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap()
            .into_iter();

        let hex_decoder_b = HexToByteDecoder::new("0FF".chars())
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap()
            .into_iter();

        let xor_cipher = XorCipher::new(hex_decoder_a, hex_decoder_b);
        let actual_output = xor_cipher.collect::<Result<Vec<u8>, io::Error>>();

        assert!(actual_output.is_err());
    }
}
