use std::iter;
use thiserror::Error;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum VernamCipherError {
    #[error("input length not equal")]
    UnevenLength,
}

pub fn vernam_cipher_with_key<'a>(
    plain_text: &'a str,
    key: &'a str,
) -> Box<dyn Iterator<Item = Result<u8, VernamCipherError>> + 'a> {
    let plain_text_bytes = plain_text
        .chars()
        .flat_map(crate::encode::utils::char_to_bytes);

    let repeating_key_bytes = key
        .chars()
        .cycle()
        .take(plain_text.len())
        .flat_map(crate::encode::utils::char_to_bytes);

    let xor_cipher = VernamCipher::new(plain_text_bytes, repeating_key_bytes);
    Box::new(xor_cipher)
}

pub struct VernamCipher<I, J>
where
    I: Iterator<Item = u8>,
    J: Iterator<Item = u8>,
{
    a: iter::Peekable<I>,
    b: iter::Peekable<J>,
}

impl<I, J> VernamCipher<I, J>
where
    I: Iterator<Item = u8>,
    J: Iterator<Item = u8>,
{
    pub fn new(a: I, b: J) -> Self {
        VernamCipher {
            a: a.peekable(),
            b: b.peekable(),
        }
    }
}

impl<I, J> Iterator for VernamCipher<I, J>
where
    I: Iterator<Item = u8>,
    J: Iterator<Item = u8>,
{
    type Item = Result<u8, VernamCipherError>;
    fn next(&mut self) -> Option<Self::Item> {
        if self.a.peek().is_some() && self.b.peek().is_some() {
            let a = self.a.next()?;
            let b = self.b.next()?;

            Some(Ok(a ^ b))
        } else if self.a.peek().is_none() && self.b.peek().is_none() {
            None
        } else {
            Some(Err(VernamCipherError::UnevenLength))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::encode::hex;

    #[test]
    fn xor_cipher_sanity_check() {
        let hex_decoder_a =
            hex::HexToByteDecoder::new("1c0111001f010100061a024b53535009181c".chars())
                .collect::<Result<Vec<u8>, hex::HexEncodingError>>()
                .unwrap()
                .into_iter();

        let hex_decoder_b =
            hex::HexToByteDecoder::new("686974207468652062756c6c277320657965".chars())
                .collect::<Result<Vec<u8>, hex::HexEncodingError>>()
                .unwrap()
                .into_iter();

        let xor_cipher = VernamCipher::new(hex_decoder_a, hex_decoder_b);
        let actual_output = xor_cipher
            .collect::<Result<Vec<u8>, VernamCipherError>>()
            .unwrap();
        let actual_output_hex = hex::ByteToHexEncoder::new(actual_output.into_iter());

        let expected_output_hex = "746865206b696420646f6e277420706c6179";
        assert_eq!(
            expected_output_hex,
            actual_output_hex
                .collect::<Result<String, hex::HexEncodingError>>()
                .unwrap()
        )
    }

    #[test]
    fn xor_cipher_uneven_length() {
        let hex_decoder_a = hex::HexToByteDecoder::new("F0".chars())
            .collect::<Result<Vec<u8>, hex::HexEncodingError>>()
            .unwrap()
            .into_iter();

        let hex_decoder_b = hex::HexToByteDecoder::new("0FF".chars())
            .collect::<Result<Vec<u8>, hex::HexEncodingError>>()
            .unwrap()
            .into_iter();

        let xor_cipher = VernamCipher::new(hex_decoder_a, hex_decoder_b);
        let actual_output = xor_cipher.collect::<Result<Vec<u8>, VernamCipherError>>();

        assert!(actual_output.is_err());
    }

    #[test]
    fn xor_cipher_utf8() {
        let plaintext = "こんにちは".as_bytes().iter().cloned();
        let key = "こんこんこ".as_bytes().iter().cloned();
        let xor_cipher = VernamCipher::new(plaintext, key);
        let actual_output = xor_cipher.collect::<Result<Vec<u8>, VernamCipherError>>();
        assert!(actual_output.is_ok());
    }
}
