struct XorCipher<I>
where
    I: Iterator<Item = u8>,
{
    input_a: I,
    input_b: I,
}

impl<I> XorCipher<I>
where
    I: Iterator<Item = u8>,
{
    fn new(input_a: I, input_b: I) -> Self {
        XorCipher { input_a, input_b }
    }
}

impl<I> Iterator for XorCipher<I>
where
    I: Iterator<Item = u8>,
{
    type Item = u8;
    fn next(&mut self) -> Option<Self::Item> {
        if let (Some(a), Some(b)) = (self.input_a.next(), self.input_b.next()) {
            Some(a ^ b)
        } else {
            None
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
        let actual_output = xor_cipher.collect::<Vec<u8>>();
        let actual_output_hex = hex::ByteToHexEncoder::new(actual_output.into_iter());

        let expected_output_hex = "746865206b696420646f6e277420706c6179";
        assert_eq!(
            expected_output_hex,
            actual_output_hex
                .collect::<Result<String, io::Error>>()
                .unwrap()
        )
    }
}
