use super::super::ciphers::BlockCipher;
use super::Padder;

struct Pkcs7 {}

impl<C> Padder<C> for Pkcs7
where
    C: BlockCipher,
{
    fn pad(&self, input: super::UnpaddedBytes) -> Vec<C::Block> {
        todo!()
    }

    fn unpad(&self, input: Vec<C::Block>) -> super::UnpaddedBytes {
        todo!()
    }
}
