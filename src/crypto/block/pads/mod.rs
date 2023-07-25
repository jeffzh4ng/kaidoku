use super::ciphers::BlockCipher;

pub mod ansix923;
pub mod iso10126;
pub mod iso7816;
pub mod pkcs7;

pub trait Padder<C: BlockCipher>
where
    C: BlockCipher,
{
    fn pad(&self, input: Vec<u8>) -> Vec<C::Block>;
    fn unpad(&self, input: Vec<C::Block>) -> Vec<u8>;
}
