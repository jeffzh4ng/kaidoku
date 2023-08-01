use super::Block;
use generic_array::ArrayLength;

pub mod ansix923;
pub mod iso10126;
pub mod iso7816;
pub mod pkcs7;

pub trait Padder<N: ArrayLength<u8>> {
    fn pad(&self, input: Vec<u8>) -> Vec<Block<N>>;
    fn unpad(&self, input: Vec<Block<N>>) -> Vec<u8>;
}
