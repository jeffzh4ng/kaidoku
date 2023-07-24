pub mod aes;
pub mod vernam;

pub trait BlockMode<C>
where
    C: BlockCipher,
{
    fn encrypt_with_backend(&mut self);
}

pub trait BlockCipher {
    fn encrypt_block(&self, block: &mut [u8; Self::BlockSize]);
    fn decrypt_block(&self, block: &mut [u8; Self::BlockSize]);
}

pub trait StreamCipher {}
