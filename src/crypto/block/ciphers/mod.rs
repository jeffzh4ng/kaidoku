pub mod aes;

pub trait BlockCipher {
    type Block: Copy + Default;
    type Key: AsRef<[u8]>;

    fn new(key: Self::Key) -> Self;
    fn encrypt_block(&self, block: &Self::Block) -> Self::Block;
    fn decrypt_block(&self, block: &Self::Block) -> Self::Block;
}
