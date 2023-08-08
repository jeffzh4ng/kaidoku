use super::ciphers::BlockCipher;
use super::pads::Padder;
use super::Block;

pub mod cbc;
pub mod ecb;

/// `BlockMode` is a trait representing a mode of operation for block ciphers.
///
/// This trait is generic over three parameters:
/// * `N` is a type implementing `ArrayLength<u8>`, specifying the block size.
/// * `C` is a type implementing `BlockCipher<N>`, specifying the block cipher.
/// * `P` is a type implementing `Padder<N>`, specifying the padding scheme.
///
/// A block cipher by itself is only suitable for the secure cryptographic
/// transformation of a fixed-length group of bits called a block. A mode of
/// operation describes how to *repeatedly* apply a cipher's single-block
/// operation to transform larger amounts of data than a single block.
///
/// Block modes such as ECB, CBC, OFB, CFB, CTR and XTS provide *confidentiality*,
/// but do not provide protection against accidental or malicious tampering
/// of payloads, also known as *integrity*.
///
/// ECB: Y_i = F(P_i, K)
/// CBC: Y_i = P_i XOR C_(i-1)
///
/// Callers with systems that require authentication on top of secrecy
/// should used AEAD (authenticated encryption with additional data) schemes such
/// as GCM, CCM, and SIV.
pub trait BlockMode<N, C, P>
where
    N: generic_array::ArrayLength<u8>,
    C: BlockCipher<N>,
    P: Padder<N>,
{
    fn new(cipher: C, padder: P) -> Self;
    fn encrypt(&mut self, plaintext: Vec<u8>) -> Vec<Block<N>>;
    fn decrypt(&mut self, ciphertext: Vec<Block<N>>) -> Vec<u8>;
}

trait ParallelizableBlockMode {}
trait RandomReadableBlockMode {}
