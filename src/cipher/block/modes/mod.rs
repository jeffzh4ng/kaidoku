use super::ciphers::BlockCipher;
use super::pads::Padder;

mod cbc;
mod cfb;
mod ctr;
mod ecb;
mod ofb;

pub use cbc::*;
pub use cfb::*;
pub use ctr::*;
pub use ecb::*;
pub use ofb::*;

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
/// ECB: C_i = encrypt_block(P_i, K)
/// CBC: C_i = encrypt_block(P_i XOR C_{i-1}, K), C_0 = IV
/// OFB: C_i = P_i XOR S_i, S_i = encrypt_block(S_{i-1}, K), S_0 = IV
/// CFB: Y_i = P_i XOR S_i, S_i = encrypt_block(C_{i-1}, K), C_0 = IV
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
    fn encrypt(&mut self, plaintext: Vec<u8>) -> Vec<u8>;
    fn decrypt(&mut self, ciphertext: Vec<u8>) -> Vec<u8>;
}
