pub mod ciphers;
pub mod modes;
pub mod pads;

use generic_array;

// using generic_array to type [u8; usize]
// since Rust types nor structs support const generics
type Block<N> = generic_array::GenericArray<u8, N>;
