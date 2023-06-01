use std::io;

use fuin::{attack, crypto, encode};

fn main() {
    println!(
        " 
    .d888           d8b          
    d88P            Y8P          
    888                          
    888888 888  888 888 88888b
    888    888  888 888 888 \"88b 
    888    888  888 888 888  888 
    888    Y88b 888 888 888  888 
    888     \"Y88888 888 888  888
    "
    );

    // challenge 3: single byte XOR attack
    let cipher_text = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let plain_text = attack::single_byte_xor_attack(cipher_text);
    println!("single byte XOR attack: {}", plain_text.unwrap());

    // challenge 4: single byte XOR attack from file
    let path = "/Users/jeff/Documents/repos/fuin/src/single-character-xor.txt";
    let plain_text = attack::single_byte_xor_attack_from_file(path);
    println!("single byte XOR from file attak: {}", plain_text);

    // challenge 5: repeating key XOR
    let plain_text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";

    let cipher_text = crypto::xor_cipher_with_key(plain_text, key)
        .collect::<Result<Vec<u8>, io::Error>>()
        .unwrap()
        .into_iter();
    let cipher_text_hex = encode::hex::ByteToHexEncoder::new(cipher_text) // TODO: look into iterators over references
        .collect::<Result<String, io::Error>>()
        .unwrap();

    println!("cipher_text_hex: {}", cipher_text_hex);

    // #[derive(Eq, PartialEq)]
    // struct SizeDistancePair(i32, i32);

    // impl Ord for SizeDistancePair {
    //     fn cmp(&self, other: &Self) -> Ordering {
    //         other.1.cmp(&self.1) // min heap
    //     }
    // }

    // impl PartialOrd for SizeDistancePair {
    //     fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
    //         Some(self.cmp(other))
    //     }
    // }

    // // challenge 6: repeating key XOR attack

    // // take in a file of base64 encoded strings
    // // decode the strings into bytes
    // let path = path::Path::new("/Users/jeff/Documents/repos/fuin/src/repeating-key-xor.txt");
    // let display = path.display();
    // let file = match fs::File::open(path) {
    //     Err(why) => panic!("couldn't open {}: {}", display, why),
    //     Ok(file) => file,
    // };
    // let contents = io::BufReader::new(file)
    //     .lines()
    //     .map(|line| line.unwrap())
    //     .collect::<Vec<String>>()
    //     .join("");

    // // let cipher_text_bytes = encode::base64::Base64ToByteDecoder::new(contents.chars())
    // //     .collect::<Result<Vec<u8>, io::Error>>()
    // //     .unwrap();

    // let cipher_text_bytes: Vec<u8> = Vec::new();

    // let mut min_hamming_distances = collections::BinaryHeap::new();
    // for key_size in 2..40 {
    //     let chunk_one = "".bytes();
    //     let chunk_two = "".bytes();

    //     let hamming_distance = encode::hamming_distance(chunk_one, chunk_two).unwrap();
    //     let hamming_distance_normalized = hamming_distance as i32 / key_size;

    //     min_hamming_distances.push(SizeDistancePair(key_size, hamming_distance_normalized));
    // }

    // // take the smallest 3 hamming distances
    // let keys_with_smallest_hamming_distances: Vec<_> = min_hamming_distances
    //     .into_iter()
    //     .take(3)
    //     .map(|pair| pair.0)
    //     .collect();

    // // break the ciphertext into blocks of key_size length
    // //  Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    // let transposed_blocks: Vec<Vec<u8>> = Vec::new();

    // for b in transposed_blocks {
    //     // solve each block as if it was single-character XOR
    //     // the single-byte (char) XOR key is the most likely key for that block
    //     let plain_text = attack::single_byte_xor_attack(b);
    //     println!("attack single byte XOR: {}", plain_text.unwrap());
    // }

    // put them togethter for each transposed block and you have the key
}
