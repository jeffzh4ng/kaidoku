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

    // challenge 6: repeating key XOR attack
    let path = "/Users/jeff/Documents/repos/fuin/src/repeating-key-xor.txt";
    let plain_text = attack::repeating_byte_xor_attack(path);
    println!("repeating key XOR attack: {}", plain_text);
}
