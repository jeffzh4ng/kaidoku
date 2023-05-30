use std::io;

use fuin::{attack, encode};

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

    let cipher_text = encode::hex::HexToByteDecoder::new(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".chars(),
    )
    .collect::<Result<Vec<u8>, io::Error>>()
    .unwrap();

    let plain_text = attack::single_byte_xor_attack(cipher_text);
    println!("plain_text_with_highest_score: {}", plain_text)
}
