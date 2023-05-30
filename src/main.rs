use std::{fs, io, io::BufRead, path};

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

    // challenge 3: single byte XOR attack
    let cipher_text = encode::hex::HexToByteDecoder::new(
        "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736".chars(),
    )
    .collect::<Result<Vec<u8>, io::Error>>()
    .unwrap();

    let plain_text = attack::single_byte_xor_attack(cipher_text);
    println!("plain_text_with_highest_score: {}", plain_text.unwrap());

    // challenge 4: single byte XOR attack from file
    let path = path::Path::new("/Users/jeff/Documents/repos/fuin/src/single-byte-xor.txt");
    let display = path.display();
    let file = match fs::File::open(path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };

    let mut high_score = 0;
    let mut plain_text_with_high_score = String::new();

    let reader = io::BufReader::new(file);
    for line in reader.lines() {
        match line {
            Ok(line) => {
                let cipher_text = encode::hex::HexToByteDecoder::new(line.chars())
                    .collect::<Result<Vec<u8>, io::Error>>()
                    .unwrap();

                let plain_text = attack::single_byte_xor_attack(cipher_text);

                if let Some(p) = plain_text {
                    if high_score == 0 || attack::score(&p) > high_score {
                        high_score = attack::score(&p);
                        plain_text_with_high_score = p;
                    }
                }
            }
            Err(why) => println!("error reading line: {}", why),
        }
    }

    println!(
        "plain_text_with_highest_score: {}",
        plain_text_with_high_score
    );
}
