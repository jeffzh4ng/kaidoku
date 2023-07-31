use std::{path, thread};

use ::rand::prelude::*;
use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

// TODOs
// - remove clones made to satisfy borrow checker
// - generic array
// - cli: files, stdin
// - cd: lints, benchmarks, msrv, tests

/// commandline cryptographic protocols
#[derive(Parser)]
#[command(
    author,
    version,
    about,
    long_about = None
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    Encrypt {
        #[arg(short, long)]
        input: path::PathBuf,

        #[arg(short, long)]
        encoding: String,

        #[arg(short, long)]
        protocol: String,

        #[arg(short, long)]
        output: path::PathBuf,
    },

    Decrypt {
        #[arg(short, long)]
        input: path::PathBuf,

        #[arg(short, long)]
        encoding: String,

        #[arg(short, long)]
        protocol: String,

        #[arg(short, long)]
        output: path::PathBuf,
    },

    GenerateKey {
        #[arg(short, long)]
        protocol: String,

        #[arg(short, long)]
        output: path::PathBuf,
    },
}

fn main() -> Result<()> {
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

    let cli = Cli::parse();
    match &cli.command {
        Some(Commands::Encrypt {
            input,
            encoding,
            protocol,
            output,
        }) => {
            println!("encrypt");
            let plain_text =
                "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
            let key = "ICE";

            let cipher_text = fuin::crypto::stream::vernam_cipher_with_key(plain_text, key)
                .collect::<Result<Vec<u8>, fuin::crypto::stream::VernamCipherError>>()
                .context("unable to encrypt plaintext")?;
            // .unwrap()
            // .into_iter();
        }
        Some(Commands::Decrypt {
            input,
            encoding,
            protocol,
            output,
        }) => {
            println!("decrypt");
        }
        Some(Commands::GenerateKey { protocol, output }) => {
            println!("generate key");
        }
        None => {
            test_runner();
        }
    };

    Ok(())
}

fn test_runner() {
    // ____ ____ ____ ____ ____ ____ _________ ____ ____ ____ ____ ____ ____ ____
    // ||S |||T |||R |||E |||A |||M |||       |||C |||I |||P |||H |||E |||R |||S ||
    // ||__|||__|||__|||__|||__|||__|||_______|||__|||__|||__|||__|||__|||__|||__||
    // |/__\|/__\|/__\|/__\|/__\|/__\|/_______\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|

    // the following ciphers are vernam ciphers
    // vernam ciphers are the digital translation of vigenere ciphers.
    // they are shift ciphers that use XOR as the "shift" function
    // the XOR shift is quite different than shifting by addition or "alphabet"
    // XOR is indeed mod 2, but only the single bits in a byte are added mod 2
    // *the characters aren't shifted by the mod 26 operator. they are shifted by the XOR operator*
    // the resulting ciphertext character that the byte encodes is not *key=K* positions ahead of plaintext character

    // -------------monoalphabetic "singleshift" ciphers------------------------
    // the cipher is attacked simply by brute forcing through the keyspace aka shift space
    // decrypting the ciphertext with the single shift, and then scoring the plaintext based on freq analysis

    // challenge 3: monoalphabetic vernam attack
    let cipher_text = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    let plain_text = fuin::attack::vernam::monoalphabetic_attack(cipher_text);
    println!("single byte XOR attack: {}", plain_text.unwrap().unwrap().1);

    // challenge 4: monoalphabetic vernam attack (file variation)
    let path = "/Users/jeff/Documents/repos/fuin/tests/data/monoalphabetic_vernam_ciphertext.txt";
    let plain_text = fuin::attack::vernam::monoalphabetic_attack_file_variation(path);
    println!("single byte XOR from file attack: {}", plain_text.unwrap());

    // -------------polyalphabetic "polyshift" ciphers--------------------------
    // the cipher is attacked by kasiski examination variation
    // https://en.wikipedia.org/wiki/Kasiski_examination
    // we find the probable key size by using the hamming distance statistic,
    // instead of the traditional repeat sequence distance statistic

    // once we have the probable key size, we break the ciphertext into blocks of that size
    // tranpose the blocks such that the groupings contain ciphertext characters encrypted with the *same* key (shift)
    // then we solve each block by treating it like a monoalphabetic vernam attack :)
    // yes, brute force through keyspace aka shiftspace, and use freq analysis

    // challenge 5: polyalphabetic vernam
    let plain_text = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    let key = "ICE";

    let cipher_text = fuin::crypto::stream::vernam_cipher_with_key(plain_text, key)
        .collect::<Result<Vec<u8>, fuin::crypto::stream::VernamCipherError>>()
        .unwrap()
        .into_iter();
    let cipher_text_hex = fuin::encode::hex::ByteToHexEncoder::new(cipher_text) // TODO: look into iterators over references
        .collect::<Result<String, fuin::encode::hex::HexEncodingError>>()
        .unwrap();
    println!("cipher_text_hex: {}", cipher_text_hex);

    // challenge 6: polyalphabetic vernam attack
    let path = "/Users/jeff/Documents/repos/fuin/tests/data/polyalphabetic_vernam_ciphertext.txt";
    let plain_text = fuin::attack::vernam::polyalphabetic_attack(path);
    println!("polyalphabetic vernam attack: {}", plain_text);

    // joseph mauborgne recognized if the key was "endless and senseless",
    // aka key length = plaintext length and it's truly *random*,
    // then cryptanalysis (polyalphabetic vernam attack) above would be rendered impossible
    // this was later formalized by claude shannon in a classified report in 1945, and in a public one in 1949

    // -------------one time pad------------------------------------------------
    // - include complexity theory primer
    // - sketch proof (include)
    // - look into TRNGs in rust (and roll your own by hand)

    // - talk about relaxing, and approximating perfect secrecy --> practical secrecy aka TRNG -> PRNG

    // -------------mt19937 cipher----------------------------------------------
    // challenge 21: implement MT19937 RNG

    let seed = 1131464071u32;
    let seed_bytes = seed.to_be_bytes();
    let mut mt = fuin::rng::MT::from_seed(seed_bytes);

    let handle = thread::spawn(move || {
        for _ in 0..2 {
            let mut buf = [0u8; 4];
            mt.fill_bytes(&mut buf);

            let x = u32::from_be_bytes(buf);
            println!("mt19937 random number: {x}");
        }
    });

    handle.join().unwrap();

    // -------------rc4 cipher--------------------------------------------------
    // -------------pcg --------------------------------------------------------
    // -------------xorshift----------------------------------------------------
    // -------------xorshiro----------------------------------------------------

    // -------------chacha20 cipher---------------------------------------------

    // ____ ____ ____ ____ ____ _________ ____ ____ ____ ____ ____ ____ ____
    // ||B |||L |||O |||C |||K |||       |||C |||I |||P |||H |||E |||R |||S ||
    // ||__|||__|||__|||__|||__|||_______|||__|||__|||__|||__|||__|||__|||__||
    // |/__\|/__\|/__\|/__\|/__\|/_______\|/__\|/__\|/__\|/__\|/__\|/__\|/__\|
}
