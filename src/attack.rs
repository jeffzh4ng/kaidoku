use std::{
    cmp::Ordering,
    collections::{self, HashMap},
    fs,
    io::{self, BufRead},
    path::{self, Path},
};

use crate::{crypto, encode};

const ENGLISH_FREQ: &str = "QZXJKVBWPYGMCFULDRHS NIOTAE";
pub fn score(s: &str) -> i32 {
    s.chars().fold(0, |acc, c| {
        if ENGLISH_FREQ.contains(c) {
            return acc + ENGLISH_FREQ.chars().position(|x| x == c).unwrap() as i32 + 1;
        }

        acc
    })
}

pub fn monoalphabetic_vernam_attack(cipher_text_hex: &str) -> Option<String> {
    let cipher_text = encode::hex::HexToByteDecoder::new(cipher_text_hex.chars())
        .collect::<Result<Vec<u8>, io::Error>>()
        .unwrap();

    // ciphertext: 1111 0000
    // keyspace:   0000 0001
    // plaintext:  1111 0001
    let mut plain_text_scores = HashMap::new();

    // brute force through the key space
    let key_space = (0..=255).collect::<Vec<u8>>();
    for k in key_space {
        // f(c, k) = p
        // f = xor cipher
        // p = plain text
        // c = cipher text
        // k = key
        let input_a = cipher_text.clone().into_iter();
        let input_b = std::iter::repeat(k)
            .take(cipher_text.len())
            .collect::<Vec<u8>>()
            .into_iter();

        let plain_bytes = crypto::XorCipher::new(input_a, input_b)
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();

        let s = String::from_utf8(plain_bytes.clone());

        // check if plain bytes are invalid utf8
        if s.is_err() {
            continue;
        }

        // convert bytes to string, calculate the score, and store it in the map
        let plain_text = s.unwrap();
        let score = score(&plain_text);
        plain_text_scores.insert(plain_text, score);
    }

    // sort the map by score
    let mut plain_text_scores_tuples = plain_text_scores
        .into_iter()
        .collect::<Vec<(String, i32)>>();
    plain_text_scores_tuples.sort_by(|a, b| b.1.cmp(&a.1));

    if plain_text_scores_tuples.is_empty() {
        return None; // no valid plain text
    }

    // if there's a tie, warn
    if plain_text_scores_tuples[0].1 == plain_text_scores_tuples[1].1 {
        println!("warning: there's a tie");
        println!("one: {:?}", &plain_text_scores_tuples[0].0);
        println!("two: {:?}", &plain_text_scores_tuples[1].0);
    }

    if !&plain_text_scores_tuples[0].0.as_bytes().is_ascii() {
        return None;
    }

    // select the plain text with the highest score
    let plain_text = &plain_text_scores_tuples[0].0;

    Some(plain_text.to_string())
}

pub fn monoalphabetic_vernam_attack_file_variation(path_location: &str) -> String {
    let path = Path::new(path_location);
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
            Ok(cipher_text) => {
                let plain_text = monoalphabetic_vernam_attack(&cipher_text);

                if let Some(p) = plain_text {
                    if high_score == 0 || score(&p) > high_score {
                        high_score = score(&p);
                        plain_text_with_high_score = p;
                    }
                }
            }
            Err(why) => println!("error reading line: {}", why),
        }
    }

    plain_text_with_high_score
}

#[derive(Eq, PartialEq)]
struct SizeDistancePair(i32, i32);

impl Ord for SizeDistancePair {
    fn cmp(&self, other: &Self) -> Ordering {
        other.1.cmp(&self.1) // min heap
    }
}

impl PartialOrd for SizeDistancePair {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

// TODO: rust docs?
pub fn polyalphabetic_vernam_attack(path_location: &str) -> &str {
    // take in a file of base64 encoded strings
    // decode the strings into bytes
    let path = path::Path::new(path_location);
    let display = path.display();
    let file = match fs::File::open(path) {
        Err(why) => panic!("couldn't open {}: {}", display, why),
        Ok(file) => file,
    };
    let contents = io::BufReader::new(file)
        .lines()
        .map(|line| line.unwrap())
        .collect::<Vec<String>>()
        .join("");

    let cipher_text_bytes = encode::base64::Base64ToByteDecoder::new(contents.chars())
        .collect::<Result<Vec<u8>, io::Error>>()
        .unwrap();

    let mut min_hamming_distances = collections::BinaryHeap::new();
    for key_size in 2..40 {
        let chunk_one = "".bytes();
        let chunk_two = "".bytes();

        let hamming_distance = encode::hamming_distance(chunk_one, chunk_two).unwrap();
        let hamming_distance_normalized = hamming_distance as i32 / key_size;

        min_hamming_distances.push(SizeDistancePair(key_size, hamming_distance_normalized));
    }

    // take the smallest 3 hamming distances
    let keys_with_smallest_hamming_distances: Vec<_> = min_hamming_distances
        .into_iter()
        .take(3)
        .map(|pair| pair.0)
        .collect();

    // break the ciphertext into blocks of key_size length
    //  Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    let transposed_blocks: Vec<Vec<u8>> = Vec::new();

    // for b in transposed_blocks {
    //     // solve each block as if it was single-character XOR
    //     // the single-byte (char) XOR key is the most likely key for that block
    //     let plain_text = single_byte_xor_attack(b);
    //     println!("attack single byte XOR: {}", plain_text.unwrap());
    // }

    // put them togethter for each transposed block and you have the key
    todo!()
}
