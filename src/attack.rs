use std::{
    cmp::Ordering,
    collections::{self, HashMap},
    fs,
    io::{self, BufRead},
    path::{self, Path},
};

use crate::{
    crypto,
    encode::{
        self,
        hex::{self, ByteToHexEncoder},
    },
};

const ENGLISH_FREQ: &str = "QZXJKVBWPYGMCFULDRHS NIOTAE";
pub fn score(s: &str) -> i32 {
    s.chars().fold(0, |acc, c| {
        if ENGLISH_FREQ.contains(c) {
            return acc + ENGLISH_FREQ.chars().position(|x| x == c).unwrap() as i32 + 1;
        }

        acc
    })
}

pub fn monoalphabetic_vernam_attack(cipher_text_hex: &str) -> Option<(Vec<u8>, String)> {
    let cipher_text = encode::hex::HexToByteDecoder::new(cipher_text_hex.chars())
        .collect::<Result<Vec<u8>, io::Error>>()
        .unwrap();

    // ciphertext: 1111 0000
    // keyspace:   0000 0001
    // plaintext:  1111 0001
    let mut plain_text_scores: HashMap<(Vec<u8>, String), i32> = HashMap::new();

    // brute force through the key space
    let key_space = (0..=255).collect::<Vec<u8>>();
    for k in key_space {
        // f(c, k) = p
        // f = xor cipher
        // p = plain text
        // c = cipher text
        // k = key
        let c = cipher_text.clone().into_iter();
        let k = std::iter::repeat(k)
            .take(cipher_text.len())
            .collect::<Vec<u8>>()
            .into_iter();

        let plain_bytes = crypto::XorCipher::new(c, k.clone())
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();

        let plain_text = String::from_utf8(plain_bytes.clone());

        // check if plain bytes are invalid utf8
        if plain_text.is_err() {
            continue;
        }

        // convert bytes to string, calculate the score, and store it in the map
        let plain_text = plain_text.unwrap();
        let score = score(&plain_text);
        plain_text_scores.insert((k.collect(), plain_text), score);
    }

    // sort the map by score
    let mut plain_text_scores_tuples = plain_text_scores
        .into_iter()
        .collect::<Vec<((Vec<u8>, String), i32)>>();
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

    if !&plain_text_scores_tuples[0].0 .1.as_bytes().is_ascii() {
        return None;
    }

    // select the plain text with the highest score
    let key_plain_text_tuple = &plain_text_scores_tuples[0].0;
    Some(key_plain_text_tuple.clone())
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

                if let Some((k, p)) = plain_text {
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
pub fn polyalphabetic_vernam_attack(path_location: &str) -> String {
    // employing hamming distance variation of the kasiski attack
    let cipher_text_bytes = parse_and_decode_file(path_location);
    let probable_key_size = find_probable_key_size(&cipher_text_bytes);
    let probable_key = find_probable_key(&cipher_text_bytes, probable_key_size);

    // println!("{:?}", cipher_text_bytes);
    // println!("{:?}", probable_key_size);
    // println!("{:?}", probable_key);

    let plain_bytes =
        crypto::XorCipher::new(cipher_text_bytes.into_iter(), probable_key.into_iter())
            .collect::<Result<Vec<u8>, io::Error>>()
            .unwrap();
    let plain_text = String::from_utf8(plain_bytes).unwrap();
    plain_text
}

fn parse_and_decode_file(path_location: &str) -> Vec<u8> {
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

    cipher_text_bytes
}

fn find_probable_key_size(cipher_text_bytes: &[u8]) -> i32 {
    let mut min_hamming_distances = collections::BinaryHeap::new();
    for key_size in 2..40 {
        // assuming Alice and Bob aren't aware of Shannon's perfect secrecy
        // ==> key length < 40
        let chunk_one = cipher_text_bytes[0..key_size].to_vec().into_iter();
        let chunk_two = cipher_text_bytes[key_size..key_size * 2]
            .to_vec()
            .into_iter();

        let hamming_distance = encode::hamming_distance(chunk_one, chunk_two).unwrap();
        let hamming_distance_normalized = hamming_distance as i32 / key_size as i32;

        min_hamming_distances.push(SizeDistancePair(
            key_size as i32,
            hamming_distance_normalized,
        ));
    }

    // take the smallest 3 hamming distances
    let keys_with_smallest_hamming_distances: Vec<_> = min_hamming_distances
        .into_iter()
        .take(3)
        .map(|pair| pair.0)
        .collect();

    let probable_key_size = keys_with_smallest_hamming_distances[0]; // take the first
    probable_key_size
}

fn find_probable_key(cipher_text_bytes: &[u8], probable_key_size: i32) -> Vec<u8> {
    // chunk the ciphertext into blocks the same size of the probable key
    let chunks: Vec<Vec<u8>> = cipher_text_bytes
        .chunks(probable_key_size as usize)
        .map(|chunk| chunk.to_vec())
        .collect();

    // now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    let transposed_blocks: Vec<Vec<u8>> = (0..probable_key_size)
        .enumerate()
        .map(|(i, _)| {
            chunks
                .iter()
                .filter_map(|chunk| {
                    if i < chunk.len() {
                        Some(chunk[i])
                    } else {
                        None
                    }
                })
                .collect()
        }) // for each row, grab col[i]
        .collect();

    let probable_key = transposed_blocks
        .iter()
        .map(|b| {
            // solve each block as if it were monoalphabetic_vernam
            // the single-byte (char) XOR key is the most likely key for that block
            // let s = String::from_utf8(b.clone()).unwrap();
            let hex_encoded_bytes = encode::hex::ByteToHexEncoder::new(b.clone().into_iter())
                .collect::<Result<String, io::Error>>()
                .unwrap();

            let plain_text = monoalphabetic_vernam_attack(&hex_encoded_bytes);
            plain_text.unwrap().0
        })
        .flat_map(|v: Vec<u8>| v.into_iter())
        .collect();

    probable_key
}
