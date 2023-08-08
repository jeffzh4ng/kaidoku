use std::{
    cmp::Ordering,
    collections::{self, HashMap},
    fs,
    io::{self, BufRead},
    path::{self, Path},
};

use crate::{crypto, encode};

use thiserror::Error;

#[non_exhaustive]
#[derive(Debug, Error)]
pub enum VernamAttackError {
    #[error("plain text with highest score is invalid ASCII")]
    PlainTextAsciiError,

    #[error(transparent)]
    HexError(#[from] encode::hex::HexEncodingError),

    #[error(transparent)]
    VernamError(#[from] crypto::stream::VernamCipherError),

    #[error(transparent)]
    IoError(#[from] io::Error),
}

const ENGLISH_FREQ: &str = "QZXJKVBWPYGMCFULDRHS NIOTAE";
pub fn score(s: &str) -> i32 {
    s.chars().fold(0, |acc, c| {
        if let Some(p) = ENGLISH_FREQ.chars().position(|x| x == c) {
            acc + (p as i32 + 1)
        } else {
            acc
        }
    })
}

pub fn monoalphabetic_attack(
    cipher_text_hex: &str,
) -> Result<Option<(u8, String)>, VernamAttackError> {
    let cipher_text = encode::hex::HexToByteDecoder::new(cipher_text_hex.chars())
        .collect::<Result<Vec<u8>, encode::hex::HexEncodingError>>()?;

    // ciphertext: 1111 0000
    // keyspace:   0000 0001
    // plaintext:  1111 0001
    let mut plain_text_scores: HashMap<(u8, String), i32> = HashMap::new();

    // brute force through the key space
    let key_space = (0..=255).collect::<Vec<u8>>();
    for k in key_space {
        // f(c, k) = p
        // f = xor cipher
        // p = plain text
        // c = cipher text
        // k = key
        let c = cipher_text.clone().into_iter();
        let k_stretched = std::iter::repeat(k).take(cipher_text.len());

        let plain_bytes = crypto::stream::VernamCipher::new(c, k_stretched.clone())
            .collect::<Result<Vec<u8>, crypto::stream::VernamCipherError>>()?;

        // convert bytes to string, calculate the score, and store it in the map
        let plain_text = String::from_utf8(plain_bytes);

        // check if plain bytes are invalid utf8
        if plain_text.is_err() {
            continue;
        }

        // convert bytes to string, calculate the score, and store it in the map
        let plain_text = plain_text.unwrap();

        let score = score(&plain_text);
        plain_text_scores.insert((k, plain_text), score);
    }

    // sort the map by score
    let mut plain_text_scores_tuples = plain_text_scores
        .into_iter()
        .collect::<Vec<((u8, String), i32)>>();
    plain_text_scores_tuples.sort_by(|a, b| b.1.cmp(&a.1));

    if plain_text_scores_tuples.is_empty() {
        return Ok(None);
    }

    // if there's a tie, warn
    if plain_text_scores_tuples[0].1 == plain_text_scores_tuples[1].1 {
        println!("warning: there's a tie");
        println!("one: {:?}", &plain_text_scores_tuples[0].0);
        println!("two: {:?}", &plain_text_scores_tuples[1].0);
    }

    if !&plain_text_scores_tuples[0].0 .1.as_bytes().is_ascii() {
        return Err(VernamAttackError::PlainTextAsciiError);
    }

    // select the plain text with the highest score
    let key_plain_text_tuple = &plain_text_scores_tuples[0].0;
    Ok(Some(key_plain_text_tuple.clone()))
}

pub fn monoalphabetic_attack_file_variation(
    path_location: &str,
) -> Result<String, VernamAttackError> {
    let path = Path::new(path_location);
    let file = fs::File::open(path)?;

    let reader = io::BufReader::new(file);
    let plain_text_with_high_score = reader
        .lines()
        .collect::<Result<Vec<String>, io::Error>>()?
        .into_iter()
        .map(|cipher_text| monoalphabetic_attack(&cipher_text))
        .filter_map(Result::ok)
        .fold((0, String::new()), |(high_score, x), score_option| {
            if let Some((_k, y)) = score_option {
                if high_score == 0 || score(&y) > high_score {
                    return (score(&y), y);
                }
            }

            (high_score, x)
        });

    Ok(plain_text_with_high_score.1)
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

pub fn polyalphabetic_attack(path_location: &str) -> String {
    // employing hamming distance variation of the kasiski attack
    let cipher_text_bytes = parse_and_decode_file(path_location);
    let probable_key_size = find_probable_key_size(&cipher_text_bytes);
    let probable_key = find_probable_key(&cipher_text_bytes, probable_key_size);

    // TODO: make decrypt function for plain bytes
    let probable_key_stretched = probable_key
        .into_iter()
        .cycle()
        .take(cipher_text_bytes.len());

    let plain_bytes =
        crypto::stream::VernamCipher::new(cipher_text_bytes.into_iter(), probable_key_stretched)
            .collect::<Result<Vec<u8>, crypto::stream::VernamCipherError>>()
            .unwrap();
    let plain_text = String::from_utf8(plain_bytes).unwrap();

    plain_text
}

fn parse_and_decode_file(path_location: &str) -> Vec<u8> {
    let path = path::Path::new(path_location);
    let file = fs::File::open(path).unwrap();
    let contents = io::BufReader::new(file)
        .lines()
        .map(|line| line.unwrap())
        .collect::<Vec<String>>()
        .join("");

    let cipher_text_bytes = encode::base64::Base64ToByteDecoder::new(contents.chars())
        .collect::<Result<Vec<u8>, encode::base64::Base64Error>>()
        .unwrap();

    cipher_text_bytes
}

fn find_probable_key_size(cipher_text_bytes: &[u8]) -> i32 {
    let mut min_hamming_distances = collections::BinaryHeap::new();
    // println!("c: {:?}", cipher_text_bytes);
    for key_size in 2..40 {
        // assuming Alice and Bob aren't aware of Shannon's perfect secrecy
        // ==> key length < 40
        let chunks = [
            cipher_text_bytes[0..key_size].iter().copied(),
            cipher_text_bytes[key_size..key_size * 2].iter().copied(),
            cipher_text_bytes[key_size * 2..key_size * 3]
                .iter()
                .copied(),
            cipher_text_bytes[key_size * 3..key_size * 4]
                .iter()
                .copied(),
        ];
        let mut sum = 0;
        for i in 0..chunks.len() {
            for j in i + 1..chunks.len() {
                let s = encode::hamming::distance(chunks[i].clone(), chunks[j].clone()).unwrap();
                sum += s
            }
        }

        let hamming_distance_normalized = sum / key_size;

        min_hamming_distances.push(SizeDistancePair(
            key_size as i32,
            hamming_distance_normalized as i32,
        ));
    }

    // take the smallest 3 hamming distances
    let keys_with_smallest_hamming_distances: Vec<_> = min_hamming_distances
        .into_iter()
        .take(5)
        .map(|pair| pair.0)
        .collect();

    let probable_key_size = keys_with_smallest_hamming_distances[0]; // take the first
    probable_key_size
}

fn find_probable_key(cipher_text_bytes: &[u8], probable_key_size: i32) -> Vec<u8> {
    // chunk the ciphertext into blocks with the same size as the probable key
    let chunks: Vec<Vec<u8>> = cipher_text_bytes
        .chunks(probable_key_size as usize)
        .map(|chunk| chunk.to_vec())
        .collect();

    // now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
    let transposed_chunks: Vec<Vec<u8>> = (0..probable_key_size)
        .enumerate()
        .map(|(r, _)| {
            chunks
                .iter()
                .filter_map(|chunk| {
                    if r < chunk.len() {
                        Some(chunk[r])
                    } else {
                        None
                    }
                })
                .collect()
        }) // for each row, grab col[i]
        .collect();

    let probable_key = transposed_chunks
        .iter()
        .map(|b| {
            // solve each block as if it were monoalphabetic_vernam
            // the single-byte (char) XOR key is the most likely key for that block
            // let s = String::from_utf8(b.clone()).unwrap();
            let hex_encoded_bytes = encode::hex::ByteToHexEncoder::new(b.clone().into_iter())
                .collect::<Result<String, encode::hex::HexEncodingError>>()
                .unwrap();

            let key_plain_text_tuple = monoalphabetic_attack(&hex_encoded_bytes);
            key_plain_text_tuple.unwrap().unwrap().0
        })
        .collect();

    probable_key
}
