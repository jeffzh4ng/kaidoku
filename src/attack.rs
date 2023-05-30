use std::{collections::HashMap, io};

use crate::crypto;

pub fn single_byte_xor_attack(cipher_text: Vec<u8>) -> String {
    const FOO: &str = "ETAOIN SHRDLU";
    fn score(s: &str) -> i32 {
        s.chars().fold(0, |acc, c| {
            if FOO.contains(c) {
                return acc + 1;
            }

            acc
        })
    }

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

        // check if plain bytes are invalid utf8
        if String::from_utf8(plain_bytes.clone()).is_err() {
            continue;
        }

        // convert bytes to string, calculate the score, and store it in the map
        let plain_text = String::from_utf8(plain_bytes).unwrap();
        let score = score(&plain_text);
        plain_text_scores.insert(plain_text, score);
    }

    // sort the map by score
    let mut plain_text_scores_tuples = plain_text_scores
        .into_iter()
        .collect::<Vec<(String, i32)>>();
    plain_text_scores_tuples.sort_by(|a, b| b.1.cmp(&a.1));

    // select the plain text with the highest score
    let plain_text = &plain_text_scores_tuples[0].0;

    plain_text.to_string()
}
