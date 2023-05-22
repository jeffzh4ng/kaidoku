use std::collections::{HashMap, VecDeque};

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

    println!("rusty cryptopals");
    println!("=========================================================");

    println!("Set 1: Basics");
    println!("---");
    println!("1. convert hex to base64");
    let hex_s = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let le_bs = hex_to_bytes(&hex_s);
    let b64_s = bytes_to_base64(&le_bs);

    println!("input: {:?}", hex_s);
    println!("output: {:?}", b64_s);
    println!("---");
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
    fn hex_to_nibble(c: &char) -> Option<u8> {
        let hex_map: HashMap<char, u8> = HashMap::from([
            ('0', 0x0),
            ('1', 0x1),
            ('2', 0x2),
            ('3', 0x3),
            ('4', 0x4),
            ('5', 0x5),
            ('6', 0x6),
            ('7', 0x7),
            ('8', 0x8),
            ('9', 0x9),
            ('a', 0xA),
            ('b', 0xB),
            ('c', 0xC),
            ('d', 0xD),
            ('e', 0xE),
            ('f', 0xF),
        ]);

        return if let Some((c, b)) = hex_map.get_key_value(&c) {
            Some(*b)
        } else {
            None
        };
    }

    let mut le_bs = Vec::new();

    // process the hex-encoded string in chunks of 2
    for le_w in s.chars().rev().collect::<Vec<char>>().chunks(2) {
        // reverse the reversed chunk for big endian ordering
        let be_w = le_w.iter().rev().collect::<Vec<&char>>();

        // convert two hex-encoded chars into high and low nibbles
        let high = hex_to_nibble(be_w[0]).unwrap();
        let low = hex_to_nibble(be_w[1]).unwrap();

        // push the byte into the little-endian ordered byte vector
        le_bs.push(high << 4 | low)
    }

    le_bs
}

fn bytes_to_base64(bytes: &[u8]) -> String {
    const B64_MAP: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn u32_to_four_b64s(w: u32) -> Vec<char> {
        let one = w >> 18;
        let two = (w >> 12) & 0b000000111111;
        let three = (w >> 6) & 0b000000000000111111;
        let four = w & 0b000000000000000000111111;

        // convert u32s to base64 chars
        let one = B64_MAP.chars().nth(one as usize).unwrap();
        let two = B64_MAP.chars().nth(two as usize).unwrap();
        let three = B64_MAP.chars().nth(three as usize).unwrap();
        let four = B64_MAP.chars().nth(four as usize).unwrap();

        Vec::from([four, three, two, one])
    }

    // process bs in groups of three
    let mut b64_string = VecDeque::new();

    for w in bytes.chunks(3) {
        let three_bytes: &[u8; 3] = w.try_into().unwrap(); // TODO: error handling?

        // merge three_bytes into a u32
        let mut w: u32 = 0;
        for (i, b) in three_bytes.iter().enumerate() {
            w |= (*b as u32) << (i * 8);
        }

        // convert u32 into four base64 chars, ordered little-endian
        let four_b64_chars = u32_to_four_b64s(w);

        // iterating in normal order is fine since four_b64_chars is little-endian
        for b64_char in four_b64_chars {
            b64_string.push_front(b64_char);
        }
    }

    // convert b64 characters into String
    b64_string.into_iter().collect()
}
