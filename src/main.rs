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

    println!("=========================================================");

    println!("Set 1: Basics");
    println!("---");
    println!("1. convert hex to base64");
    let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    let le_bytes = hex_to_bytes(&hex);
    let b64 = bytes_to_base64(&le_bytes);

    println!("input: {:?}", hex);
    println!("output: {:?}", b64);
    println!("---");
}

fn hex_to_bytes(s: &str) -> Vec<u8> {
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

    let hex_to_nibble = |c: &char| -> Option<&u8> { hex_map.get(c) };

    let mut le_bs = Vec::new();
    // process the hex-encoded string in chunks of 2
    for le_w in s.chars().rev().collect::<Vec<char>>().chunks(2) {
        // 1. reverse the reversed chunk for big endian ordering
        let be_w = le_w.iter().rev().collect::<Vec<&char>>();

        // 2. convert two hex-encoded chars into high and low nibbles
        let high = hex_to_nibble(be_w[0]).unwrap();
        let low = hex_to_nibble(be_w[1]).unwrap();

        // 3. push the byte into the little-endian ordered byte vector
        le_bs.push(high << 4 | low)
    }

    le_bs
}

fn bytes_to_base64(bytes: &[u8]) -> String {
    const B64_MAP: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    fn u32_to_four_b64s(w: u32) -> Vec<char> {
        let mask = 0b111111;
        let one = w >> 18;
        let two = (w >> 12) & mask;
        let three = (w >> 6) & mask;
        let four = w & mask;

        // convert u32s to base64 chars
        let one = B64_MAP.chars().nth(one as usize).unwrap();
        let two = B64_MAP.chars().nth(two as usize).unwrap();
        let three = B64_MAP.chars().nth(three as usize).unwrap();
        let four = B64_MAP.chars().nth(four as usize).unwrap();

        Vec::from([four, three, two, one])
    }

    let mut b64_string = VecDeque::new();

    // process bytes in groups of three
    for w in bytes.chunks(3) {
        let mut three_bytes: Vec<u8> = Vec::from([0, 0, 0]);
        for (i, b) in w.iter().enumerate() {
            three_bytes[i] = *b;
        }

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
