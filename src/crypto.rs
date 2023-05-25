use crate::encode;

// fn xor() {
//     let a = encode::HexToByteDecoder::new("1c0111001f010100061a024b53535009181c");
//     let b = encode::HexToByteDecoder::new("686974207468652062756c6c277320657965");
//     let c = a
//         .unwrap()
//         .zip(b.unwrap())
//         .map(|(x, y)| x ^ y)
//         .collect::<Vec<u8>>();

//     let c_pretty_print = encode::ByteToHexEncoder::new(c.into_iter()).collect::<String>();
//     println!("{}", c_pretty_print);
// }
