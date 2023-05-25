use fuin::encode::{ByteToHexEncoder, HexToByteDecoder};

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

    let a = HexToByteDecoder::new("1c0111001f010100061a024b53535009181c");
    let b = HexToByteDecoder::new("686974207468652062756c6c277320657965");
    let c = a
        .unwrap()
        .zip(b.unwrap())
        .map(|(x, y)| x ^ y)
        .collect::<Vec<u8>>();

    let c_pretty_print = ByteToHexEncoder::new(c.into_iter()).collect::<String>();
    println!("{}", c_pretty_print);
}
