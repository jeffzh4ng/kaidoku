use fuin::encode;

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
    let hex = "6d49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    if let Ok(hex_to_byte_decoder) = encode::HexToByteDecoder::new(hex) {
        let byte_to_base64_encoder = encode::ByteToBase64Encoder::new(hex_to_byte_decoder);
        let base64 = byte_to_base64_encoder
            .into_iter()
            .flatten()
            .collect::<String>();

        println!("{base64}");
    }
}
