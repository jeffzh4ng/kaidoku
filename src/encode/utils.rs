pub fn char_to_bytes(c: char) -> Vec<u8> {
    let mut bytes = [0u8; 4]; // buffer of byte 4 is large enough to encode any char
    c.encode_utf8(&mut bytes);
    bytes.into()
}
