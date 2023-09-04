// The MD5 message-digest algorithm takes as input a message of arbitrary length
// and produces as output a 128-bit "fingerprint" or "message digest" of the input.

// The MD5 algorithm is an extension of the MD4 message-digest algorithm.
// MD5 is slightly slower than MD4, but is more "conservative" in
// design. MD5 was designed because it was felt that MD4 was perhaps
// being adopted for use more quickly than justified by the existing
// critical review; because MD4 was designed to be exceptionally fast,
// it is "at the edge" in terms of risking successful cryptanalytic
// attack. MD5 backs off a bit, giving up a little in speed for a much
// greater likelihood of ultimate security. It incorporates some
// suggestions made by various reviewers, and contains additional
// optimizations. The MD5 algorithm is being placed in the public domain
// for review and possible adoption as a standard.

// see more: https://www.ietf.org/rfc/rfc1321.txt
fn md5(input: Vec<u8>) -> Vec<u8> {
    // 1. padding
    let mut output = input.clone();
    output.push(0x01);
    while input.len() % 512 != 448 {
        output.push(0x00);
    }

    // 2. append length
    let len: u64 = input.len().try_into().unwrap();
    let len_bytes = len.to_be_bytes();

    for i in (0..4).rev() {
        output.push(len_bytes[i]);
    }

    for i in (4..8).rev() {
        output.push(len_bytes[i]);
    }

    // 3. init buffer
    let word_a = vec![0x01u8, 0x23u8, 0x45u8, 0x67u8];
    let word_b = vec![0x89u8, 0xabu8, 0xcdu8, 0xefu8];
    let word_c = vec![0xfeu8, 0xdcu8, 0xbau8, 0x98u8];
    let word_d = vec![0x76u8, 0x54u8, 0x32u8, 0x10u8];
    let buffer = [word_a, word_b, word_c, word_d];

    // 4. process message in 16 word blocks
    // 5. output

    todo!()
}
