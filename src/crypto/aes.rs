pub fn aes_encrypt(plaintext: Vec<u8>, key: &str) -> String {
    // add_round_key(state);
    //
    // for round in (0..10) {
    // sub_bytes(state);
    // shift_rows(state);
    // mix_cols(state);
    // add_round_key(state);
    // }
    //
    // sub_bytes(state);
    // shift_rows(state);
    // add_round_key(state);

    todo!()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn foo() {
        assert_eq!(1, 1);
    }
}
