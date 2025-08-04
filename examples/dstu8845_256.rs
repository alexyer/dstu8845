use cipher::{KeyIvInit, StreamCipher};
use dstu8845::Dstu8845_256;

fn main() {
    let key = Dstu8845_256::generate_key().unwrap();
    let iv = Dstu8845_256::generate_iv().unwrap();

    let mut encoder = Dstu8845_256::new(&key, &iv);

    let mut text = b"Hello World".to_vec();

    encoder.apply_keystream(text.as_mut_slice());

    assert_ne!(text.as_slice(), b"Hello World".as_slice());

    // does not support seeking
    let mut decoder = Dstu8845_256::new(&key, &iv);
    decoder.apply_keystream(text.as_mut_slice());

    assert_eq!(text.as_slice(), b"Hello World".as_slice());
}
