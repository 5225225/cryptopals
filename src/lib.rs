#![allow(dead_code)]

use crypto::symmetriccipher::BlockDecryptor as _;
use crypto::symmetriccipher::BlockEncryptor as _;

pub fn hex_to_b64(hex: &str) -> String {
    base64::encode(hex::decode(hex).expect("invalid hex"))
}

pub fn xor(a: &[u8], b: &[u8]) -> Vec<u8> {
    a.iter().zip(b.iter().cycle()).map(|(a, b)| a ^ b).collect()
}

pub fn byte_freq(x: &[u8]) -> [u8; 256] {
    let mut result = [0; 256];

    for &byte in x {
        result[byte as usize] += 1;
    }

    result
}

pub fn hamming_dist(a: &[u8], b: &[u8]) -> u32 {
    a.iter().zip(b).map(|(x, y)| (x ^ y).count_ones()).sum()
}

pub fn aes_128_ecb_enc(mut input: Vec<u8>, key: &[u8]) -> Vec<u8> {
    let dec = crypto::aessafe::AesSafe128Encryptor::new(key);

    assert!(key.len() == 16);

    pkcs7_padding(&mut input, 16);

    let mut ret = Vec::new();

    for chunk in input.chunks_exact(16) {
        let mut result = [0_u8; 16_usize];

        dec.encrypt_block(&chunk, &mut result);

        ret.extend(&result);
    }

    ret
}

pub fn aes_128_ecb_dec(input: &[u8], key: &[u8]) -> Vec<u8> {
    let dec = crypto::aessafe::AesSafe128Decryptor::new(key);

    assert!(key.len() == 16);

    let mut ret = Vec::new();

    assert!(input.len() % 16 == 0);
    for chunk in input.chunks_exact(16) {
        let mut result = [0_u8; 16_usize];

        dec.decrypt_block(&chunk, &mut result);

        ret.extend(&result);
    }

    let padding_amount = *ret.last().unwrap();

    assert!(padding_amount <= 16);

    ret.truncate(ret.len() - padding_amount as usize);

    ret
}

pub fn aes_128_cbc_enc(mut input: Vec<u8>, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let dec = crypto::aessafe::AesSafe128Encryptor::new(key);

    pkcs7_padding(&mut input, 16);

    let mut previous = [0u8; 16usize];
    previous.copy_from_slice(iv);

    let mut ret = Vec::new();

    for chunk in input.chunks_exact(16) {
        let mut result = [0_u8; 16_usize];

        let xored = xor(&previous, &chunk);

        dec.encrypt_block(&xored, &mut result);

        ret.extend(&result);
        previous.copy_from_slice(&result);
    }

    ret
}

pub fn aes_128_cbc_dec(input: &[u8], key: &[u8], iv: &[u8]) -> Vec<u8> {
    let dec = crypto::aessafe::AesSafe128Decryptor::new(key);

    assert!(key.len() == 16);
    assert!(iv.len() == 16);

    let mut previous = [0u8; 16usize];
    previous.copy_from_slice(iv);

    let mut ret = Vec::new();

    assert!(input.len() % 16 == 0);
    for chunk in input.chunks_exact(16) {
        let mut result = [0_u8; 16_usize];

        dec.decrypt_block(&chunk, &mut result);

        assert!(previous.len() == result.len());
        let xored = xor(&previous, &result);

        ret.extend(&xored);
        previous.copy_from_slice(&chunk);
    }

    let padding_amount = *ret.last().unwrap();

    assert!(padding_amount <= 16);

    ret.truncate(ret.len() - padding_amount as usize);

    ret
}

pub fn english_score(x: &[u8]) -> impl Ord {
    let freq_table: &[(u8, u32)] = &[
        (b' ', 20000),
        (b'e', 11162),
        (b't', 9356),
        (b'a', 8497),
        (b'r', 7587),
        (b'i', 7546),
        (b'o', 7507),
        (b'n', 6749),
        (b's', 6327),
        (b'h', 6094),
        (b'd', 4253),
        (b'l', 4025),
        (b'u', 2758),
        (b'w', 2560),
        (b'm', 2406),
        (b'f', 2228),
        (b'c', 2202),
        (b'g', 2015),
        (b'y', 1994),
        (b'p', 1929),
        (b'b', 1492),
        (b'k', 1292),
        (b'v', 978),
        (b'j', 153),
        (b'x', 150),
        (b'q', 95),
        (b'z', 77),
    ];

    let mut score = 0;

    for ch in x.iter() {
        if let Some(f) = freq_table.iter().find(|x| x.0 == *ch) {
            score += f.1;
        }
    }

    score
}

pub fn solve_sc(input: &[u8]) -> u8 {
    let tries: Vec<Vec<u8>> = (0..=255)
        .map(|val| xor(&input, &[val]))
        .map(|x| x.to_ascii_lowercase())
        .collect::<Vec<_>>();

    tries
        .into_iter()
        .enumerate()
        .max_by_key(|(_idx, x)| english_score(x))
        .unwrap()
        .0 as u8
}

pub fn pkcs7_padding(input: &mut Vec<u8>, pad_to: usize) {
    let mut padding_required = pad_to - input.len() % pad_to;
    assert!(padding_required <= 255);

    if padding_required == 0 {
        padding_required = pad_to;
    }

    assert!(padding_required <= pad_to);
    for _ in 0..padding_required {
        input.push(padding_required as u8)
    }

    assert!(input.len() % pad_to == 0);
    assert!(*input.last().unwrap() as usize <= pad_to);
}

pub fn kvparse(input: &str) -> Vec<(String, String)> {
    let mut ret = Vec::new();

    for pair in input.split("&") {
        let mut it = pair.splitn(2, "=");
        let key = it.next().unwrap().to_string();
        let value = it.next().unwrap().to_string();

        ret.push((key, value));
    }

    ret
}

pub fn kvencode(input: Vec<(String, String)>) -> String {
    let mut ret = String::new();

    for (key, value) in input {
        ret.push_str(&key);
        ret.push_str("=");
        ret.push_str(&value);
        ret.push_str("&");
    }

    ret.truncate(ret.len() - 1);

    ret
}

pub fn encryption_oracle(input: Vec<u8>, detector: impl FnOnce(&[u8]) -> bool) {
    let key: [u8; 16] = rand::random();
    let iv: [u8; 16] = rand::random();
    let use_cbc = rand::random();

    if use_cbc {
        let encrypted = aes_128_cbc_enc(input, &key, &iv);

        assert!(detector(&encrypted));
    } else {
        let encrypted = aes_128_ecb_enc(input, &key);

        assert!(!detector(&encrypted));
    }
}

#[test]
fn kvtest() {
    let parsed = kvparse("foo=bar&baz=qux&zap=zazzle");

    let my_map = vec![
        ("foo".to_string(), "bar".to_string()),
        ("baz".to_string(), "qux".to_string()),
        ("zap".to_string(), "zazzle".to_string()),
    ];

    assert_eq!(parsed, my_map);
}

pub fn profile_for(x: &str) -> Vec<(String, String)> {
    let mut ret = Vec::new();

    if x.contains(|ch| ch == '&' || ch == '=') {
        panic!("invalid email");
    }

    ret.push(("email".to_string(), x.to_string()));
    ret.push(("uid".to_string(), "10".to_string()));
    ret.push(("role".to_string(), "user".to_string()));

    ret
}

use proptest::prelude::*;
proptest! {
    #[test]
    fn aes_128_cbc_roundtrip(input: Vec<u8>, key: [u8; 16], iv: [u8; 16]) {
        let encrypted = aes_128_cbc_enc(input.clone(), &key, &iv);
        let decrypted = aes_128_cbc_dec(&encrypted, &key, &iv);

        assert_eq!(input, decrypted);
    }

    #[test]
    fn aes_128_ecb_roundtrip(input: Vec<u8>, key: [u8; 16]) {
        let encrypted = aes_128_ecb_enc(input.clone(), &key);
        let decrypted = aes_128_ecb_dec(&encrypted, &key);

        assert_eq!(input, decrypted);
    }
}
