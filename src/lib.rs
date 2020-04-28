#![allow(dead_code)]

use itertools::Itertools;

use crypto::buffer::WriteBuffer as _;
use crypto::symmetriccipher::BlockEncryptor as _;
use crypto::symmetriccipher::BlockDecryptor as _;

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

pub fn aes_128_ecb_dec(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut dec = crypto::aes::ecb_decryptor(
        crypto::aes::KeySize::KeySize128,
        key,
        crypto::blockmodes::PkcsPadding,
    );

    let mut data_buf = crypto::buffer::RefReadBuffer::new(&input);

    let mut output = vec![0_u8; input.len()];
    let mut output_buf = crypto::buffer::RefWriteBuffer::new(&mut output);

    dec.decrypt(&mut data_buf, &mut output_buf, true).unwrap();

    let pos = output_buf.position();
    output.truncate(pos);

    output
}

pub fn aes_128_cbc_enc(mut input: Vec<u8>, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let dec = crypto::aessafe::AesSafe128Decryptor::new(key);

    pkcs7_padding(&mut input, 16);
    
    let mut previous = [0u8; 16usize];
    previous.copy_from_slice(iv);

    let mut ret = Vec::new();

    for chunk in input.chunks_exact(16) {
        let mut result = [0_u8; 16_usize];

        dec.decrypt_block(&chunk, &mut result);

        let xored = xor(&previous, &result);

        ret.extend(&xored);
        previous.copy_from_slice(&chunk);
    }

    ret
}

pub fn aes_128_cbc_dec(mut input: Vec<u8>, key: &[u8], iv: &[u8]) -> Vec<u8> {
    let dec = crypto::aessafe::AesSafe128Decryptor::new(key);

    pkcs7_padding(&mut input, 16);
    
    let mut previous = [0u8; 16usize];
    previous.copy_from_slice(iv);

    let mut ret = Vec::new();

    for chunk in input.chunks_exact(16) {
        let mut result = [0_u8; 16_usize];

        dec.decrypt_block(&chunk, &mut result);

        let xored = xor(&previous, &result);

        ret.extend(&xored);
        previous.copy_from_slice(&chunk);
    }

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
    let mut tries: Vec<Vec<u8>> = (0..=255)
        .map(|val| xor(&input, &[val]))
        .map(|mut x| x.to_ascii_lowercase())
        .collect::<Vec<_>>();

    tries
        .into_iter()
        .enumerate()
        .max_by_key(|(idx, x)| english_score(x))
        .unwrap()
        .0 as u8
}

pub fn pkcs7_padding(input: &mut Vec<u8>, pad_to: usize) {
    let padding_required = pad_to - input.len() % pad_to;
    assert!(padding_required <= 255);

    for _ in 0..padding_required {
        input.push(padding_required as u8)
    }

    assert!(input.len() % pad_to == 0);
}


#[test]
fn challenge1() {
    assert_eq!(
        hex_to_b64(
            "49276d206b696c6c696e6720796f757220627261696e206c\
                 696b65206120706f69736f6e6f7573206d757368726f6f6d"
        ),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
}

#[test]
fn challenge2() {
    let a = hex::decode("1c0111001f010100061a024b53535009181c").unwrap();
    let b = hex::decode("686974207468652062756c6c277320657965").unwrap();
    let c = xor(&a, &b);

    assert_eq!(
        c,
        hex::decode("746865206b696420646f6e277420706c6179").unwrap()
    );
}

#[test]
fn challenge3() {
    let input = hex::decode("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")
        .unwrap();

    let key = solve_sc(&input);

    let solved = xor(&input, &[key]);

    let s = std::str::from_utf8(&solved).unwrap();

    assert_eq!(s, "Cooking MC's like a pound of bacon");
}

#[test]
fn challenge4() {
    let inputs = include_str!("4.txt")
        .split("\n")
        .map(|x| hex::decode(x).unwrap());

    let mut tries: Vec<Vec<u8>> = (0..=255)
        .cartesian_product(inputs)
        .map(|(byte, line)| xor(&line, &[byte]))
        .collect();

    let item = tries.iter().max_by_key(|x| english_score(x)).unwrap();

    let s = std::str::from_utf8(item).unwrap();

    assert_eq!(s, "Now that the party is jumping\n");
}

#[test]
fn challenge5() {
    let plain = b"Burning 'em, if you ain't quick and nimble\nI go crazy \
        when I hear a cymbal";

    let hexencoded = hex::encode(xor(plain, b"ICE"));

    assert_eq!(
        hexencoded,
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a2622632427276527\
             2a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );
}

#[test]
fn challenge6_hammingdist() {
    assert_eq!(hamming_dist(b"this is a test", b"wokka wokka!!!"), 37);
}

#[test]
fn challenge6() {
    // modified from b64 to hex because base64 couldn't decode the base64
    //
    let data = hex::decode(include_str!("6.txt")).unwrap();

    let expected_keysize = (2..=40)
        .min_by_key(|&keysize| {
            data.chunks_exact(keysize * 2)
                .map(|x| {
                    let left = &x[0..keysize];
                    let right = &x[keysize..];
                    assert_eq!(left.len(), right.len());
                    hamming_dist(left, right)
                })
                .sum::<u32>()
        })
        .unwrap();

    assert_eq!(expected_keysize, 29);

    let cipher_blocks = data.chunks(expected_keysize);

    let mut final_key = Vec::new();

    for idx in 0..expected_keysize {
        let mut new_block = Vec::new();

        for cb in cipher_blocks.clone() {
            if let Some(b) = cb.get(idx) {
                new_block.push(*b);
            }
        }

        let new_b_key = solve_sc(&new_block);

        final_key.push(new_b_key);
    }

    let result = String::from_utf8(xor(&data, &final_key)).unwrap();

    assert_eq!(&result,
        "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n");
}

#[test]
fn challenge7() {
    let data = hex::decode(include_str!("7.txt")).unwrap();

    let result = aes_128_ecb_dec(&data, b"YELLOW SUBMARINE");

    let rstring = String::from_utf8(result).unwrap();

    assert_eq!(&rstring, "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n");
}

#[test]
fn challenge8() {
    let data = include_str!("8.txt")
        .split("\n")
        .map(|x| hex::decode(x).unwrap());

    for (idx, line) in data.enumerate() {
        let mut found = std::collections::HashSet::new();
        let mut expected = 0;
        let chunks = line.chunks_exact(16);
        for chunk in chunks {
            found.insert(chunk);
            expected += 1;
        }

        if expected != found.len() {
            println!("maybe line {}", hex::encode(&line));
            println!(
                "I was expecting {} unique 16 byte chunks but found {}",
                expected,
                found.len()
            );

            assert_eq!(expected, 10);
            assert_eq!(found.len(), 7);

            let mut found = std::collections::HashSet::new();
            for chunk in line.chunks_exact(16) {
                println!(
                    "{}{}",
                    if found.contains(chunk) { "*" } else { " " },
                    hex::encode(chunk)
                );
                found.insert(chunk);
            }

            return;
        }
    }

    panic!("couldn't find line")
}

#[test]
fn challenge9() {
    let mut input = b"YELLOW SUBMARINE".to_vec();

    pkcs7_padding(&mut input, 20);

    assert_eq!(input, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}

#[test]
fn challenge10() {
    let mut input = hex::decode(include_str!("10.txt")).unwrap();

    let result = aes_128_cbc_dec(input, b"YELLOW SUBMARINE", &[0u8; 16]);

    let rstring = String::from_utf8_lossy(&result);

    assert_eq!(rstring, "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n\u{4}\u{4}\u{4}\u{4}ܝ]�o��\u{1d}���<�");
}

#[test]
fn challenge11() {

}
