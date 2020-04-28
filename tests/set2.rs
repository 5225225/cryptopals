#![allow(dead_code)]

use itertools::Itertools;

use crypto::buffer::WriteBuffer as _;
use crypto::symmetriccipher::BlockEncryptor as _;
use crypto::symmetriccipher::BlockDecryptor as _;

use cryptopals::*;

#[test]
fn challenge9() {
    let mut input = b"YELLOW SUBMARINE".to_vec();

    pkcs7_padding(&mut input, 20);

    assert_eq!(input, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}

#[test]
fn challenge10() {
    let mut input = hex::decode(include_str!("10.txt")).unwrap();

    let result = aes_128_cbc_dec(&input, b"YELLOW SUBMARINE", &[0u8; 16]);

    let rstring = String::from_utf8(result).unwrap();

    assert_eq!(rstring, "I\'m back and I\'m ringin\' the bell \nA rockin\' on the mike while the fly girls yell \nIn ecstasy in the back of me \nWell that\'s my DJ Deshay cuttin\' all them Z\'s \nHittin\' hard and the girlies goin\' crazy \nVanilla\'s on the mike, man I\'m not lazy. \n\nI\'m lettin\' my drug kick in \nIt controls my mouth and I begin \nTo just let it flow, let my concepts go \nMy posse\'s to the side yellin\', Go Vanilla Go! \n\nSmooth \'cause that\'s the way I will be \nAnd if you don\'t give a damn, then \nWhy you starin\' at me \nSo get off \'cause I control the stage \nThere\'s no dissin\' allowed \nI\'m in my own phase \nThe girlies sa y they love me and that is ok \nAnd I can dance better than any kid n\' play \n\nStage 2 -- Yea the one ya\' wanna listen to \nIt\'s off my head so let the beat play through \nSo I can funk it up and make it sound good \n1-2-3 Yo -- Knock on some wood \nFor good luck, I like my rhymes atrocious \nSupercalafragilisticexpialidocious \nI\'m an effect and that you can bet \nI can take a fly girl and make her wet. \n\nI\'m like Samson -- Samson to Delilah \nThere\'s no denyin\', You can try to hang \nBut you\'ll keep tryin\' to get my style \nOver and over, practice makes perfect \nBut not if you\'re a loafer. \n\nYou\'ll get nowhere, no place, no time, no girls \nSoon -- Oh my God, homebody, you probably eat \nSpaghetti with a spoon! Come on and say it! \n\nVIP. Vanilla Ice yep, yep, I\'m comin\' hard like a rhino \nIntoxicating so you stagger like a wino \nSo punks stop trying and girl stop cryin\' \nVanilla Ice is sellin\' and you people are buyin\' \n\'Cause why the freaks are jockin\' like Crazy Glue \nMovin\' and groovin\' trying to sing along \nAll through the ghetto groovin\' this here song \nNow you\'re amazed by the VIP posse. \n\nSteppin\' so hard like a German Nazi \nStartled by the bases hittin\' ground \nThere\'s no trippin\' on mine, I\'m just gettin\' down \nSparkamatic, I\'m hangin\' tight like a fanatic \nYou trapped me once and I thought that \nYou might have it \nSo step down and lend me your ear \n\'89 in my time! You, \'90 is my year. \n\nYou\'re weakenin\' fast, YO! and I can tell it \nYour body\'s gettin\' hot, so, so I can smell it \nSo don\'t be mad and don\'t be sad \n\'Cause the lyrics belong to ICE, You can call me Dad \nYou\'re pitchin\' a fit, so step back and endure \nLet the witch doctor, Ice, do the dance to cure \nSo come up close and don\'t be square \nYou wanna battle me -- Anytime, anywhere \n\nYou thought that I was weak, Boy, you\'re dead wrong \nSo come on, everybody and sing this song \n\nSay -- Play that funky music Say, go white boy, go white boy go \nplay that funky music Go white boy, go white boy, go \nLay down and boogie and play that funky music till you die. \n\nPlay that funky music Come on, Come on, let me hear \nPlay that funky music white boy you say it, say it \nPlay that funky music A little louder now \nPlay that funky music, white boy Come on, Come on, Come on \nPlay that funky music \n");
}

#[test]
fn challenge11() {
    for _ in 0..512 {
        let input = [0u8; 32usize];

        encryption_oracle(input.to_vec(), |encrypted| {
            let first_half = &encrypted[0..15];
            let last_half = &encrypted[16..31];
            
            first_half != last_half
        });
    }
}

#[test]
fn challenge12() {
    let unknown_string = hex::decode(include_str!("12.txt")).unwrap();
    let key: [u8; 16] = rand::random();
    
    let encryptor = |my_string: &[u8]| {
        let mut to_encrypt = Vec::new();

        to_encrypt.extend(my_string);
        to_encrypt.extend(&unknown_string);

        aes_128_ecb_enc(to_encrypt, &key)
    };

    let block_size;

    { // figure out block size
        let mut my_string = Vec::new();
        let baseline_size = encryptor(&my_string).len();
        while encryptor(&my_string).len() == baseline_size {
            my_string.push(0);
        }


        let new_baseline_size = encryptor(&my_string).len();
        while encryptor(&my_string).len() == new_baseline_size {
            my_string.push(0);
        }

        block_size = encryptor(&my_string).len() - new_baseline_size
    }

    assert_eq!(block_size, 16);

    let to_add = vec![0u8; block_size*3];

    let encrypted = encryptor(&to_add);

    let mut chunks = encrypted.chunks_exact(block_size);
    let a = chunks.next().unwrap();
    let b = chunks.next().unwrap();

    assert!(a == b);
    // encrypting same value with same key using ECB gives the same result regardless of position
    
    let decrypt_starting_with = |input: &[u8]| {
        assert!(input.len() < block_size);

        let mut guess = Vec::new();
        guess.resize_with(block_size - 1 - input.len(), || 0);

        println!("{:?}", &guess);
        let encrypted = encryptor(&guess);
        let encblock1 = &encrypted[0..block_size];

        for last_byte in 0..=255 {
            let mut new = Vec::new();
            new.resize_with(block_size - 1 - input.len(), || 0);
            new.extend(input);
            new.push(last_byte);

            assert!(new.len() == block_size);
            let encrypted_try = encryptor(&new);
            let encblock1_try = &encrypted_try[0..block_size];
            if encblock1_try == encblock1 {
                return last_byte;
            }
        }

        panic!("could not find encrypted byte");
    };

    assert_eq!(decrypt_starting_with(&[]), b'R');

    let mut guess = Vec::new();
    for _ in 0..block_size-1 {
        let ch = decrypt_starting_with(&guess);
        guess.push(ch);
    }
    
    panic!("{:?}", guess);
}
