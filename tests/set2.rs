#![allow(dead_code)]

use cryptopals::*;

#[test]
fn challenge9() {
    let mut input = b"YELLOW SUBMARINE".to_vec();

    pkcs7_padding(&mut input, 20);

    assert_eq!(input, b"YELLOW SUBMARINE\x04\x04\x04\x04");
}

#[test]
fn challenge10() {
    let input = hex::decode(include_str!("10.txt")).unwrap();

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

    {
        // figure out block size
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

    let to_add = vec![0u8; block_size * 3];

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
    for _ in 0..block_size - 1 {
        let ch = decrypt_starting_with(&guess);
        guess.push(ch);
    }

    // now we know the first block_size bytes, we can use that to brute force the rest of them
    //
    // We want to get the value of encrypt_block where the first block_size-1 bytes are *known*,
    // and the last one is not.
    //
    let message_length = encryptor(&[]).len();

    for decrypt_idx in block_size - 1..message_length {
        let padding_amount = (block_size - ((decrypt_idx + 1) % block_size)) % block_size;

        // unknown_string[decrypt_idx] must be at the end of a block
        assert_eq!((padding_amount + decrypt_idx) % block_size, block_size - 1);
        assert!(padding_amount < block_size);

        if decrypt_idx % block_size == block_size - 1 {
            assert!(padding_amount == 0);
        }

        let mut alignment_padding = Vec::new();
        alignment_padding.resize_with(padding_amount, || 0);

        let encrypted_value = encryptor(&alignment_padding);

        // is this bad code
        // again, yes
        let start_of_block = decrypt_idx + padding_amount + 1 - block_size;
        let end_of_block = decrypt_idx + padding_amount + 1;

        assert_eq!(start_of_block % block_size, 0);
        assert_eq!(end_of_block % block_size, 0); //exclusive, this is the index of the start of the *next* block

        let encrypted_block = &encrypted_value[start_of_block..end_of_block];
        assert_eq!(encrypted_block.len(), block_size);

        // encrypted_block is now a single block where the last byte is unknown, and the first
        // block_size-1 bytes are the last blocksize-1 bytes of guess
        //
        let mut found = false;
        for guess_byte in 0..=255 {
            let mut tg = guess[guess.len() + 1 - block_size..].to_vec();
            assert_eq!(tg.len(), block_size - 1);

            tg.push(guess_byte);

            // this relies on the fact that there's no prefix
            // we just want to encrypt a single block, nothing fancy
            // we don't care about the padding
            // if there was an unknown prefix then we could work it out
            let encrypted_result = encryptor(&tg);

            let encrypted_block_guess = &encrypted_result[0..block_size];

            assert_eq!(encrypted_block_guess.len(), encrypted_block.len());
            if encrypted_block_guess == encrypted_block {
                guess.push(guess_byte);
                found = true;
                break;
            }
        }
        if !found {
            // we couldn't find a block... let's stop here??????
            break;
        }
    }

    let padding_amount = *guess.last().unwrap() as usize;

    let guess_msg = &guess[0..guess.len() - padding_amount - 1];

    let final_answer = String::from_utf8(guess_msg.to_vec()).unwrap();

    assert_eq!(final_answer, "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by");
}

#[test]
fn challenge13() {
    let key: [u8; 16] = rand::random();

    let oracle = |username: &str| {
        let input = profile_for(username).to_vec();
        let encoded = kvencode(input);
        println!("{}", encoded);
        aes_128_ecb_enc(encoded.into_bytes(), &key)
    };

    let oracle_result = |encrypted: &[u8]| {
        let decrypted = aes_128_ecb_dec(encrypted, &key);

        let decstr = String::from_utf8(decrypted).unwrap();

        dbg!(&decstr);

        let map: std::collections::HashMap<_, _> = kvparse(&decstr).into_iter().collect();

        map["role"] == "admin"
    };

    // we are assuming we already know the format and cipher
    //
    // Using an email of foo@arbaz.com, we get 3 blocks
    //
    // | email=foo@arbaz | .com&uid=10&role= | user ((padding bytes))
    //
    // We then take the first 2 blocks (32 bytes), and get the oracle to encrypt "admin" with the
    // correct padding bytes.

    let clean = oracle("foo@arbaz.com");
    assert_eq!(clean.len(), 16 * 3);

    let clean_prefix = &clean[0..32];

    let mut admin_str = String::new();

    // Pad it such that after this we're on a block of our own
    admin_str.push_str(&"X".repeat(16 - "email=".len()));
    dbg!(&admin_str);

    // Push something that looks like "admin"
    admin_str.push_str("admin");
    dbg!(&admin_str);

    admin_str.push_str(&"\x0b".repeat(0x0b));

    let admin_vec = admin_str.into_bytes();

    let admin_encrypted = oracle(std::str::from_utf8(&admin_vec).unwrap());

    let mut spliced = Vec::new();
    spliced.extend(clean_prefix);
    spliced.extend(&admin_encrypted[16..32]);
    assert_eq!(spliced.len() % 16, 0);

    assert!(oracle_result(&spliced));
}

#[test]
fn challenge14() {
    use rand::RngCore;

    let unknown_string = hex::decode(include_str!("12.txt")).unwrap();
    let mut random_string_full = [0u8; 256];
    rand::thread_rng().fill_bytes(&mut random_string_full);
    let random_string_len = rand::random::<u8>() as usize;
    let random_string = &random_string_full[0..random_string_len];
    let key: [u8; 16] = rand::random();

    let encryptor = |my_string: &[u8]| {
        let mut to_encrypt = Vec::new();

        to_encrypt.extend(random_string);
        to_encrypt.extend(my_string);
        to_encrypt.extend(&unknown_string);

        aes_128_ecb_enc(to_encrypt, &key)
    };

    let block_size;
    let block_offset;

    {
        // figure out block size
        let mut my_string = Vec::new();
        let baseline_size = encryptor(&my_string).len();
        while encryptor(&my_string).len() == baseline_size {
            my_string.push(0);
        }

        let new_baseline_size = encryptor(&my_string).len();
        while encryptor(&my_string).len() == new_baseline_size {
            my_string.push(0);
        }

        block_size = encryptor(&my_string).len() - new_baseline_size;
        block_offset = new_baseline_size - baseline_size;
    }

    assert_eq!(block_size, 16);

    let to_add = vec![0u8; block_size * 3];

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
    for _ in 0..block_size - 1 {
        let ch = decrypt_starting_with(&guess);
        guess.push(ch);
    }

    // now we know the first block_size bytes, we can use that to brute force the rest of them
    //
    // We want to get the value of encrypt_block where the first block_size-1 bytes are *known*,
    // and the last one is not.
    //
    let message_length = encryptor(&[]).len();

    for decrypt_idx in block_size - 1..message_length {
        let padding_amount = (block_size - ((decrypt_idx + 1) % block_size)) % block_size;

        // unknown_string[decrypt_idx] must be at the end of a block
        assert_eq!((padding_amount + decrypt_idx) % block_size, block_size - 1);
        assert!(padding_amount < block_size);

        if decrypt_idx % block_size == block_size - 1 {
            assert!(padding_amount == 0);
        }

        let mut alignment_padding = Vec::new();
        alignment_padding.resize_with(padding_amount, || 0);

        let encrypted_value = encryptor(&alignment_padding);

        // is this bad code
        // again, yes
        let start_of_block = decrypt_idx + padding_amount + 1 - block_size;
        let end_of_block = decrypt_idx + padding_amount + 1;

        assert_eq!(start_of_block % block_size, 0);
        assert_eq!(end_of_block % block_size, 0); //exclusive, this is the index of the start of the *next* block

        let encrypted_block = &encrypted_value[start_of_block..end_of_block];
        assert_eq!(encrypted_block.len(), block_size);

        // encrypted_block is now a single block where the last byte is unknown, and the first
        // block_size-1 bytes are the last blocksize-1 bytes of guess
        //
        let mut found = false;
        for guess_byte in 0..=255 {
            let mut tg = guess[guess.len() + 1 - block_size..].to_vec();
            assert_eq!(tg.len(), block_size - 1);

            tg.push(guess_byte);

            // this relies on the fact that there's no prefix
            // we just want to encrypt a single block, nothing fancy
            // we don't care about the padding
            // if there was an unknown prefix then we could work it out
            let encrypted_result = encryptor(&tg);

            let encrypted_block_guess = &encrypted_result[0..block_size];

            assert_eq!(encrypted_block_guess.len(), encrypted_block.len());
            if encrypted_block_guess == encrypted_block {
                guess.push(guess_byte);
                found = true;
                break;
            }
        }
        if !found {
            // we couldn't find a block... let's stop here??????
            break;
        }
    }

    let padding_amount = *guess.last().unwrap() as usize;

    let guess_msg = &guess[0..guess.len() - padding_amount - 1];

    let final_answer = String::from_utf8(guess_msg.to_vec()).unwrap();

    assert_eq!(final_answer, "Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\nThe girlies on standby waving just to say hi\nDid you stop? No, I just drove by");
}
