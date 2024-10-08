use itertools::Itertools;

use cryptopals::*;

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
        .split('\n')
        .map(|x| hex::decode(x).unwrap());

    let tries: Vec<Vec<u8>> = (0..=255)
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
        .split('\n')
        .map(|x| hex::decode(x).unwrap());

    for line in data {
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
