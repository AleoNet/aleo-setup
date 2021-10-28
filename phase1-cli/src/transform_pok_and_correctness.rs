use phase1::{Phase1, Phase1Parameters, PublicKey};
use setup_utils::{calculate_hash, print_hash, CheckForCorrectness, UseCompression};

use snarkvm_curves::PairingEngine as Engine;

use std::io::{Read, Write};

pub fn transform_pok_and_correctness<T: Engine + Sync>(
    challenge_is_compressed: UseCompression,
    challenge: &[u8],
    contribution_is_compressed: UseCompression,
    response: &[u8],
    compress_new_challenge: UseCompression,
    parameters: &Phase1Parameters<T>,
) -> Vec<u8> {
    println!(
        "Will verify and decompress a contribution to accumulator for 2^{} powers of tau",
        parameters.total_size_in_log2
    );

    let expected_challenge_length = match challenge_is_compressed {
        UseCompression::Yes => parameters.contribution_size - parameters.public_key_size,
        UseCompression::No => parameters.accumulator_size,
    };
    if challenge.len() != expected_challenge_length {
        panic!(
            "The size of challenge file should be {}, but it's {}, so something isn't right.",
            expected_challenge_length,
            challenge.len()
        );
    }

    let expected_response_length = match contribution_is_compressed {
        UseCompression::Yes => parameters.contribution_size,
        UseCompression::No => parameters.accumulator_size + parameters.public_key_size,
    };
    if response.len() != expected_response_length {
        panic!(
            "The size of response file should be {}, but it's {}, so something isn't right.",
            expected_response_length,
            response.len()
        );
    }

    println!("Calculating previous challenge hash...");

    // Check that contribution is correct

    let current_accumulator_hash = calculate_hash(&challenge);

    println!("Hash of the `challenge` file for verification:");
    print_hash(&current_accumulator_hash);

    // Check the hash chain - a new response must be based on the previous challenge!
    {
        let mut response_challenge_hash = [0; 64];
        (&response[..])
            .read_exact(&mut response_challenge_hash)
            .expect("couldn't read hash of challenge file from response file");

        println!("`response` was based on the hash:");
        print_hash(&response_challenge_hash);

        if response_challenge_hash != current_accumulator_hash {
            panic!("Hash chain failure. This is not the right response.");
        }
    }

    let response_hash = calculate_hash(&response);

    println!("Hash of the response file for verification:");
    print_hash(&response_hash);

    // get the contributor's public key
    let public_key = PublicKey::read(&response, contribution_is_compressed, &parameters)
        .expect("wasn't able to deserialize the response file's public key");

    // check that it follows the protocol

    println!("Verifying a contribution to contain proper powers and correspond to the public key...");

    let res = Phase1::verification(
        &challenge,
        &response,
        &public_key,
        &current_accumulator_hash,
        challenge_is_compressed,
        contribution_is_compressed,
        CheckForCorrectness::No,
        CheckForCorrectness::Full,
        &parameters,
    );

    if let Err(e) = res {
        println!("Verification failed: {}", e);
        panic!("INVALID CONTRIBUTION!!!");
    } else {
        println!("Verification succeeded!");
    }

    if compress_new_challenge == contribution_is_compressed {
        println!("Don't need to recompress the contribution, copying the file without the public key...");
        let mut new_challenge = challenge.to_vec();
        new_challenge.resize(parameters.accumulator_size + parameters.public_key_size, 0);

        let hash = calculate_hash(&new_challenge);

        println!("Here's the BLAKE2b hash of the decompressed participant's response as new_challenge file:");
        print_hash(&hash);
        println!("Done! new challenge file contains the new challenge file. The other files");
        println!("were left alone.");
        new_challenge
    } else {
        println!("Verification succeeded! Writing to new challenge file...");

        // Create new challenge
        let mut new_challenge = vec![0; parameters.accumulator_size];

        (&mut new_challenge[0..])
            .write_all(&response_hash)
            .expect("unable to write a default hash to new challenge");

        Phase1::decompress(&response, &mut new_challenge, CheckForCorrectness::No, &parameters)
            .expect("must decompress a response for a new challenge");

        let recompressed_hash = calculate_hash(&new_challenge);

        println!("Here's the BLAKE2b hash of the decompressed participant's response as new_challenge file:");
        print_hash(&recompressed_hash);
        println!("Done! new challenge file contains the new challenge file. The other files");
        println!("were left alone.");

        new_challenge
    }
}
