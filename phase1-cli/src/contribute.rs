use phase1::{Phase1, Phase1Parameters};
use setup_utils::{calculate_hash, CheckForCorrectness, UseCompression};

use snarkvm_curves::PairingEngine as Engine;

use rand::{CryptoRng, Rng};
use std::io::{Read, Write};

pub fn contribute<T: Engine + Sync>(
    compressed_input: UseCompression,
    challenge: &[u8],
    compressed_output: UseCompression,
    check_input_correctness: CheckForCorrectness,
    parameters: &Phase1Parameters<T>,
    mut rng: impl Rng + CryptoRng,
) -> Vec<u8> {
    let expected_challenge_length = match compressed_input {
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

    let required_output_length = match compressed_output {
        UseCompression::Yes => parameters.contribution_size,
        UseCompression::No => parameters.accumulator_size + parameters.public_key_size,
    };

    let mut response = vec![0; required_output_length];

    tracing::info!("Calculating previous contribution hash...");

    assert_eq!(
        UseCompression::No,
        compressed_input,
        "Hashing the compressed file in not yet defined"
    );
    let current_accumulator_hash = calculate_hash(&challenge);

    tracing::info!("`challenge` file contains decompressed points and has a hash:");
    log_hash(&current_accumulator_hash);

    (&mut response[0..])
        .write_all(&current_accumulator_hash)
        .expect("unable to write a challenge hash to mmap");

    {
        let mut challenge_hash = [0; 64];
        (&challenge[..])
            .read_exact(&mut challenge_hash)
            .expect("couldn't read hash of challenge file from response file");

        tracing::info!(
            "`challenge` file claims (!!! Must not be blindly trusted) that it was based on the original contribution with a hash:"
        );
        log_hash(&challenge_hash);
    }

    // Construct our keypair using the RNG we created above
    let (public_key, private_key) =
        Phase1::key_generation(&mut rng, current_accumulator_hash.as_ref()).expect("could not generate keypair");

    // Perform the transformation
    tracing::info!("Computing and writing your contribution, this could take a while...");

    // this computes a transformation and writes it
    Phase1::computation(
        &challenge,
        &mut response,
        compressed_input,
        compressed_output,
        check_input_correctness,
        &private_key,
        &parameters,
    )
    .expect("must contribute with the key");

    tracing::info!("Finishing writing your contribution to response file...");

    // Write the public key
    public_key
        .write(&mut response, compressed_output, &parameters)
        .expect("unable to write public key");

    // Get the hash of the contribution, so the user can compare later
    let contribution_hash = calculate_hash(&response);

    tracing::info!(
        "Done!\n\n\
              Your contribution has been written to response file\n\n\
              The BLAKE2b hash of response file is:\n"
    );
    log_hash(&contribution_hash);
    tracing::info!("Thank you for your participation, much appreciated! :)");
    response
}

fn log_hash(hash: &[u8]) {
    for line in hash.chunks(16) {
        let mut text = String::new();
        text.push('\t');
        for section in line.chunks(4) {
            for b in section {
                text.push_str(&format!("{:02x}", b));
            }
            text.push(' ');
        }
        tracing::info!("{}", text);
    }
}
