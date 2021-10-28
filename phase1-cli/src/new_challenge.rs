use phase1::{Phase1, Phase1Parameters};
use setup_utils::{blank_hash, calculate_hash, print_hash, UseCompression};

use snarkvm_curves::PairingEngine as Engine;

use std::io::Write;

pub fn new_challenge<T: Engine + Sync>(
    compress_new_challenge: UseCompression,
    parameters: &Phase1Parameters<T>,
) -> Vec<u8> {
    println!(
        "Will generate an empty accumulator for 2^{} powers of tau",
        parameters.total_size_in_log2
    );
    println!("In total will generate up to {} powers", parameters.powers_g1_length);

    let expected_challenge_length = match compress_new_challenge {
        UseCompression::Yes => parameters.contribution_size - parameters.public_key_size,
        UseCompression::No => parameters.accumulator_size,
    };

    let mut challenge = vec![0; expected_challenge_length];

    // Write a blank BLAKE2b hash:
    let hash = blank_hash();
    (&mut challenge[0..])
        .write_all(&hash)
        .expect("unable to write a default hash to mmap");

    println!("Blank hash for an empty challenge:");
    print_hash(&hash);

    Phase1::initialization(&mut challenge, compress_new_challenge, &parameters)
        .expect("generation of initial accumulator is successful");

    // Get the hash of the contribution, so the user can compare later
    let contribution_hash = calculate_hash(&challenge);

    println!("Empty contribution is formed with a hash:");
    print_hash(&contribution_hash);
    println!("Wrote a fresh accumulator to challenge file");

    challenge
}
