use phase2::parameters::MPCParameters;
use setup_utils::{print_hash, CheckForCorrectness, UseCompression};

use snarkvm_curves::PairingEngine;
use snarkvm_utilities::CanonicalSerialize;

use std::{
    fs::File,
    io::{BufRead, BufReader},
};
use tracing::info;

use crate::{CombineOpts, COMPRESS_CONTRIBUTE_OUTPUT};

pub fn combine<E: PairingEngine>(combine_opts: &CombineOpts) {
    info!("Combining phase 2");

    let response_list_reader =
        BufReader::new(File::open(&combine_opts.response_list_fname).expect("should have opened the response list"));

    let full_contents = std::fs::read(&combine_opts.initial_full_fname).expect("should have initial full parameters");
    let full_parameters = MPCParameters::<E>::read_fast(
        full_contents.as_slice(),
        UseCompression::No,
        CheckForCorrectness::No,
        false,
    )
    .expect("should have read full parameters");

    let mut query_contents =
        std::io::Cursor::new(std::fs::read(&combine_opts.initial_query_fname).expect("should have read initial query"));
    let query_parameters =
        MPCParameters::<E>::read_groth16_fast(&mut query_contents, UseCompression::No, CheckForCorrectness::No, false)
            .expect("should have deserialized initial query params");

    let parameters_compressed = COMPRESS_CONTRIBUTE_OUTPUT;
    let mut all_parameters = vec![];
    for line in response_list_reader.lines() {
        let line = line.expect("should have read line");
        let contents = std::fs::read(line).expect("should have read response");
        let parameters = MPCParameters::<E>::read_fast(
            contents.as_slice(),
            parameters_compressed,
            CheckForCorrectness::No,
            false,
        )
        .expect("should have read parameters");
        all_parameters.push(parameters);
    }

    let combined =
        MPCParameters::<E>::combine(&query_parameters, &all_parameters).expect("should have combined parameters");

    let contributions_hash = full_parameters
        .verify(&combined)
        .expect("should have verified successfully");

    info!("Contributions hashes:");
    for contribution_hash in contributions_hash {
        print_hash(&contribution_hash[..]);
    }

    let mut combined_contents = vec![];
    combined
        .write(&mut combined_contents)
        .expect("should have written combined");
    std::fs::write(&combine_opts.combined_fname, &combined_contents).expect("should have written combined file");

    let mut combined_parameters_contents = vec![];
    combined
        .params
        .serialize_uncompressed(&mut combined_parameters_contents)
        .expect("should have serialized combined parameters");
    std::fs::write(
        format!("{}.params", combine_opts.combined_fname),
        &combined_parameters_contents,
    )
    .expect("should have written combined parameters file");
}
