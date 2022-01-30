use phase1::{Phase1, Phase1Parameters};
use setup_utils::UseCompression;

use snarkvm_curves::PairingEngine as Engine;

use memmap::*;
use std::{
    fs::{File, OpenOptions},
    io::{BufRead, BufReader},
};

const CONTRIBUTION_IS_COMPRESSED: UseCompression = UseCompression::Yes;
const COMPRESS_NEW_COMBINED: UseCompression = UseCompression::No;

pub fn combine<T: Engine + Sync>(
    response_list_filename: &str,
    combined_filename: &str,
    parameters: &Phase1Parameters<T>,
) {
    println!("Will combine contributions",);

    let mut readers = vec![];

    let response_list_reader =
        BufReader::new(File::open(response_list_filename).expect("should have opened the response list"));
    for (chunk_index, line) in response_list_reader.lines().enumerate() {
        let line = line.expect("should have read line");
        let parameters =
            parameters.into_chunk_parameters(parameters.contribution_mode, chunk_index, parameters.chunk_size);
        let response_reader = OpenOptions::new()
            .read(true)
            .open(line)
            .expect("unable open response file in this directory");
        {
            let metadata = response_reader
                .metadata()
                .expect("unable to get filesystem metadata for response file");
            let expected_response_length = match CONTRIBUTION_IS_COMPRESSED {
                UseCompression::Yes => parameters.contribution_size,
                UseCompression::No => parameters.accumulator_size + parameters.public_key_size,
            };
            if metadata.len() != (expected_response_length as u64) {
                panic!(
                    "The size of response file should be {}, but it's {}, so something isn't right.",
                    expected_response_length,
                    metadata.len()
                );
            }
        }

        unsafe {
            readers.push(
                MmapOptions::new()
                    .map(&response_reader)
                    .expect("should have mapped the reader"),
            );
        }
    }

    let parameters_for_output = Phase1Parameters::<T>::new(
        parameters.contribution_mode,
        0,
        parameters.powers_g1_length,
        parameters.curve.clone(),
        parameters.proving_system,
        parameters.total_size_in_log2,
        parameters.batch_size,
    );
    let writer = OpenOptions::new()
        .read(true)
        .write(true)
        .create_new(true)
        .open(combined_filename)
        .expect("unable to create new combined file in this directory");

    tracing::debug!("Parameters for output: {:?}", parameters_for_output);

    writer
        .set_len(parameters_for_output.accumulator_size as u64)
        .expect("must make output file large enough");

    let mut writable_map = unsafe {
        MmapOptions::new()
            .map_mut(&writer)
            .expect("unable to create a memory map for output")
    };

    let parameters = Phase1Parameters::<T>::new(
        parameters.contribution_mode,
        0,
        parameters.chunk_size,
        parameters.curve.clone(),
        parameters.proving_system,
        parameters.total_size_in_log2,
        parameters.batch_size,
    );
    tracing::debug!("Parameters for aggregation: {:?}", parameters);
    let res = Phase1::aggregation(
        &readers
            .iter()
            .map(|r| (r.as_ref(), CONTRIBUTION_IS_COMPRESSED))
            .collect::<Vec<_>>()
            .as_slice(),
        (&mut writable_map, COMPRESS_NEW_COMBINED),
        &parameters,
    );

    if let Err(e) = res {
        println!("Combining failed: {}", e);
        panic!("INVALID CONTRIBUTIONS!!!");
    } else {
        println!("Combining succeeded!");
    }
}
