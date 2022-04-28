use crate::{
    environment::Environment,
    storage::{ContributionLocator, Disk, Locator, Object, StorageObject},
    CoordinatorError,
};
use phase1::{helpers::CurveKind, Phase1, Phase1Parameters};
use setup_utils::{blank_hash, calculate_hash, UseCompression};
use snarkvm_curves::{bls12_377::Bls12_377, bw6_761::BW6_761};

use snarkvm_curves::PairingEngine as Engine;

use std::fs::File;
use std::io::Cursor;
use std::{io::BufWriter, io::Write, time::Instant};
use tracing::{debug, error, info, trace};

pub(crate) struct Initialization;

extern crate pairing;
extern crate phase2;
extern crate sapling_crypto;

use masp_phase2::MPCParameters;
use masp_proofs::*;

impl Initialization {
    ///
    /// Runs chunk initialization for a given environment, round height, and chunk ID.
    ///
    /// Executes the round initialization on a given chunk ID.
    ///
    #[inline]
    pub(crate) fn run(
        environment: &Environment,
        storage: &mut Disk,
        round_height: u64,
        chunk_id: u64,
    ) -> anyhow::Result<Vec<u8>> {
        info!("Starting initialization on round {} chunk {}", round_height, chunk_id);
        let start = Instant::now();

        // Determine the expected challenge size.
        let expected_challenge_size = Object::contribution_file_size(environment, chunk_id, true);
        // TODO: implement calculate size macro for our curves
        // let expected_challenge_size = 200_000_000; //FIXME: improve this with contribution_file_size
        trace!("Expected challenge file size is {}", expected_challenge_size);

        // Initialize and fetch a writer for the contribution locator so the output is saved.
        let contribution_locator = Locator::ContributionFile(ContributionLocator::new(round_height, chunk_id, 0, true));
        storage.initialize(contribution_locator.clone(), expected_challenge_size as u64)?;

        // Run ceremony initialization on chunk.
        let settings = environment.parameters();

        if let Err(error) = match settings.curve() {
            // TODO: change phase1_chunked_parameters, not used by phase2
            CurveKind::Bls12_381 => Self::initialization(
                storage.writer(&contribution_locator)?.as_mut(),
                environment.compressed_inputs(),
                &phase1_chunked_parameters!(Bls12_377, settings, chunk_id),
            ),
            CurveKind::Bls12_377 => Self::initialization(
                storage.writer(&contribution_locator)?.as_mut(),
                environment.compressed_inputs(),
                &phase1_chunked_parameters!(Bls12_377, settings, chunk_id),
            ),
            CurveKind::BW6 => Self::initialization(
                storage.writer(&contribution_locator)?.as_mut(),
                environment.compressed_inputs(),
                &phase1_chunked_parameters!(BW6_761, settings, chunk_id),
            ),
        } {
            error!("Initialization failed with {}", error);
            return Err(CoordinatorError::InitializationFailed.into());
        }

        // Copy the current transcript to the next transcript.
        // This operation will *overwrite* the contents of `next_transcript`.
        let next_contribution_locator =
            Locator::ContributionFile(ContributionLocator::new(round_height + 1, chunk_id, 0, true));
        if let Err(error) = storage.copy(&contribution_locator, &next_contribution_locator) {
            return Err(error.into());
        }

        // Check that the current and next contribution hash match.
        let hash = Self::check_hash(storage, &contribution_locator, &next_contribution_locator)?;
        debug!("The challenge hash of Chunk {} is {}", chunk_id, pretty_hash!(&hash));

        let elapsed = Instant::now().duration_since(start);
        info!("Completed initialization on chunk {} in {:?}", chunk_id, elapsed);
        Ok(hash)
    }

    /// Runs Phase 1 initialization on the given parameters.
    #[inline]
    fn initialization<T: Engine + Sync>(
        mut writer: &mut [u8],
        compressed: UseCompression,
        parameters: &Phase1Parameters<T>,
    ) -> Result<(), CoordinatorError> {
        // trace!("Initializing Powers of Tau on 2^{}", parameters.total_size_in_log2);
        // trace!("In total will generate up to {} powers", parameters.powers_g1_length);

        let hash = blank_hash();
        // (&mut writer[0..]).write_all(hash.as_slice())?;
        writer.write_all(&hash.as_slice())?;
        writer.flush()?;
        debug!("Empty challenge hash is {}", pretty_hash!(&hash));
        // debug!("Empty challenge is {}", pretty_hash!(&writer));
        info!("Starting Phase 1 initialization operation");
        // Add here your MPC Parameters init function
        // let jubjub_params = sapling_crypto::jubjub::JubjubBls12::new();
        // Sapling spend circuit
        // const size: usize = 1024 * 1024 *2;
        // let mut writer: Vec<u8> = Vec::with_capacity(size);
        // let mut writer: Vec<u8> = vec![];
        // let mut writer = BufWriter::with_capacity(1024 * 1024, writer_tmp);

        // phase2::MPCParameters::new(sapling_crypto::circuit::sapling::Spend {
        //     params: &jubjub_params,
        //     value_commitment: None,
        //     proof_generation_key: None,
        //     payment_address: None,
        //     commitment_randomness: None,
        //     ar: None,
        //     auth_path: vec![None; 32], // Tree depth is 32 for sapling
        //     anchor: None,
        // })
        // .unwrap()
        // .write(&mut writer)
        // .unwrap();

        // MASP spend circuit
        // let spend_params = MPCParameters::new(
        //     masp_proofs::circuit::sapling::Spend {
        //         value_commitment: None,
        //         proof_generation_key: None,
        //         payment_address: None,
        //         commitment_randomness: None,
        //         ar: None,
        //         auth_path: vec![None; 32], // Tree depth is 32 for sapling
        //         anchor: None,
        //     },
        //     //should_filter_points_at_infinity,
        //     //radix_directory,
        // )
        // .unwrap();
        // info!("Writing initial MASP Spend parameters to .",);

        // spend_params
        //     .write(&mut writer)
        //     .expect("unable to write MASP Spend params");

        // println!("Creating initial parameters for MASP Output...");
        // // MASP output circuit
        // let output_params = MPCParameters::new(
        //     masp_proofs::circuit::sapling::Output {
        //         value_commitment: None,
        //         payment_address: None,
        //         commitment_randomness: None,
        //         esk: None,
        //         asset_identifier: vec![None; 256],
        //     },
        //     //should_filter_points_at_infinity,
        //     //radix_directory,
        // )
        // .unwrap();

        // println!("Writing initial MASP Output parameters to .",);

        // output_params
        //     .write(&mut writer)
        //     .expect("unable to write MASP Output params");

        println!("Creating initial parameters for MASP Convert...");
        // MASP Convert circuit
        let convert_params = MPCParameters::new(
            masp_proofs::circuit::convert::Convert {
                value_commitment: None,
                auth_path: vec![None; 32], // Tree depth is 32 for sapling
                anchor: None,
            },
            //should_filter_points_at_infinity,
            //radix_directory,
        )
        .unwrap();

        println!("Writing initial MASP Convert parameters to .",);

        convert_params
            .write(&mut writer)
            .expect("unable to write MASP Convert params");

        writer.flush()?;

        // param.get_params().serialize(writer)?;
        // Phase1::initialization(&mut writer, compressed, &parameters)?;
        trace!("Completed Phase 1 initialization operation");

        Ok(())
    }

    /// Compute both contribution hashes and check for equivalence.
    #[inline]
    fn check_hash(
        storage: &Disk,
        contribution_locator: &Locator,
        next_contribution_locator: &Locator,
    ) -> anyhow::Result<Vec<u8>> {
        let current = storage.reader(contribution_locator)?;
        let next = storage.reader(next_contribution_locator)?;

        // Compare the contribution hashes of both files to ensure the copy succeeded.
        let contribution_hash_0 = calculate_hash(current.as_ref());
        let contribution_hash_1 = calculate_hash(next.as_ref());
        if contribution_hash_0 != contribution_hash_1 {
            return Err(CoordinatorError::InitializationTranscriptsDiffer.into());
        }

        Ok(contribution_hash_1.to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::{
        commands::Initialization,
        storage::{ContributionLocator, Locator, StorageObject},
        testing::prelude::*,
    };
    use setup_utils::{blank_hash, calculate_hash, GenericArray};

    use tracing::{debug, trace};

    #[test]
    #[serial]
    fn test_initialization_run() {
        initialize_test_environment(&TEST_ENVIRONMENT_ANOMA);

        // Define test parameters.
        let round_height = 0;
        let number_of_chunks = TEST_ENVIRONMENT_ANOMA.number_of_chunks();

        // Define test storage.
        let mut storage = test_storage(&TEST_ENVIRONMENT_ANOMA);

        // Initialize the previous contribution hash with a no-op value.
        let mut previous_contribution_hash: GenericArray<u8, _> =
            GenericArray::from_slice(vec![0; 64].as_slice()).clone();

        // Generate a new challenge for the given parameters.
        for chunk_id in 0..number_of_chunks {
            debug!("Initializing test chunk {}", chunk_id);

            // Execute the ceremony initialization
            let candidate_hash =
                Initialization::run(&TEST_ENVIRONMENT_ANOMA, &mut storage, round_height, chunk_id).unwrap();

            // Open the contribution locator file.
            let locator = Locator::ContributionFile(ContributionLocator::new(round_height, chunk_id, 0, true));
            let reader = storage.reader(&locator).unwrap();

            // Check that the contribution chunk was generated based on the blank hash.
            let hash = blank_hash();

            debug!("blank hash is {}", pretty_hash!(&hash));
            let challenge_hash = calculate_hash(&reader);
            debug!("reader hash is {}", pretty_hash!(challenge_hash));
            debug!("reader is {}", pretty_hash!(&reader[0..255]));
            for (i, (expected, candidate)) in hash.iter().zip(reader.as_ref().chunks(64).next().unwrap()).enumerate() {
                trace!(
                    "Checking byte {} of expected hash: {:02x} =? {:02x}",
                    i,
                    expected,
                    candidate
                );
                assert_eq!(expected, candidate);
            }

            // If chunk ID is under (number_of_chunks / 2), the contribution hash
            // of each iteration will match with Groth16 and Marlin.
            if chunk_id < (number_of_chunks / 2) as u64 {
                // Sanity only - Check that the current contribution hash matches the previous one.
                let contribution_hash = calculate_hash(reader.as_ref());
                assert_eq!(contribution_hash.to_vec(), candidate_hash);
                match chunk_id == 0 {
                    true => previous_contribution_hash = contribution_hash,
                    false => {
                        assert_eq!(previous_contribution_hash, contribution_hash);
                        previous_contribution_hash = contribution_hash;
                    }
                }
                trace!(
                    "The contribution hash of chunk {} is {}",
                    chunk_id,
                    pretty_hash!(&contribution_hash)
                );
            }
        }
    }
}
