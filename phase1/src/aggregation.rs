use super::*;

impl<'a, E: PairingEngine + Sync> Phase1<'a, E> {
    ///
    /// Phase 1: Aggregation
    ///
    /// Takes as input a buffer of elements in serialized form,
    /// reads them as group elements, and attempts to write them to
    /// the output buffer.
    ///
    pub fn aggregation(
        inputs: &[(&[u8], UseCompression)],
        (output, compressed_output): (&mut [u8], UseCompression),
        parameters: &Phase1Parameters<E>,
    ) -> Result<()> {
        let span = info_span!("phase1-aggregation");
        let _enter = span.enter();

        info!("Starting Aggregation");

        for (chunk_index, (input, compressed_input)) in inputs.iter().enumerate() {
            let chunk_parameters =
                parameters.into_chunk_parameters(parameters.contribution_mode, chunk_index, parameters.chunk_size);

            let input = *input;
            let compressed_input = *compressed_input;

            let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) =
                split(input, &chunk_parameters, compressed_input);
            let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) =
                split_at_chunk_mut(output, &chunk_parameters, compressed_output);

            let start = chunk_index * chunk_parameters.chunk_size;
            let end = (chunk_index + 1) * chunk_parameters.chunk_size;

            debug!("Combining chunk from {} to {}", start, end);
            debug!("Chunk parameters: {:?}", chunk_parameters);

            let span = info_span!("Batch", start, end);
            let _enter = span.enter();

            match parameters.proving_system {
                ProvingSystem::Groth16 => {
                    rayon::scope(|t| {
                        let _enter = span.enter();

                        t.spawn(|_| {
                            let _enter = span.enter();

                            let elements: Vec<E::G1Affine> = in_tau_g1
                                .read_batch(compressed_input, CheckForCorrectness::No)
                                .expect("should have read batch");
                            tau_g1
                                .write_batch(&elements, compressed_output)
                                .expect("should have written batch");

                            debug!(
                                "Tau G1 aggregation for chunk {} successful; {} G1 elements written",
                                chunk_index,
                                elements.len()
                            );
                        });

                        debug!(
                            "`start = {}, chunk_parameters.powers_length = {}, start < chunk_parameters.powers_length = {}`",
                            start,
                            chunk_parameters.powers_length,
                            start < chunk_parameters.powers_length
                        );
                        if start < chunk_parameters.powers_length {
                            rayon::scope(|t| {
                                let _enter = span.enter();

                                t.spawn(|_| {
                                    let _enter = span.enter();
                                    let elements: Vec<E::G2Affine> = in_tau_g2
                                        .read_batch(compressed_input, CheckForCorrectness::No)
                                        .expect("should have read batch");
                                    tau_g2
                                        .write_batch(&elements, compressed_output)
                                        .expect("should have written batch");

                                    debug!(
                                        "Tau G2 aggregation for chunk {} successful; {} G2 elements written",
                                        chunk_index,
                                        elements.len()
                                    );
                                });

                                t.spawn(|_| {
                                    let _enter = span.enter();

                                    let elements: Vec<E::G1Affine> = in_alpha_g1
                                        .read_batch(compressed_input, CheckForCorrectness::No)
                                        .expect("should have read batch");
                                    alpha_g1
                                        .write_batch(&elements, compressed_output)
                                        .expect("should have written batch");

                                    debug!(
                                        "alpha_g1 aggregation for chunk {} successful; {} G1 elements written",
                                        chunk_index,
                                        elements.len()
                                    );
                                });

                                t.spawn(|_| {
                                    let _enter = span.enter();

                                    let elements: Vec<E::G1Affine> = in_beta_g1
                                        .read_batch(compressed_input, CheckForCorrectness::No)
                                        .expect("should have read batch");
                                    beta_g1
                                        .write_batch(&elements, compressed_output)
                                        .expect("should have written batch");

                                    debug!(
                                        "beta_g1 aggregation for chunk {} successful; {} G1 elements written",
                                        chunk_index,
                                        elements.len()
                                    );
                                });
                            });
                        }

                        if chunk_index == 0 {
                            let element: E::G2Affine = (&*in_beta_g2)
                                .read_element(compressed_input, CheckForCorrectness::No)
                                .expect("should have read element");
                            beta_g2
                                .write_element(&element, compressed_output)
                                .expect("should have written element");
                            debug!("beta_g2 aggregation for chunk {} successful", chunk_index);
                        }
                    });
                }

                ProvingSystem::Marlin => {
                    rayon::scope(|t| {
                        let _enter = span.enter();

                        t.spawn(|_| {
                            let _enter = span.enter();

                            let elements: Vec<E::G1Affine> = in_tau_g1
                                .read_batch(compressed_input, CheckForCorrectness::No)
                                .expect("should have read batch");
                            tau_g1
                                .write_batch(&elements, compressed_output)
                                .expect("should have written batch");

                            trace!("tau_g1 aggregation for chunk {} successful", chunk_index);
                        });

                        // handle tau G2
                        if start < 2 + chunk_parameters.total_size_in_log2 {
                            rayon::scope(|t| {
                                let _enter = span.enter();
                                t.spawn(|_| {
                                    let _enter = span.enter();

                                    let elements: Vec<E::G2Affine> = in_tau_g2
                                        .read_batch(compressed_input, CheckForCorrectness::No)
                                        .expect("should have read batch");
                                    tau_g2
                                        .write_batch(&elements, compressed_output)
                                        .expect("should have written batch");

                                    trace!("tau_g2 aggregation for chunk {} successful", chunk_index);
                                });
                            });
                        }
                        // handle alpha tau G1
                        if start < 3 + 3 * chunk_parameters.total_size_in_log2 {
                            rayon::scope(|t| {
                                let _enter = span.enter();

                                t.spawn(|_| {
                                    let _enter = span.enter();

                                    let elements: Vec<E::G1Affine> = in_alpha_g1
                                        .read_batch(compressed_input, CheckForCorrectness::No)
                                        .expect("should have read batch");
                                    alpha_g1
                                        .write_batch(&elements, compressed_output)
                                        .expect("should have written batch");

                                    trace!("alpha_g1 aggregation for chunk {} successful", chunk_index);
                                });
                            });
                        }
                    });
                }
            }

            debug!("chunk {} processing successful", chunk_index);
        }

        info!("phase1-aggregation complete");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::testing::{generate_input, generate_output};

    use snarkvm_curves::{bls12_377::Bls12_377, bw6_761::BW6_761};

    fn aggregation_test<E: PairingEngine>(
        powers: usize,
        batch: usize,
        compressed_input: UseCompression,
        compressed_output: UseCompression,
        use_wrong_chunks: bool,
    ) {
        let correctness = CheckForCorrectness::Full;

        for proving_system in &[ProvingSystem::Groth16, ProvingSystem::Marlin] {
            let powers_length = 1 << powers;
            let powers_g1_length = (powers_length << 1) - 1;
            let powers_length_for_proving_system = match *proving_system {
                ProvingSystem::Groth16 => powers_g1_length,
                ProvingSystem::Marlin => powers_length,
            };
            let num_chunks = (powers_length_for_proving_system + batch - 1) / batch;

            let mut full_contribution: Vec<Vec<u8>> = vec![];

            for chunk_index in 0..num_chunks {
                // Generate a new parameter for this chunk.
                let parameters = Phase1Parameters::<E>::new_chunk(
                    ContributionMode::Chunked,
                    chunk_index,
                    batch,
                    *proving_system,
                    powers,
                    batch,
                );

                //
                // First contributor computes a chunk.
                //

                let output_1 = {
                    // Start with an empty hash as this is the first time.
                    let digest = blank_hash();

                    // Construct the first contributor's keypair.
                    let (public_key_1, private_key_1) = {
                        let mut rng = derive_rng_from_seed(b"test_verify_transformation 1");
                        Phase1::<E>::key_generation(&mut rng, digest.as_ref()).expect("could not generate keypair")
                    };

                    // Allocate the input/output vectors
                    let (input, _) = generate_input(&parameters, compressed_input, correctness);
                    let mut output_1 = generate_output(&parameters, compressed_output);

                    // Compute a chunked contribution.
                    Phase1::computation(
                        &input,
                        &mut output_1,
                        compressed_input,
                        compressed_output,
                        correctness,
                        &private_key_1,
                        &parameters,
                    )
                    .unwrap();
                    // Ensure that the key is not available to the verifier.
                    drop(private_key_1);

                    // Verify that the chunked contribution is correct.
                    assert!(
                        Phase1::verification(
                            &input,
                            &output_1,
                            &public_key_1,
                            &digest,
                            compressed_input,
                            compressed_output,
                            correctness,
                            correctness,
                            &parameters,
                        )
                        .is_ok()
                    );

                    output_1
                };

                //
                // Second contributor computes a chunk.
                //

                let output_2 = {
                    // Note subsequent participants must use the hash of the accumulator they received.
                    let digest = calculate_hash(&output_1);

                    // Construct the second contributor's keypair, based on the first contributor's output.
                    let (public_key_2, private_key_2) = {
                        let mut rng = derive_rng_from_seed(b"test_verify_transformation 2");
                        Phase1::key_generation(&mut rng, digest.as_ref()).expect("could not generate keypair")
                    };

                    // Generate a new output vector for the second contributor.
                    let mut output_2 = generate_output(&parameters, compressed_output);

                    // Compute a chunked contribution, based on the first contributor's output.
                    Phase1::computation(
                        &output_1,
                        &mut output_2,
                        compressed_output,
                        compressed_output,
                        correctness,
                        &private_key_2,
                        &parameters,
                    )
                    .unwrap();
                    // Ensure that the key is not available to the verifier.
                    drop(private_key_2);

                    // Verify that the chunked contribution is correct.
                    assert!(
                        Phase1::verification(
                            &output_1,
                            &output_2,
                            &public_key_2,
                            &digest,
                            compressed_output,
                            compressed_output,
                            correctness,
                            correctness,
                            &parameters,
                        )
                        .is_ok()
                    );

                    // Verification will fail if the old hash is used.
                    if parameters.chunk_index == 0 {
                        assert!(
                            Phase1::verification(
                                &output_1,
                                &output_2,
                                &public_key_2,
                                &blank_hash(),
                                compressed_output,
                                compressed_output,
                                correctness,
                                correctness,
                                &parameters,
                            )
                            .is_err()
                        );
                    }

                    output_2
                };

                // Return the output based on the test case currently being run.
                match use_wrong_chunks && chunk_index == 1 {
                    true => {
                        let chunk_0_contribution: Vec<u8> = (*full_contribution.iter().last().unwrap()).to_vec();
                        full_contribution.push(chunk_0_contribution);
                    }
                    false => {
                        full_contribution.push(output_2.clone());
                    }
                }
            }

            // Aggregate the right ones. Combining and verification should work.

            let full_parameters = Phase1Parameters::<E>::new_full(*proving_system, powers, batch);
            let mut output = generate_output(&full_parameters, compressed_output);

            // Flatten the {full_contribution} vector.
            let full_contribution = full_contribution
                .iter()
                .map(|v| (v.as_slice(), compressed_output))
                .collect::<Vec<_>>();

            let parameters = Phase1Parameters::<E>::new(
                ContributionMode::Chunked,
                0,
                batch,
                full_parameters.curve,
                *proving_system,
                powers,
                batch,
            );
            Phase1::aggregation(&full_contribution, (&mut output, compressed_output), &parameters).unwrap();

            let parameters = Phase1Parameters::<E>::new_full(*proving_system, powers, batch);
            assert!(Phase1::aggregate_verification((&output, compressed_output, correctness), &parameters,).is_ok());
        }
    }

    #[test]
    #[should_panic]
    fn test_aggregation_bls12_377_wrong_chunks() {
        aggregation_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::No, UseCompression::Yes, true);
    }

    #[test]
    fn test_aggregation_bls12_377() {
        aggregation_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes, false);
        aggregation_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes, false);
        aggregation_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::No, UseCompression::No, false);
        aggregation_test::<Bls12_377>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::No, false);
    }

    #[test]
    #[should_panic]
    fn test_aggregation_bw6_wrong_chunks() {
        aggregation_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::No, UseCompression::Yes, true);
    }

    #[test]
    fn test_aggregation_bw6() {
        aggregation_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes, false);
        aggregation_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::Yes, false);
        aggregation_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::No, UseCompression::No, false);
        aggregation_test::<BW6_761>(4, 3 + 3 * 4, UseCompression::Yes, UseCompression::No, false);
    }
}
