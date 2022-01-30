use super::*;
use snarkvm_fields::{batch_inversion, Field};

impl<'a, E: PairingEngine + Sync> Phase1<'a, E> {
    ///
    /// Phase 1 - Computation: Steps 5, 6, and 7
    ///
    /// Reads an input buffer and a secret key **which must be destroyed after this function is executed**.
    /// It then generates 2^(N+1) -1 powers of tau (tau is stored inside the secret key).
    /// Finally, each group element read from the input is multiplied by the corresponding power of tau depending
    /// on its index and maybe some extra coefficient, and is written to the output buffer.
    ///
    pub fn computation(
        input: &[u8],
        output: &mut [u8],
        compressed_input: UseCompression,
        compressed_output: UseCompression,
        check_input_for_correctness: CheckForCorrectness,
        key: &PrivateKey<E>,
        parameters: &'a Phase1Parameters<E>,
    ) -> Result<()> {
        let span = info_span!("phase1-computation");
        let _enter = span.enter();

        info!("starting...");

        // Get immutable references of the input chunks.
        let (tau_g1_inputs, tau_g2_inputs, alpha_g1_inputs, beta_g1_inputs, mut beta_g2_inputs) =
            split(&input, parameters, compressed_input);

        // Get mutable references of the outputs.
        let (tau_g1_outputs, tau_g2_outputs, alpha_g1_outputs, beta_g1_outputs, beta_g2_outputs) =
            split_mut(output, parameters, compressed_output);
        info!("Parameters for contribution: {:?}", parameters);

        match parameters.proving_system {
            ProvingSystem::Groth16 => {
                // Write beta_g2 (0th index element) to beta_g2_outputs.
                {
                    // Fetch the element.
                    let mut beta_g2_el =
                        beta_g2_inputs.read_element::<E::G2Affine>(compressed_input, check_input_for_correctness)?;
                    // Multiply it by the key's beta element.
                    beta_g2_el = beta_g2_el.mul(key.beta);
                    // Write it back.
                    beta_g2_outputs.write_element(&beta_g2_el, compressed_output)?;
                }

                // load `batch_size` chunks on each iteration and perform the transformation
                iter_chunk(&parameters, |start, end| {
                    debug!("contributing to chunk from {} to {}", start, end);

                    let span = info_span!("batch", start, end);
                    let _enter = span.enter();

                    // Determine the chunk start and end indices based on the contribution mode.
                    let (start_chunk, end_chunk) = match parameters.contribution_mode {
                        ContributionMode::Chunked => (
                            start - parameters.chunk_index * parameters.chunk_size,
                            end - parameters.chunk_index * parameters.chunk_size,
                        ),
                        ContributionMode::Full => (start, end),
                    };

                    rayon_cfg::scope(|t| {
                        let _enter = span.enter();

                        t.spawn(|_| {
                            let _enter = span.enter();

                            // Generate powers from `start` to `end` (e.g. [0,4) then [4, 8) etc.)
                            let powers = generate_powers_of_tau::<E>(&key.tau, start, end);

                            trace!("generated powers of tau");

                            // Raise each element from the input buffer to the powers of tau
                            // and write the updated value (without allocating) to the
                            // output buffer
                            rayon_cfg::scope(|t| {
                                let _enter = span.enter();
                                info!("Starting powers of Tau in G1");

                                t.spawn(|_| {
                                    let _enter = span.enter();

                                    // Check that the chunk is of nonzero length.
                                    assert!(tau_g1_inputs.len() > 0);

                                    apply_powers::<E::G1Affine>(
                                        (tau_g1_outputs, compressed_output),
                                        (tau_g1_inputs, compressed_input, check_input_for_correctness),
                                        (start_chunk, end_chunk),
                                        &powers,
                                        None,
                                    )
                                    .expect("could not apply powers of tau to tau_g1 elements");

                                    info!("Applied powers to tau_g1 elements");
                                });
                                if start < parameters.powers_length {
                                    // if the `end` would be out of bounds, then just process until
                                    // the end (this is necessary in case the last batch would try to
                                    // process more elements than available)
                                    let max = match parameters.contribution_mode {
                                        ContributionMode::Chunked => std::cmp::min(
                                            (parameters.chunk_index + 1) * parameters.chunk_size,
                                            parameters.powers_length,
                                        ),
                                        ContributionMode::Full => parameters.powers_length,
                                    };
                                    let end = if start + parameters.batch_size > max { max } else { end };

                                    // Determine the chunk start and end indices based on the contribution mode.
                                    let (start_chunk, end_chunk) = match parameters.contribution_mode {
                                        ContributionMode::Chunked => (
                                            start - parameters.chunk_index * parameters.chunk_size,
                                            end - parameters.chunk_index * parameters.chunk_size,
                                        ),
                                        ContributionMode::Full => (start, end),
                                    };

                                    rayon_cfg::scope(|t| {
                                        let _enter = span.enter();

                                        t.spawn(|_| {
                                            let _enter = span.enter();
                                            info!("Starting powers of Tau in G2");

                                            // Check that the chunk is of nonzero length.
                                            assert!(tau_g2_inputs.len() > 0);

                                            apply_powers::<E::G2Affine>(
                                                (tau_g2_outputs, compressed_output),
                                                (tau_g2_inputs, compressed_input, check_input_for_correctness),
                                                (start_chunk, end_chunk),
                                                &powers,
                                                None,
                                            )
                                            .expect("could not apply powers of tau to tau_g2 elements");

                                            trace!("Applied powers of Tau in G2");
                                        });

                                        t.spawn(|_| {
                                            let _enter = span.enter();
                                            info!("Starting Alpha G1 elements");

                                            // Check that the chunk is of nonzero length.
                                            assert!(alpha_g1_inputs.len() > 0);

                                            apply_powers::<E::G1Affine>(
                                                (alpha_g1_outputs, compressed_output),
                                                (alpha_g1_inputs, compressed_input, check_input_for_correctness),
                                                (start_chunk, end_chunk),
                                                &powers,
                                                Some(&key.alpha),
                                            )
                                            .expect("could not apply powers of tau to alpha_g1 elements");

                                            info!("Applied powers to Alpha G1 elements");
                                        });

                                        t.spawn(|_| {
                                            info!("Starting beta G1 elements");
                                            let _enter = span.enter();

                                            // Check that the chunk is of nonzero length.
                                            assert!(beta_g1_inputs.len() > 0);

                                            apply_powers::<E::G1Affine>(
                                                (beta_g1_outputs, compressed_output),
                                                (beta_g1_inputs, compressed_input, check_input_for_correctness),
                                                (start_chunk, end_chunk),
                                                &powers,
                                                Some(&key.beta),
                                            )
                                            .expect("could not apply powers of tau to beta_g1 elements");

                                            trace!("Applied powers to Beta G1 elements");
                                        });
                                    });
                                }
                            });
                        });
                    });

                    debug!("chunk contribution successful");

                    Ok(())
                })?;
            }
            ProvingSystem::Marlin => {
                // we assume batch_size > 3 + 3*total_size_in_log2, allowing all the smaller amounts
                // of powers in tau G2 and alpha tau G1 to reside there
                if parameters.chunk_index == 0 {
                    let degree_bound_powers = (0..parameters.total_size_in_log2)
                        .map(|i| key.tau.pow([parameters.powers_length as u64 - 1 - (1 << i) + 2]))
                        .collect::<Vec<_>>();

                    let mut g2_inverse_powers = degree_bound_powers.clone();

                    batch_inversion(&mut g2_inverse_powers);

                    apply_powers::<E::G2Affine>(
                        (tau_g2_outputs, compressed_output),
                        (tau_g2_inputs, compressed_input, check_input_for_correctness),
                        (2, parameters.total_size_in_log2 + 2),
                        &g2_inverse_powers,
                        None,
                    )
                    .expect("could not apply powers of tau to tau_g2 elements");

                    let g1_degree_powers = degree_bound_powers
                        .into_iter()
                        .map(|f| vec![f, f * &key.tau, f * &key.tau.pow([2])])
                        .flatten()
                        .collect::<Vec<_>>();

                    apply_powers::<E::G1Affine>(
                        (alpha_g1_outputs, compressed_output),
                        (alpha_g1_inputs, compressed_input, check_input_for_correctness),
                        (3, 3 + 3 * parameters.total_size_in_log2),
                        &g1_degree_powers,
                        Some(&key.alpha),
                    )
                    .expect("could not apply powers of tau to tau_g2 elements");

                    let num_alpha_powers = 3;
                    let powers = generate_powers_of_tau::<E>(&key.tau, 0, num_alpha_powers);

                    apply_powers::<E::G1Affine>(
                        (alpha_g1_outputs, compressed_output),
                        (alpha_g1_inputs, compressed_input, check_input_for_correctness),
                        (0, num_alpha_powers),
                        &powers,
                        Some(&key.alpha),
                    )
                    .expect("could not apply powers of tau alpha to tau_g1 elements");

                    let powers = generate_powers_of_tau::<E>(&key.tau, 0, 2);

                    apply_powers::<E::G2Affine>(
                        (tau_g2_outputs, compressed_output),
                        (tau_g2_inputs, compressed_input, check_input_for_correctness),
                        (0, 2),
                        &powers,
                        None,
                    )
                    .expect("could not apply powers of tau to initial tau_g2 elements");
                }

                // load `batch_size` chunks on each iteration and perform the transformation
                iter_chunk(&parameters, |start, end| {
                    debug!("contributing to chunk from {} to {}", start, end);

                    let span = info_span!("batch", start, end);
                    let _enter = span.enter();

                    // Determine the chunk start and end indices based on the contribution mode.
                    let (start_chunk, end_chunk) = match parameters.contribution_mode {
                        ContributionMode::Chunked => (
                            start - parameters.chunk_index * parameters.chunk_size,
                            end - parameters.chunk_index * parameters.chunk_size,
                        ),
                        ContributionMode::Full => (start, end),
                    };

                    rayon_cfg::scope(|t| {
                        let _enter = span.enter();

                        t.spawn(|_| {
                            let _enter = span.enter();

                            // Generate powers from `start` to `end` (e.g. [0,4) then [4, 8) etc.)
                            let powers = generate_powers_of_tau::<E>(&key.tau, start, end);

                            trace!("generated powers of tau");

                            apply_powers::<E::G1Affine>(
                                (tau_g1_outputs, compressed_output),
                                (tau_g1_inputs, compressed_input, check_input_for_correctness),
                                (start_chunk, end_chunk),
                                &powers,
                                None,
                            )
                            .expect("could not apply powers of tau to tau_g1 elements");
                        });
                    });

                    debug!("chunk contribution successful");

                    Ok(())
                })?;
            }
        }

        info!("phase1-contribution complete");

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::testing::generate_input;
    use setup_utils::{batch_exp, derive_rng_from_seed, generate_powers_of_tau};

    use snarkvm_curves::{bls12_377::Bls12_377, bw6_761::BW6_761};

    fn curve_computation_test<E: PairingEngine>(
        powers: usize,
        batch: usize,
        compressed_input: UseCompression,
        compressed_output: UseCompression,
    ) {
        let input_correctness = CheckForCorrectness::Full;

        for proving_system in &[ProvingSystem::Groth16, ProvingSystem::Marlin] {
            let parameters = Phase1Parameters::<E>::new_full(*proving_system, powers, batch);
            let expected_response_length = parameters.get_length(compressed_output);

            // Get a non-mutable copy of the initial accumulator state.
            let (input, mut before) = generate_input(&parameters, compressed_input, CheckForCorrectness::No);

            let mut output = vec![0; expected_response_length];

            // Construct our keypair using the RNG we created above
            let current_accumulator_hash = blank_hash();
            let mut rng = derive_rng_from_seed(b"curve_computation_test");
            let (_, privkey) = Phase1::key_generation(&mut rng, current_accumulator_hash.as_ref())
                .expect("could not generate keypair");

            Phase1::computation(
                &input,
                &mut output,
                compressed_input,
                compressed_output,
                input_correctness,
                &privkey,
                &parameters,
            )
            .unwrap();

            let deserialized = Phase1::deserialize(&output, compressed_output, input_correctness, &parameters).unwrap();

            match proving_system {
                ProvingSystem::Groth16 => {
                    let tau_powers = generate_powers_of_tau::<E>(&privkey.tau, 0, parameters.powers_g1_length);
                    batch_exp(
                        &mut before.tau_powers_g1,
                        &tau_powers[0..parameters.g1_chunk_size],
                        None,
                    )
                    .unwrap();
                    batch_exp(
                        &mut before.tau_powers_g2,
                        &tau_powers[0..parameters.other_chunk_size],
                        None,
                    )
                    .unwrap();
                    batch_exp(
                        &mut before.alpha_tau_powers_g1,
                        &tau_powers[0..parameters.other_chunk_size],
                        Some(&privkey.alpha),
                    )
                    .unwrap();
                    batch_exp(
                        &mut before.beta_tau_powers_g1,
                        &tau_powers[0..parameters.other_chunk_size],
                        Some(&privkey.beta),
                    )
                    .unwrap();
                    before.beta_g2 = before.beta_g2.mul(privkey.beta);
                }
                ProvingSystem::Marlin => {
                    let tau_powers = generate_powers_of_tau::<E>(&privkey.tau, 0, parameters.powers_length);
                    batch_exp(
                        &mut before.tau_powers_g1,
                        &tau_powers[0..parameters.powers_length],
                        None,
                    )
                    .unwrap();

                    let degree_bound_powers = (0..parameters.total_size_in_log2)
                        .map(|i| privkey.tau.pow([parameters.powers_length as u64 - 1 - (1 << i) + 2]))
                        .collect::<Vec<_>>();
                    let mut g2_inverse_powers = degree_bound_powers.clone();
                    batch_inversion(&mut g2_inverse_powers);
                    batch_exp(&mut before.tau_powers_g2[..2], &tau_powers[0..2], None).unwrap();
                    batch_exp(
                        &mut before.tau_powers_g2[2..],
                        &g2_inverse_powers[0..parameters.total_size_in_log2],
                        None,
                    )
                    .unwrap();

                    let g1_degree_powers = degree_bound_powers
                        .into_iter()
                        .map(|f| vec![f, f * &privkey.tau, f * &privkey.tau * &privkey.tau])
                        .flatten()
                        .collect::<Vec<_>>();
                    batch_exp(
                        &mut before.alpha_tau_powers_g1[3..3 + 3 * parameters.total_size_in_log2],
                        &g1_degree_powers,
                        Some(&privkey.alpha),
                    )
                    .unwrap();
                    batch_exp(
                        &mut before.alpha_tau_powers_g1[0..3],
                        &tau_powers[0..3],
                        Some(&privkey.alpha),
                    )
                    .unwrap();
                }
            }
            assert_eq!(deserialized, before);
        }
    }

    #[test]
    fn test_computation_bls12_377_compressed() {
        // Receives a compressed/uncompressed input, contributes to it, and produces a compressed/uncompressed output
        curve_computation_test::<Bls12_377>(2, 2, UseCompression::Yes, UseCompression::Yes);
        curve_computation_test::<Bls12_377>(2, 2, UseCompression::No, UseCompression::Yes);
        curve_computation_test::<Bls12_377>(2, 2, UseCompression::Yes, UseCompression::No);

        // Works even when the batch is larger than the powers
        curve_computation_test::<Bls12_377>(6, 128, UseCompression::Yes, UseCompression::Yes);
        curve_computation_test::<Bls12_377>(6, 128, UseCompression::No, UseCompression::Yes);
        curve_computation_test::<Bls12_377>(6, 128, UseCompression::Yes, UseCompression::No);
    }

    #[test]
    fn test_computation_bls12_377_uncompressed() {
        // Receives an uncompressed input, contributes to it, and produces an uncompressed output
        curve_computation_test::<Bls12_377>(3, 4, UseCompression::No, UseCompression::No);
        curve_computation_test::<Bls12_377>(6, 64, UseCompression::No, UseCompression::No);

        // Works even if the batch is larger than the powers
        curve_computation_test::<Bls12_377>(6, 128, UseCompression::No, UseCompression::No);
    }

    #[test]
    fn test_computation_bw6_761_compressed() {
        // Receives a compressed/uncompressed input, contributes to it, and produces a compressed/uncompressed output
        curve_computation_test::<BW6_761>(2, 2, UseCompression::Yes, UseCompression::Yes);
        curve_computation_test::<BW6_761>(2, 2, UseCompression::No, UseCompression::Yes);
        curve_computation_test::<BW6_761>(2, 2, UseCompression::Yes, UseCompression::No);

        // Works even when the batch is larger than the powers
        curve_computation_test::<BW6_761>(6, 128, UseCompression::Yes, UseCompression::Yes);
        curve_computation_test::<BW6_761>(6, 128, UseCompression::No, UseCompression::Yes);
        curve_computation_test::<BW6_761>(6, 128, UseCompression::Yes, UseCompression::No);
    }

    #[test]
    fn test_computation_bw6_761_uncompressed() {
        // Receives an uncompressed input, contributes to it, and produces an uncompressed output
        curve_computation_test::<BW6_761>(3, 4, UseCompression::No, UseCompression::No);
        curve_computation_test::<BW6_761>(6, 64, UseCompression::No, UseCompression::No);

        // Works even if the batch is larger than the powers
        curve_computation_test::<BW6_761>(6, 128, UseCompression::No, UseCompression::No);
    }
}
