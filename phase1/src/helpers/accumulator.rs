//! Accumulator which operates on batches of data

use crate::{helpers::buffers::*, Phase1Parameters, ProvingSystem};
use cfg_if::cfg_if;
use setup_utils::{BatchDeserializer, BatchSerializer, Deserializer, Serializer, *};

use snarkvm_curves::{AffineCurve, PairingEngine};

#[cfg(not(feature = "wasm"))]
use crate::ContributionMode;
#[cfg(not(feature = "wasm"))]
use snarkvm_fields::{FieldParameters, PrimeField, Zero};
#[cfg(not(feature = "wasm"))]
use snarkvm_utilities::BitIteratorBE;

#[allow(type_alias_bounds)]
type AccumulatorElements<E: PairingEngine> = (
    Vec<E::G1Affine>,
    Vec<E::G2Affine>,
    Vec<E::G1Affine>,
    Vec<E::G1Affine>,
    E::G2Affine,
);

#[allow(type_alias_bounds)]
#[allow(unused)]
type AccumulatorElementsRef<'a, E: PairingEngine> = (
    &'a [E::G1Affine],
    &'a [E::G2Affine],
    &'a [E::G1Affine],
    &'a [E::G1Affine],
    &'a E::G2Affine,
);

cfg_if! {
    if #[cfg(not(feature = "wasm"))] {
        use crate::PublicKey;

        /// Given a public key and the accumulator's digest, it hashes each G1 element
        /// along with the digest, and then hashes it to G2.
        pub(crate) fn compute_g2_s_key<E: PairingEngine>(key: &PublicKey<E>, digest: &[u8]) -> Result<[E::G2Affine; 3]> {
            Ok([
                compute_g2_s::<E>(&digest, &key.tau_g1.0, &key.tau_g1.1, 0)?,
                compute_g2_s::<E>(&digest, &key.alpha_g1.0, &key.alpha_g1.1, 1)?,
                compute_g2_s::<E>(&digest, &key.beta_g1.0, &key.beta_g1.1, 2)?,
            ])
        }

        /// Reads a list of G1 elements from the buffer to the provided `elements` slice
        /// and then checks that their powers pairs ratio matches the one from the
        /// provided `check` pair
        pub(crate) fn check_power_ratios<E: PairingEngine>(
            (buffer, compression, check_for_correctness): (&[u8], UseCompression, CheckForCorrectness),
            (start, end): (usize, usize),
            elements: &mut [E::G1Affine],
            check: &(E::G2Affine, E::G2Affine),
        ) -> Result<()> {
            let size = buffer_size::<E::G1Affine>(compression);
            buffer[start * size..end * size].read_batch_preallocated(
                &mut elements[0..end - start],
                compression,
                check_for_correctness,
            )?;
            check_same_ratio::<E>(&power_pairs(&elements[..end - start]), check, "Power pairs")?;
            Ok(())
        }

        /// Reads a list of G2 elements from the buffer to the provided `elements` slice
        /// and then checks that their powers pairs ratio matches the one from the
        /// provided `check` pair
        pub(crate) fn check_power_ratios_g2<E: PairingEngine>(
            (buffer, compression, check_for_correctness): (&[u8], UseCompression, CheckForCorrectness),
            (start, end): (usize, usize),
            elements: &mut [E::G2Affine],
            check: &(E::G1Affine, E::G1Affine),
        ) -> Result<()> {
            let size = buffer_size::<E::G2Affine>(compression);
            buffer[start * size..end * size].read_batch_preallocated(
                &mut elements[0..end - start],
                compression,
                check_for_correctness,
            )?;
            check_same_ratio::<E>(check, &power_pairs(&elements[..end - start]), "Power pairs")?;
            Ok(())
        }

        /// Reads a list of group elements from the buffer to the provided `elements` slice
        /// and then checks that the elements are nonzero and in the prime order subgroup.
        pub(crate) fn check_elements_are_nonzero_and_in_prime_order_subgroup<C: AffineCurve>(
            (buffer, compression): (&[u8], UseCompression),
            (start, end): (usize, usize),
            elements: &mut [C],
        ) -> Result<()> {
            let size = buffer_size::<C>(compression);
            buffer[start * size..end * size].read_batch_preallocated(
                &mut elements[0..end - start],
                compression,
                CheckForCorrectness::Full,
            )?;
            // TODO(kobi): replace with batch subgroup check
            let all_in_prime_order_subgroup = elements.iter().all(|p| {
                p.mul_bits(BitIteratorBE::new(<<C::ScalarField as PrimeField>::Parameters as FieldParameters>::MODULUS))
                    .is_zero()
            });
            if !all_in_prime_order_subgroup {
                return Err(Error::IncorrectSubgroup);
            }
            Ok(())
        }

        /// Reads a chunk of 2 elements from the buffer
        pub(crate) fn read_initial_elements<C: AffineCurve>(
            buffer: &[u8],
            compressed: UseCompression,
            check_input_for_correctness: CheckForCorrectness,
        ) -> Result<Vec<C>> {
            read_initial_elements_with_amount(buffer, 2, compressed, check_input_for_correctness)
        }

        /// Reads a chunk of {amount} elements from the buffer
        pub(crate) fn read_initial_elements_with_amount<C: AffineCurve>(
            buffer: &[u8],
            amount: usize,
            compressed: UseCompression,
            check_input_for_correctness: CheckForCorrectness,
        ) -> Result<Vec<C>> {
            let batch = amount;
            let size = buffer_size::<C>(compressed);
            let result = buffer[0..batch * size].read_batch(compressed, check_input_for_correctness)?;
            if result.len() != batch {
                return Err(Error::InvalidLength {
                    expected: batch,
                    got: result.len(),
                });
            }
            Ok(result)
        }

        /// Takes a compressed input buffer and decompresses it.
        fn decompress_buffer<C: AffineCurve>(
            output: &mut [u8],
            input: &[u8],
            check_input_for_correctness: CheckForCorrectness,
            (start, end): (usize, usize),
        ) -> Result<()> {
            let in_size = buffer_size::<C>(UseCompression::Yes);
            let out_size = buffer_size::<C>(UseCompression::No);
            // read the compressed input
            let elements =
                input[start * in_size..end * in_size].read_batch::<C>(UseCompression::Yes, check_input_for_correctness)?;
            // write it back uncompressed
            output[start * out_size..end * out_size].write_batch(&elements, UseCompression::No)?;

            Ok(())
        }

        /// Takes a compressed input buffer and decompresses it into the output buffer.
        pub fn decompress<E: PairingEngine>(
            input: &[u8],
            output: &mut [u8],
            check_input_for_correctness: CheckForCorrectness,
            parameters: &Phase1Parameters<E>,
        ) -> Result<()> {
            let compressed_input = UseCompression::Yes;
            let compressed_output = UseCompression::No;

            match parameters.proving_system {
                ProvingSystem::Groth16 => {
                    // Get an immutable reference to the compressed input chunks
                    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, mut in_beta_g2) = split(&input, parameters, compressed_input);
                    // Get mutable refs to the decompressed outputs
                    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) = split_mut(output, parameters, compressed_output);

                    // Decompress beta_g2
                    {
                        // Get the compressed element
                        let beta_g2_el =
                            in_beta_g2.read_element::<E::G2Affine>(compressed_input, check_input_for_correctness)?;
                        // Write it back decompressed
                        beta_g2.write_element(&beta_g2_el, compressed_output)?;
                    }

                    // Load `batch_size` chunks on each iteration and decompress them
                    rayon::scope(|t| {
                        t.spawn(|_| {
                            decompress_buffer::<E::G1Affine>(
                                tau_g1,
                                in_tau_g1,
                                check_input_for_correctness,
                                (0, parameters.g1_chunk_size),
                            )
                            .expect("could not decompress the tau_g1 elements")
                        });
                        if parameters.other_chunk_size > 0 {
                            rayon::scope(|t| {
                                t.spawn(|_| {
                                    decompress_buffer::<E::G2Affine>(
                                        tau_g2,
                                        in_tau_g2,
                                        check_input_for_correctness,
                                        (0, parameters.other_chunk_size),
                                    )
                                    .expect("could not decompress the tau_g2 elements")
                                });
                                t.spawn(|_| {
                                    decompress_buffer::<E::G1Affine>(
                                        alpha_g1,
                                        in_alpha_g1,
                                        check_input_for_correctness,
                                        (0, parameters.other_chunk_size),
                                    )
                                    .expect("could not decompress the alpha_g1 elements")
                                });
                                t.spawn(|_| {
                                    decompress_buffer::<E::G1Affine>(
                                        beta_g1,
                                        in_beta_g1,
                                        check_input_for_correctness,
                                        (0, parameters.other_chunk_size),
                                    )
                                    .expect("could not decompress the beta_g1 elements")
                                });
                            });
                        }
                    });
                }
                ProvingSystem::Marlin => {
                    // Get an immutable reference to the compressed input chunks
                    let (in_tau_g1, in_tau_g2, in_alpha_g1, _, _) = split(&input, parameters, compressed_input);
                    // Get mutable refs to the decompressed outputs
                    let (tau_g1, tau_g2, alpha_g1, _, _) = split_mut(output, parameters, compressed_output);

                    if parameters.chunk_index == 0 || parameters.contribution_mode == ContributionMode::Full {
                        // Load `batch_size` chunks on each iteration and decompress them
                        let num_alpha_powers = 3;
                        decompress_buffer::<E::G1Affine>(
                            alpha_g1,
                            in_alpha_g1,
                            check_input_for_correctness,
                            (0, num_alpha_powers + 3*parameters.total_size_in_log2),
                        )?;
                        decompress_buffer::<E::G2Affine>(tau_g2, in_tau_g2, check_input_for_correctness, (0, parameters.total_size_in_log2 + 2))?;
                    }

                    rayon::scope(|t| {
                         t.spawn(|_| {
                            decompress_buffer::<E::G1Affine>(
                                tau_g1,
                                in_tau_g1,
                                check_input_for_correctness,
                                (0, parameters.g1_chunk_size),
                            )
                            .expect("could not decompress the tau_g1 elements")
                        });
                    });
                }
            }
            Ok(())
        }
    }
}

/// Serializes all the provided elements to the output buffer
#[allow(unused)]
pub fn serialize<E: PairingEngine>(
    elements: AccumulatorElementsRef<E>,
    output: &mut [u8],
    compressed: UseCompression,
    parameters: &Phase1Parameters<E>,
) -> Result<()> {
    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) = elements;
    let (tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2) = split_mut(output, parameters, compressed);

    tau_g1.write_batch(&in_tau_g1, compressed)?;
    tau_g2.write_batch(&in_tau_g2, compressed)?;
    alpha_g1.write_batch(&in_alpha_g1, compressed)?;
    beta_g1.write_batch(&in_beta_g1, compressed)?;
    match parameters.proving_system {
        ProvingSystem::Groth16 => beta_g2.write_element(in_beta_g2, compressed)?,
        ProvingSystem::Marlin => {}
    }

    Ok(())
}

/// Warning, only use this on machines which have enough memory to load
/// the accumulator in memory
pub fn deserialize<E: PairingEngine>(
    input: &[u8],
    compressed: UseCompression,
    check_input_for_correctness: CheckForCorrectness,
    parameters: &Phase1Parameters<E>,
) -> Result<AccumulatorElements<E>> {
    // Get an immutable reference to the input chunks
    let (in_tau_g1, in_tau_g2, in_alpha_g1, in_beta_g1, in_beta_g2) = split(&input, parameters, compressed);

    // Deserialize each part of the buffer separately
    let tau_g1 = in_tau_g1.read_batch(compressed, check_input_for_correctness)?;
    let tau_g2 = in_tau_g2.read_batch(compressed, check_input_for_correctness)?;
    let alpha_g1 = in_alpha_g1.read_batch(compressed, check_input_for_correctness)?;
    let beta_g1 = in_beta_g1.read_batch(compressed, check_input_for_correctness)?;
    let beta_g2 = match parameters.proving_system {
        ProvingSystem::Groth16 => (&*in_beta_g2).read_element(compressed, check_input_for_correctness)?,
        ProvingSystem::Marlin => E::G2Affine::prime_subgroup_generator(),
    };

    Ok((tau_g1, tau_g2, alpha_g1, beta_g1, beta_g2))
}

#[cfg(not(feature = "wasm"))]
#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::testing::random_point_vec;

    use snarkvm_curves::bls12_377::Bls12_377;

    use rand::thread_rng;

    fn decompress_buffer_curve_test<C: AffineCurve>() {
        // Generate some random points.
        let mut rng = thread_rng();
        let num_els = 10;
        let elements: Vec<C> = random_point_vec(num_els, &mut rng);
        // Write them as compressed elements.
        let len = num_els * buffer_size::<C>(UseCompression::Yes);
        let mut input = vec![0; len];
        input.write_batch(&elements, UseCompression::Yes).unwrap();

        // Allocate the decompressed buffer.
        let len = num_els * buffer_size::<C>(UseCompression::No);
        let mut out = vec![0; len];
        // Perform the decompression.
        decompress_buffer::<C>(&mut out, &input, CheckForCorrectness::Full, (0, num_els)).unwrap();
        let deserialized = out
            .read_batch::<C>(UseCompression::No, CheckForCorrectness::Full)
            .unwrap();
        // Ensure they match.
        assert_eq!(deserialized, elements);
    }

    #[test]
    fn test_decompress_buffer() {
        decompress_buffer_curve_test::<<Bls12_377 as PairingEngine>::G1Affine>();
        decompress_buffer_curve_test::<<Bls12_377 as PairingEngine>::G2Affine>();
    }
}
