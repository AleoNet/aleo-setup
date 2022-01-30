use crate::{ContributionMode, Phase1Parameters, ProvingSystem};
use setup_utils::{BatchDeserializer, BatchSerializer, *};

use snarkvm_curves::{AffineCurve, PairingEngine};

use itertools::{Itertools, MinMaxResult};

/// Buffer, compression
type Input<'a> = (&'a [u8], UseCompression, CheckForCorrectness);

/// Mutable buffer, compression
type Output<'a> = (&'a mut [u8], UseCompression);

/// Mutable slices with format [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
type SplitBufMut<'a> = (&'a mut [u8], &'a mut [u8], &'a mut [u8], &'a mut [u8], &'a mut [u8]);

/// Immutable slices with format [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
type SplitBuf<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8], &'a [u8]);

/// Helper function to iterate over the accumulator in chunks.
/// `action` will perform an action on the chunk
pub(crate) fn iter_chunk(
    parameters: &Phase1Parameters<impl PairingEngine>,
    mut action: impl FnMut(usize, usize) -> Result<()>,
) -> Result<()> {
    // Determine the range to iterate over.
    let (min, max) = {
        // Determine the number of elements to process based on the proof system's requirement.
        let upper_bound = match parameters.proving_system {
            ProvingSystem::Groth16 => parameters.powers_g1_length,
            ProvingSystem::Marlin => parameters.powers_length,
        };

        // In chunked contribution mode, select the chunk to iterate over.
        // In full contribution mode, select the entire range up to the upper bound.
        let (min, max) = match parameters.contribution_mode {
            ContributionMode::Chunked => (
                parameters.chunk_index * parameters.chunk_size,
                std::cmp::min((parameters.chunk_index + 1) * parameters.chunk_size, upper_bound),
            ),
            ContributionMode::Full => (0, upper_bound),
        };

        (min, max)
    };

    // Iterate over the range, processing each element with the given input.
    (min..max)
        .chunks(parameters.batch_size - 1)
        .into_iter()
        .map(|chunk| {
            let (start, end) = match chunk.minmax() {
                MinMaxResult::MinMax(start, end) => (start, if end >= max - 1 { end + 1 } else { end + 2 }), // ensure there's overlap between chunks
                MinMaxResult::OneElement(start) => (start, if start >= max - 1 { start + 1 } else { start + 2 }),
                _ => return Err(Error::InvalidChunk),
            };
            action(start, end)
        })
        .collect::<Result<_>>()
}

/// Takes a buffer, reads the group elements in it, exponentiates them to the
/// provided `powers` and maybe to the `coeff`, and then writes them back
pub(crate) fn apply_powers<C: AffineCurve>(
    (output, output_compressed): Output,
    (input, input_compressed, check_input_for_correctness): Input,
    (start, end): (usize, usize),
    powers: &[C::ScalarField],
    coeff: Option<&C::ScalarField>,
) -> Result<()> {
    tracing::debug!("Applying powers {} to {}", start, end);
    let in_size = buffer_size::<C>(input_compressed);
    let out_size = buffer_size::<C>(output_compressed);

    // Read the input
    let elements =
        &mut input[start * in_size..end * in_size].read_batch::<C>(input_compressed, check_input_for_correctness)?;
    // calculate the powers
    batch_exp(elements, &powers[..(end - start)], coeff)?;
    // write back
    output[(start * out_size)..(end * out_size)].write_batch(elements, output_compressed)?;

    Ok(())
}

#[cfg(not(feature = "wasm"))]
/// Splits the full buffer in 5 non overlapping mutable slice for a given chunk and batch size.
/// Each slice corresponds to the group elements in the following order
/// [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
pub(crate) fn split_at_chunk_mut<'a, E: PairingEngine>(
    buffer: &'a mut [u8],
    parameters: &'a Phase1Parameters<E>,
    compressed: UseCompression,
) -> SplitBufMut<'a> {
    let g1_size = buffer_size::<E::G1Affine>(compressed);
    let g2_size = buffer_size::<E::G2Affine>(compressed);

    let buffer_to_chunk = |buffer: &'a mut [u8], element_size: usize, is_other: bool| -> &'a mut [u8] {
        // Determine whether to return an empty chunk based on the size of 'other'.
        if is_other && parameters.other_chunk_size == 0 {
            return &mut [];
        }

        // Determine the chunk size based on the proof system.
        let chunk_size = match (parameters.proving_system, is_other) {
            (ProvingSystem::Groth16, true) => parameters.other_chunk_size,
            (ProvingSystem::Groth16, false) => parameters.g1_chunk_size,
            (ProvingSystem::Marlin, true) => return &mut [],
            (ProvingSystem::Marlin, false) => parameters.g1_chunk_size,
        };

        let start = parameters.chunk_index * parameters.chunk_size * element_size;
        let end = start + chunk_size * element_size;

        &mut buffer[start..end]
    };

    match parameters.proving_system {
        ProvingSystem::Groth16 => {
            // leave the first 64 bytes for the hash
            let (_, others) = buffer.split_at_mut(parameters.hash_size);
            let (tau_g1, others) = others.split_at_mut(g1_size * parameters.powers_g1_length);
            let (tau_g2, others) = others.split_at_mut(g2_size * parameters.powers_length);
            let (alpha_g1, others) = others.split_at_mut(g1_size * parameters.powers_length);
            let (beta_g1, beta_g2) = others.split_at_mut(g1_size * parameters.powers_length);

            // We take up to g2_size for beta_g2, since there might be other
            // elements after it at the end of the buffer.
            (
                buffer_to_chunk(tau_g1, g1_size, false),
                buffer_to_chunk(tau_g2, g2_size, true),
                buffer_to_chunk(alpha_g1, g1_size, true),
                buffer_to_chunk(beta_g1, g1_size, true),
                &mut beta_g2[0..g2_size],
            )
        }
        ProvingSystem::Marlin => {
            let (g2_chunk_size, alpha_chunk_size) = if parameters.chunk_index == 0 {
                (parameters.total_size_in_log2 + 2, 3 + 3 * parameters.total_size_in_log2)
            } else {
                (0, 0)
            };

            // leave the first 64 bytes for the hash
            let (_, others) = buffer.split_at_mut(parameters.hash_size);
            let (tau_g1, others) = others.split_at_mut(g1_size * parameters.powers_length);
            let (tau_g2, others) = others.split_at_mut(g2_size * g2_chunk_size);
            let (alpha_g1, _) = others.split_at_mut(g1_size * alpha_chunk_size);

            (
                buffer_to_chunk(tau_g1, g1_size, false),
                tau_g2,
                alpha_g1,
                &mut [],
                &mut [],
            )
        }
    }
}

/// Splits the full buffer in 5 non overlapping mutable slice.
/// Each slice corresponds to the group elements in the following order
/// [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
pub(crate) fn split_mut<'a, E: PairingEngine>(
    buffer: &'a mut [u8],
    parameters: &'a Phase1Parameters<E>,
    compressed: UseCompression,
) -> SplitBufMut<'a> {
    match parameters.proving_system {
        ProvingSystem::Groth16 => {
            let g1_size = buffer_size::<E::G1Affine>(compressed);
            let g2_size = buffer_size::<E::G2Affine>(compressed);

            let g1_chunk_size = parameters.g1_chunk_size;
            let other_chunk_size = parameters.other_chunk_size;

            let (_, others) = buffer.split_at_mut(parameters.hash_size);
            let (tau_g1, others) = others.split_at_mut(g1_size * g1_chunk_size);
            let (tau_g2, others) = others.split_at_mut(g2_size * other_chunk_size);
            let (alpha_g1, others) = others.split_at_mut(g1_size * other_chunk_size);
            let (beta_g1, beta_g2) = others.split_at_mut(g1_size * other_chunk_size);

            // We take up to g2_size for beta_g2, since there might be other
            // elements after it at the end of the buffer.
            (tau_g1, tau_g2, alpha_g1, beta_g1, &mut beta_g2[0..g2_size])
        }
        ProvingSystem::Marlin => {
            let g1_size = buffer_size::<E::G1Affine>(compressed);
            let g2_size = buffer_size::<E::G2Affine>(compressed);

            let g1_chunk_size = parameters.g1_chunk_size;
            let (g2_chunk_size, alpha_chunk_size) = if parameters.chunk_index == 0 {
                (parameters.total_size_in_log2 + 2, 3 + 3 * parameters.total_size_in_log2)
            } else {
                (0, 0)
            };

            let (_, others) = buffer.split_at_mut(parameters.hash_size);
            let (tau_g1, others) = others.split_at_mut(g1_size * g1_chunk_size);
            let (tau_g2, others) = others.split_at_mut(g2_size * g2_chunk_size);
            let (alpha_g1, _) = others.split_at_mut(g1_size * alpha_chunk_size);

            (tau_g1, tau_g2, alpha_g1, &mut [], &mut [])
        }
    }
}

/// Splits the full buffer in 5 non overlapping immutable slice.
/// Each slice corresponds to the group elements in the following order
/// [TauG1, TauG2, AlphaG1, BetaG1, BetaG2]
pub(crate) fn split<'a, E: PairingEngine>(
    buffer: &'a [u8],
    parameters: &Phase1Parameters<E>,
    compressed: UseCompression,
) -> SplitBuf<'a> {
    match parameters.proving_system {
        ProvingSystem::Groth16 => {
            let g1_size = buffer_size::<E::G1Affine>(compressed);
            let g2_size = buffer_size::<E::G2Affine>(compressed);

            let g1_chunk_size = parameters.g1_chunk_size;
            let other_chunk_size = parameters.other_chunk_size;

            let (_, others) = buffer.split_at(parameters.hash_size);
            let (tau_g1, others) = others.split_at(g1_size * g1_chunk_size);
            let (tau_g2, others) = others.split_at(g2_size * other_chunk_size);
            let (alpha_g1, others) = others.split_at(g1_size * other_chunk_size);
            let (beta_g1, beta_g2) = others.split_at(g1_size * other_chunk_size);

            // Check that tau_g1 is not empty.
            assert!(tau_g1.len() > 0);

            // We take up to g2_size for beta_g2, since there might be other
            // elements after it at the end of the buffer.
            (tau_g1, tau_g2, alpha_g1, beta_g1, &beta_g2[0..g2_size])
        }
        ProvingSystem::Marlin => {
            let g1_size = buffer_size::<E::G1Affine>(compressed);
            let g2_size = buffer_size::<E::G2Affine>(compressed);

            let g1_chunk_size = parameters.g1_chunk_size;
            let (g2_chunk_size, alpha_chunk_size) = if parameters.chunk_index == 0 {
                (parameters.total_size_in_log2 + 2, 3 + 3 * parameters.total_size_in_log2)
            } else {
                (0, 0)
            };

            let (_, others) = buffer.split_at(parameters.hash_size);
            let (tau_g1, others) = others.split_at(g1_size * g1_chunk_size);
            let (tau_g2, others) = others.split_at(g2_size * g2_chunk_size);
            let (alpha_g1, _) = others.split_at(g1_size * alpha_chunk_size);

            // Check that tau_g1 is not empty.
            assert!(tau_g1.len() > 0);

            (tau_g1, tau_g2, alpha_g1, &[], &[])
        }
    }
}
