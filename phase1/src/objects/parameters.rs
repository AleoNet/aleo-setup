use setup_utils::UseCompression;

use snarkos_models::curves::PairingEngine;
use snarkos_utilities::ConstantSerializedSize;

use serde::{Deserialize, Serialize};
use std::marker::PhantomData;

#[derive(Clone, PartialEq, Eq, Debug, Copy, Serialize, Deserialize)]
pub enum ContributionMode {
    Full,
    Chunked,
}

#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
pub enum ProvingSystem {
    Groth16,
    Marlin,
}

/// The sizes of the group elements of a curve
#[derive(Clone, PartialEq, Eq, Default, Debug)]
pub struct CurveParameters<E> {
    /// Size of a G1 Element
    pub g1_size: usize,
    /// Size of a G2 Element
    pub g2_size: usize,
    /// Size of a compressed G1 Element
    pub g1_compressed_size: usize,
    /// Size of a compressed G2 Element
    pub g2_compressed_size: usize,
    engine_type: PhantomData<E>,
}

impl<E: PairingEngine> CurveParameters<E> {
    pub fn new() -> CurveParameters<E> {
        CurveParameters {
            g1_size: <E as PairingEngine>::G1Affine::UNCOMPRESSED_SIZE,
            g2_size: <E as PairingEngine>::G2Affine::UNCOMPRESSED_SIZE,
            g1_compressed_size: <E as PairingEngine>::G1Affine::SERIALIZED_SIZE,
            g2_compressed_size: <E as PairingEngine>::G2Affine::SERIALIZED_SIZE,
            engine_type: PhantomData,
        }
    }
}

/// The parameters used for the trusted setup ceremony
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Phase1Parameters<E> {
    /// The contribution mode
    pub contribution_mode: ContributionMode,
    /// The chunk index
    pub chunk_index: usize,
    /// The chunk size
    pub chunk_size: usize,
    /// The type of the curve being used
    pub curve: CurveParameters<E>,
    /// Proving system
    pub proving_system: ProvingSystem,
    /// The number of tau_g1 elements which will be accumulated in this chunk
    pub g1_chunk_size: usize,
    /// The number of tau_g2, alpha_g1, and beta_g1 elements which will be accumulated in this chunk
    pub other_chunk_size: usize,
    /// The total number of Powers of Tau G1 elements which will be accumulated
    pub powers_g1_length: usize,
    /// The total number of Powers of Tau Alpha/Beta/G2 elements which will be accumulated
    pub powers_length: usize,
    /// The circuit size exponent (ie length will be 2^size),
    /// depends on the computation you want to support.
    pub total_size_in_log2: usize,
    /// The size of each chunk.
    pub batch_size: usize,
    /// Size of the used public key
    pub public_key_size: usize,
    /// Total size of the accumulator used for the ceremony
    pub accumulator_size: usize,
    /// Total size of the contribution
    pub contribution_size: usize,
    /// Size of the hash of the previous contribution
    pub hash_size: usize,
}

impl<E: PairingEngine> Phase1Parameters<E> {
    /// Constructs a new ceremony parameters object from the type of provided curve
    /// Panics if given batch_size = 0
    pub fn new_full(proving_system: ProvingSystem, total_size_in_log2: usize, batch_size: usize) -> Self {
        let curve = CurveParameters::<E>::new();
        Self::new(
            ContributionMode::Full,
            0,
            0,
            curve,
            proving_system,
            total_size_in_log2,
            batch_size,
        )
    }

    /// Constructs a new ceremony parameters object for a chunk from the type of provided curve
    /// Panics if given batch_size = 0
    pub fn new_chunk(
        contribution_mode: ContributionMode,
        chunk_index: usize,
        chunk_size: usize,
        proving_system: ProvingSystem,
        total_size_in_log2: usize,
        batch_size: usize,
    ) -> Self {
        // create the curve
        let curve = CurveParameters::<E>::new();
        Self::new(
            contribution_mode,
            chunk_index,
            chunk_size,
            curve,
            proving_system,
            total_size_in_log2,
            batch_size,
        )
    }

    /// Constructs a new ceremony parameters object from the directly provided curve with parameters
    /// Consider using the `new` method if you want to use one of the pre-implemented curves
    pub fn new(
        contribution_mode: ContributionMode,
        chunk_index: usize,
        chunk_size: usize,
        curve: CurveParameters<E>,
        proving_system: ProvingSystem,
        total_size_in_log2: usize,
        batch_size: usize,
    ) -> Self {
        // assume we're using a 64 byte long hash function such as Blake
        let hash_size = 64;

        let (g1_chunk_size, other_chunk_size) = Self::chunk_sizes(
            contribution_mode,
            chunk_index,
            chunk_size,
            proving_system,
            total_size_in_log2,
        );

        let accumulator_size = match proving_system {
            ProvingSystem::Groth16 => {
                // G1 Tau powers
                g1_chunk_size * curve.g1_size +
                    // G2 Tau Powers + Alpha Tau powers + Beta Tau powers
                    (other_chunk_size * (curve.g2_size + (curve.g1_size * 2))) +
                    // Beta in G2
                    curve.g2_size +
                    // Hash of the previous contribution
                    hash_size
            }
            ProvingSystem::Marlin => {
                // G1 Tau powers
                g1_chunk_size * curve.g1_size
                    + if chunk_index == 0 {
                        // Alpha in G1
                        (3 * curve.g1_size) + (3 * total_size_in_log2 * curve.g1_size) +
                            // G2 1/Tau Powers
                            (total_size_in_log2 + 2) * curve.g2_size
                    } else {
                        0
                    }
                    // Hash of the previous contribution
                    + hash_size
            }
        };

        let public_key_size =
           // tau, alpha, beta in g2
           3 * curve.g2_compressed_size +
           // (s1, s1*tau), (s2, s2*alpha), (s3, s3*beta) in g1
           6 * curve.g1_compressed_size;

        let contribution_size = match proving_system {
            ProvingSystem::Groth16 => {
                // G1 Tau powers (compressed)
                g1_chunk_size * curve.g1_compressed_size +
                    // G2 Tau Powers + Alpha Tau powers + Beta Tau powers (compressed)
                    (other_chunk_size * (curve.g2_compressed_size + (curve.g1_compressed_size * 2))) +
                    // Beta in G2
                    curve.g2_compressed_size +
                    // Hash of the previous contribution
                    hash_size +
                    // The public key of the previous contributor
                    public_key_size
            }
            ProvingSystem::Marlin => {
                // G1 Tau powers (compressed)
                g1_chunk_size * curve.g1_compressed_size +
                    if chunk_index == 0 {
                        // Alpha in G1
                        (3 * curve.g1_compressed_size) + (3 * total_size_in_log2 * curve.g1_compressed_size) +
                            // G2 1/Tau Powers
                            (total_size_in_log2 + 2) * curve.g2_compressed_size
                    } else {
                        0
                    } +
                    // Hash of the previous contribution
                    hash_size +
                    // The public key of the previous contributor
                    public_key_size
            }
        };

        // TODO (howardwu): Remove this.
        // 2^{size}
        let powers_length = 1 << total_size_in_log2;
        // 2^{size+1} - 1
        let powers_g1_length = (powers_length << 1) - 1;

        Self {
            contribution_mode,
            chunk_index,
            chunk_size,
            curve,
            proving_system,
            g1_chunk_size,
            other_chunk_size,
            powers_g1_length,
            powers_length,
            total_size_in_log2,
            batch_size,
            accumulator_size,
            public_key_size,
            contribution_size,
            hash_size,
        }
    }

    pub fn into_chunk_parameters(
        &self,
        contribution_mode: ContributionMode,
        chunk_index: usize,
        chunk_size: usize,
    ) -> Self {
        Self::new(
            contribution_mode,
            chunk_index,
            chunk_size,
            self.curve.clone(),
            self.proving_system,
            self.total_size_in_log2,
            self.batch_size,
        )
    }

    /// Returns the length of the serialized accumulator depending on if it's compressed or not
    pub fn get_length(&self, compressed: UseCompression) -> usize {
        match compressed {
            UseCompression::Yes => self.contribution_size - self.public_key_size,
            UseCompression::No => self.accumulator_size,
        }
    }

    fn chunk_sizes(
        contribution_mode: ContributionMode,
        chunk_index: usize,
        chunk_size: usize,
        proving_system: ProvingSystem,
        total_size_in_log2: usize,
    ) -> (usize, usize) {
        // 2^{size}
        let powers_length = 1 << total_size_in_log2;
        // 2^{size+1} - 1
        let powers_g1_length = (powers_length << 1) - 1;

        // Determine the number of elements to process based on the proof system's requirement.
        let upper_bound = match proving_system {
            ProvingSystem::Groth16 => powers_g1_length,
            ProvingSystem::Marlin => powers_length,
        };

        // In chunked contribution mode, select the chunk to iterate over.
        // In full contribution mode, select the entire range up to the upper bound.
        let (start, end) = match contribution_mode {
            ContributionMode::Chunked => (chunk_index * chunk_size, (chunk_index + 1) * chunk_size),
            ContributionMode::Full => (0, upper_bound),
        };

        // Determine the number of G1 elements.
        let g1_chunk_size = match end > upper_bound {
            true => upper_bound - start,
            false => end - start,
        };

        // Determine the number of other elements.
        let other_chunk_size = match proving_system {
            ProvingSystem::Groth16 => {
                if end > powers_length && start >= powers_length {
                    0
                } else if end > powers_length {
                    powers_length - start
                } else {
                    end - start
                }
            }
            ProvingSystem::Marlin => 0,
        };

        (g1_chunk_size, other_chunk_size)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use snarkos_curves::{bls12_377::Bls12_377, bw6_761::BW6_761};

    fn curve_parameters_test<E: PairingEngine>(g1: usize, g2: usize, g1_compressed: usize, g2_compressed: usize) {
        let p = CurveParameters::<E>::new();
        assert_eq!(p.g1_size, g1);
        assert_eq!(p.g2_size, g2);
        assert_eq!(p.g1_compressed_size, g1_compressed);
        assert_eq!(p.g2_compressed_size, g2_compressed);
    }

    #[test]
    fn test_parameter_sizes() {
        curve_parameters_test::<Bls12_377>(96, 192, 48, 96);
        curve_parameters_test::<BW6_761>(192, 192, 96, 96);
    }
}
