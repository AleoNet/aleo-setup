/// Utilities to read/write and convert the Powers of Tau from Phase 1
/// to Phase 2-compatible Lagrange Coefficients.
use crate::{buffer_size, CheckForCorrectness, Deserializer, Result, Serializer, UseCompression};

use snarkvm_algorithms::{
    cfg_into_iter,
    cfg_iter,
    fft::{DomainCoeff, EvaluationDomain},
};
use snarkvm_curves::{AffineCurve, PairingEngine, ProjectiveCurve};
use snarkvm_fields::PrimeField;

#[cfg(feature = "parallel")]
use rayon::prelude::*;
use std::{fmt::Debug, io::Write};
use tracing::{debug, info, info_span};

#[derive(Debug)]
pub struct Groth16Params<E: PairingEngine> {
    pub alpha_g1: E::G1Affine,
    pub beta_g1: E::G1Affine,
    pub beta_g2: E::G2Affine,
    pub coeffs_g1: Vec<E::G1Affine>,
    pub coeffs_g2: Vec<E::G2Affine>,
    pub alpha_coeffs_g1: Vec<E::G1Affine>,
    pub beta_coeffs_g1: Vec<E::G1Affine>,
    pub h_g1: Vec<E::G1Affine>,
}

impl<E: PairingEngine> PartialEq for Groth16Params<E> {
    fn eq(&self, other: &Self) -> bool {
        self.alpha_g1 == other.alpha_g1
            && self.beta_g1 == other.beta_g1
            && self.beta_g2 == other.beta_g2
            && self.coeffs_g1 == other.coeffs_g1
            && self.coeffs_g2 == other.coeffs_g2
            && self.alpha_coeffs_g1 == other.alpha_coeffs_g1
            && self.beta_coeffs_g1 == other.beta_coeffs_g1
            && self.h_g1 == other.h_g1
    }
}

/// Performs an IFFT over the provided evaluation domain to the provided
/// vector of affine points. It then normalizes and returns them back into
/// affine form
fn to_coeffs<F, C>(domain: &EvaluationDomain<F>, coeffs: &[C]) -> Vec<C>
where
    F: PrimeField,
    C: AffineCurve,
    C::Projective: std::ops::MulAssign<F>,
    <C as AffineCurve>::Projective: DomainCoeff<F>,
{
    let mut coeffs = domain.ifft(&coeffs.iter().map(|e| e.into_projective()).collect::<Vec<_>>());
    C::Projective::batch_normalization(&mut coeffs);
    cfg_iter!(coeffs).map(|p| p.into_affine()).collect()
}

/// H query used in Groth16
/// x^i * (x^m - 1) for i in 0..=(m-2) a.k.a.
/// x^(i + m) - x^i for i in 0..=(m-2)
/// for radix2 evaluation domains
fn h_query_groth16<C: AffineCurve>(powers: &[C], degree: usize) -> Vec<C> {
    cfg_into_iter!(0..degree - 1)
        .map(|i| powers[i + degree] + powers[i].neg())
        .collect()
}

impl<E: PairingEngine> Groth16Params<E> {
    /// Loads the Powers of Tau and transforms them to coefficient form
    /// in preparation of Phase 2
    ///
    /// # Panics
    ///
    /// If `phase2_size` > length of any of the provided vectors
    pub fn new(
        phase2_size: usize,
        tau_powers_g1: Vec<E::G1Affine>,
        tau_powers_g2: Vec<E::G2Affine>,
        alpha_tau_powers_g1: Vec<E::G1Affine>,
        beta_tau_powers_g1: Vec<E::G1Affine>,
        beta_g2: E::G2Affine,
    ) -> Result<Self> {
        let span = info_span!("Groth16Utils_new");
        let _enter = span.enter();

        // Create the evaluation domain
        let domain = EvaluationDomain::<E::Fr>::new(phase2_size).expect("could not create domain");

        info!("converting powers of tau to lagrange coefficients");

        Ok(crossbeam::scope(|s| -> Result<_> {
            // Convert the accumulated powers to Lagrange coefficients
            let coeffs_g1 = s.spawn(|_| to_coeffs(&domain, &tau_powers_g1[0..phase2_size]));
            let coeffs_g2 = s.spawn(|_| to_coeffs(&domain, &tau_powers_g2[0..phase2_size]));
            let alpha_coeffs_g1 = s.spawn(|_| to_coeffs(&domain, &alpha_tau_powers_g1[0..phase2_size]));
            let beta_coeffs_g1 = s.spawn(|_| to_coeffs(&domain, &beta_tau_powers_g1[0..phase2_size]));
            // Calculate the query for the Groth16 proving system
            let h_g1 = s.spawn(|_| h_query_groth16(&tau_powers_g1, phase2_size));

            let coeffs_g1 = coeffs_g1.join()?;
            debug!("tau g1 coefficients calculated");
            let coeffs_g2 = coeffs_g2.join()?;
            debug!("tau g2 coefficients calculated");
            let alpha_coeffs_g1 = alpha_coeffs_g1.join()?;
            debug!("alpha tau g1 coefficients calculated");
            let beta_coeffs_g1 = beta_coeffs_g1.join()?;
            debug!("beta tau g1 coefficients calculated");
            let h_g1 = h_g1.join()?;
            debug!("h query coefficients calculated");

            info!("successfully created groth16 parameters from powers of tau");

            Ok(Groth16Params {
                alpha_g1: alpha_tau_powers_g1[0],
                beta_g1: beta_tau_powers_g1[0],
                beta_g2,
                coeffs_g1,
                coeffs_g2,
                alpha_coeffs_g1,
                beta_coeffs_g1,
                h_g1,
            })
        })??)
    }

    /// Writes the data structure to the provided writer, in compressed or uncompressed form.
    pub fn write<W: Write>(&self, writer: &mut W, compression: UseCompression) -> Result<()> {
        // Write alpha (in g1)
        // Needed by verifier for e(alpha, beta)
        // Needed by prover for A and C elements of proof
        writer.write_element(&self.alpha_g1, compression)?;

        // Write beta (in g1)
        // Needed by prover for C element of proof
        writer.write_element(&self.beta_g1, compression)?;

        // Write beta (in g2)
        // Needed by verifier for e(alpha, beta)
        // Needed by prover for B element of proof
        writer.write_element(&self.beta_g2, compression)?;

        // Lagrange coefficients in G1 (for constructing
        // LC/IC queries and precomputing polynomials for A)
        writer.write_elements_exact(&self.coeffs_g1, compression)?;

        // Lagrange coefficients in G2 (for precomputing
        // polynomials for B)
        writer.write_elements_exact(&self.coeffs_g2, compression)?;

        // Lagrange coefficients in G1 with alpha (for
        // LC/IC queries)
        writer.write_elements_exact(&self.alpha_coeffs_g1, compression)?;

        // Lagrange coefficients in G1 with beta (for
        // LC/IC queries)
        writer.write_elements_exact(&self.beta_coeffs_g1, compression)?;

        // Bases for H polynomial computation
        writer.write_elements_exact(&self.h_g1, compression)?;

        Ok(())
    }

    /// Reads the first `num_constraints` coefficients from the provided processed
    /// Phase 1 transcript with size `phase1_size`.
    pub fn read(
        reader: &mut [u8],
        compressed: UseCompression,
        check_input_for_correctness: CheckForCorrectness,
        phase1_size: usize,
        num_constraints: usize,
    ) -> Result<Groth16Params<E>> {
        let span = info_span!("Groth16Utils_read");
        let _enter = span.enter();

        let mut reader = std::io::Cursor::new(reader);
        let alpha_g1 = reader.read_element(compressed, check_input_for_correctness)?;
        debug!("Read alpha_g1");
        let beta_g1 = reader.read_element(compressed, check_input_for_correctness)?;
        debug!("Read beta_g1");
        let beta_g2 = reader.read_element(compressed, check_input_for_correctness)?;
        debug!("Read beta_g2");

        let position = reader.position() as usize;
        let reader = &reader.get_mut()[position..];
        debug!("Truncated reader");

        // Split the transcript in the appropriate sections
        let (in_coeffs_g1, in_coeffs_g2, in_alpha_coeffs_g1, in_beta_coeffs_g1, in_h_g1) =
            split_transcript::<E>(reader, phase1_size, num_constraints, compressed);
        debug!("Split transcript");

        info!("reading groth16 parameters...");
        // Read all elements in parallel
        // note: '??' is used for getting the result from the threaded operation,
        // and then getting the result from the function inside the thread)
        Ok(crossbeam::scope(|s| -> Result<_> {
            let coeffs_g1 =
                s.spawn(|_| in_coeffs_g1.read_batch::<E::G1Affine>(compressed, check_input_for_correctness));
            let coeffs_g2 =
                s.spawn(|_| in_coeffs_g2.read_batch::<E::G2Affine>(compressed, check_input_for_correctness));
            let alpha_coeffs_g1 =
                s.spawn(|_| in_alpha_coeffs_g1.read_batch::<E::G1Affine>(compressed, check_input_for_correctness));
            let beta_coeffs_g1 =
                s.spawn(|_| in_beta_coeffs_g1.read_batch::<E::G1Affine>(compressed, check_input_for_correctness));
            let h_g1 = s.spawn(|_| in_h_g1.read_batch::<E::G1Affine>(compressed, check_input_for_correctness));

            let coeffs_g1 = coeffs_g1.join()??;
            debug!("read tau g1 Coefficients");
            let coeffs_g2 = coeffs_g2.join()??;
            debug!("read tau g2 coefficients");
            let alpha_coeffs_g1 = alpha_coeffs_g1.join()??;
            debug!("read alpha g1 coefficients");
            let beta_coeffs_g1 = beta_coeffs_g1.join()??;
            debug!("read beta g1 coefficients");
            let h_g1 = h_g1.join()??;
            debug!("read h query coefficients");

            info!("successfully read groth16 parameters");

            Ok(Groth16Params {
                alpha_g1,
                beta_g1,
                beta_g2,
                coeffs_g1,
                coeffs_g2,
                alpha_coeffs_g1,
                beta_coeffs_g1,
                h_g1,
            })
        })??)
    }
}

/// Immutable slices with format [AlphaG1, BetaG1, BetaG2, CoeffsG1, CoeffsG2, AlphaCoeffsG1, BetaCoeffsG1, H_G1]
type SplitBuf<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8], &'a [u8]);

use crate::BatchDeserializer;

/// splits the transcript from phase 1 after it's been prepared and converted to coefficient form
fn split_transcript<E: PairingEngine>(
    input: &[u8],
    phase1_size: usize,
    size: usize,
    compressed: UseCompression,
) -> SplitBuf {
    let g1_size = buffer_size::<E::G1Affine>(compressed);
    let g2_size = buffer_size::<E::G2Affine>(compressed);

    // N elements per coefficient
    let (coeffs_g1, others) = input.split_at(g1_size * size);
    let (_, others) = others.split_at((phase1_size - size) * g1_size);
    debug!("Split coeffs_g1");

    let (coeffs_g2, others) = others.split_at(g2_size * size);
    let (_, others) = others.split_at((phase1_size - size) * g2_size);
    debug!("Split coeffs_g2");

    let (alpha_coeffs_g1, others) = others.split_at(g1_size * size);
    let (_, others) = others.split_at((phase1_size - size) * g1_size);
    debug!("Split alpha_coeffs_g1");

    let (beta_coeffs_g1, others) = others.split_at(g1_size * size);
    let (_, others) = others.split_at((phase1_size - size) * g1_size);
    debug!("Split beta_coeffs_g1");

    // N-1 for the h coeffs
    let (h_coeffs, _) = others.split_at(g1_size * (size - 1));
    debug!("Split h_coeffs");

    (coeffs_g1, coeffs_g2, alpha_coeffs_g1, beta_coeffs_g1, h_coeffs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::UseCompression;
    use phase1::{
        helpers::testing::{
            setup_verify,
            CheckForCorrectness as CheckForCorrectnessPhase1,
            UseCompression as UseCompressionPhase1,
        },
        Phase1,
        Phase1Parameters,
        ProvingSystem,
    };

    use snarkvm_curves::bls12_377::Bls12_377;

    fn read_write_curve<E: PairingEngine>(powers: usize, prepared_phase1_size: usize, compressed: UseCompression) {
        fn compat(compression: UseCompression) -> UseCompressionPhase1 {
            match compression {
                UseCompression::Yes => UseCompressionPhase1::Yes,
                UseCompression::No => UseCompressionPhase1::No,
            }
        }

        fn compat_correctness(check_correctness: CheckForCorrectness) -> CheckForCorrectnessPhase1 {
            match check_correctness {
                CheckForCorrectness::Full => CheckForCorrectnessPhase1::Full,
                CheckForCorrectness::OnlyNonZero => CheckForCorrectnessPhase1::OnlyNonZero,
                CheckForCorrectness::OnlyInGroup => CheckForCorrectnessPhase1::OnlyInGroup,
                CheckForCorrectness::No => CheckForCorrectnessPhase1::No,
            }
        }

        let batch = ((1 << powers) << 1) - 1;
        let params = Phase1Parameters::<E>::new_full(ProvingSystem::Groth16, powers, batch);
        let (_, output, _, _) = setup_verify(
            compat(compressed),
            compat_correctness(CheckForCorrectness::Full),
            compat(compressed),
            &params,
        );
        let accumulator = Phase1::deserialize(
            &output,
            compat(compressed),
            compat_correctness(CheckForCorrectness::Full),
            &params,
        )
        .unwrap();

        let groth_params = Groth16Params::<E>::new(
            prepared_phase1_size,
            accumulator.tau_powers_g1,
            accumulator.tau_powers_g2,
            accumulator.alpha_tau_powers_g1,
            accumulator.beta_tau_powers_g1,
            accumulator.beta_g2,
        )
        .unwrap();

        let mut writer = vec![];
        groth_params.write(&mut writer, compressed).unwrap();
        let mut reader = std::io::Cursor::new(writer);
        let deserialized = Groth16Params::<E>::read(
            &mut reader.get_mut(),
            compressed,
            CheckForCorrectness::Full,
            prepared_phase1_size,
            prepared_phase1_size, // phase2_size == prepared phase1 size
        )
        .unwrap();
        reader.set_position(0);
        assert_eq!(deserialized, groth_params);

        let subset = prepared_phase1_size / 2;
        let deserialized_subset = Groth16Params::<E>::read(
            &mut reader.get_mut(),
            compressed,
            CheckForCorrectness::Full,
            prepared_phase1_size,
            subset, // phase2 size is smaller than the prepared phase1 size
        )
        .unwrap();
        assert_eq!(&deserialized_subset.coeffs_g1[..], &groth_params.coeffs_g1[..subset]);
        assert_eq!(&deserialized_subset.coeffs_g2[..], &groth_params.coeffs_g2[..subset]);
        assert_eq!(
            &deserialized_subset.alpha_coeffs_g1[..],
            &groth_params.alpha_coeffs_g1[..subset]
        );
        assert_eq!(
            &deserialized_subset.beta_coeffs_g1[..],
            &groth_params.beta_coeffs_g1[..subset]
        );
        assert_eq!(&deserialized_subset.h_g1[..], &groth_params.h_g1[..subset - 1]);
        // h_query is 1 less element
    }

    #[test]
    fn first_half_powers() {
        let power = 4 as usize;
        let prepared_phase1_size = 2u32.pow(power as u32) as usize / 2;
        read_write_curve::<Bls12_377>(power, prepared_phase1_size, UseCompression::Yes);
        read_write_curve::<Bls12_377>(power, prepared_phase1_size, UseCompression::No);
    }

    #[test]
    fn phase2_equal_to_powers() {
        let power = 3 as usize;
        let prepared_phase1_size = 2u32.pow(power as u32) as usize;
        read_write_curve::<Bls12_377>(power, prepared_phase1_size, UseCompression::Yes);
        read_write_curve::<Bls12_377>(power, prepared_phase1_size, UseCompression::No);
    }

    #[test]
    #[should_panic]
    fn large_phase2_fails() {
        read_write_curve::<Bls12_377>(3, 9, UseCompression::Yes);
    }

    #[test]
    #[should_panic]
    fn large_phase2_uncompressed_fails() {
        read_write_curve::<Bls12_377>(3, 9, UseCompression::No);
    }
}
