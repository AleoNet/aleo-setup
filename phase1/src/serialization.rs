use super::*;

impl<'a, E: PairingEngine + Sync> Phase1<'a, E> {
    pub fn serialize(
        &self,
        output: &mut [u8],
        compression: UseCompression,
        parameters: &'a Phase1Parameters<E>,
    ) -> Result<()> {
        let elements = (
            self.tau_powers_g1.as_ref(),
            self.tau_powers_g2.as_ref(),
            self.alpha_tau_powers_g1.as_ref(),
            self.beta_tau_powers_g1.as_ref(),
            &self.beta_g2,
        );

        accumulator::serialize(elements, output, compression, parameters)?;

        Ok(())
    }

    pub fn deserialize(
        input: &[u8],
        compression: UseCompression,
        check_input_for_correctness: CheckForCorrectness,
        parameters: &'a Phase1Parameters<E>,
    ) -> Result<Phase1<'a, E>> {
        let (tau_powers_g1, tau_powers_g2, alpha_tau_powers_g1, beta_tau_powers_g1, beta_g2) =
            accumulator::deserialize(input, compression, check_input_for_correctness, parameters)?;
        Ok(Phase1 {
            tau_powers_g1,
            tau_powers_g2,
            alpha_tau_powers_g1,
            beta_tau_powers_g1,
            beta_g2,
            hash: blank_hash(),
            parameters,
        })
    }

    #[cfg(not(feature = "wasm"))]
    pub fn decompress(
        input: &[u8],
        output: &mut [u8],
        check_input_for_correctness: CheckForCorrectness,
        parameters: &'a Phase1Parameters<E>,
    ) -> Result<()> {
        accumulator::decompress(input, output, check_input_for_correctness, parameters)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helpers::testing::{generate_output, generate_random_accumulator};

    use snarkos_curves::{bls12_377::Bls12_377, bw6_761::BW6_761};

    fn serialize_curve_test<E: PairingEngine + Sync>(compress: UseCompression, size: usize, batch: usize) {
        for proving_system in &[ProvingSystem::Groth16, ProvingSystem::Marlin] {
            // Create a small accumulator with some random state.
            let parameters = Phase1Parameters::<E>::new_full(*proving_system, size, batch);
            let (buffer, accumulator) = generate_random_accumulator(&parameters, compress);
            let deserialized = Phase1::deserialize(&buffer, compress, CheckForCorrectness::No, &parameters).unwrap();
            assert_eq!(deserialized, accumulator);
        }
    }

    fn decompress_curve_test<E: PairingEngine>() {
        for proving_system in &[ProvingSystem::Groth16, ProvingSystem::Marlin] {
            let parameters = Phase1Parameters::<E>::new_full(*proving_system, 2, 2);
            // generate a random input compressed accumulator
            let (input, before) = generate_random_accumulator(&parameters, UseCompression::Yes);
            let mut output = generate_output(&parameters, UseCompression::No);

            // decompress the input to the output
            Phase1::decompress(&input, &mut output, CheckForCorrectness::No, &parameters).unwrap();

            // deserializes the decompressed output
            let deserialized =
                Phase1::deserialize(&output, UseCompression::No, CheckForCorrectness::No, &parameters).unwrap();
            assert_eq!(deserialized, before);

            // trying to deserialize it as compressed should obviously fail
            Phase1::deserialize(&output, UseCompression::Yes, CheckForCorrectness::No, &parameters).unwrap_err();
        }
    }

    #[test]
    fn test_serialization_bls12_377() {
        serialize_curve_test::<Bls12_377>(UseCompression::Yes, 2, 2);
        serialize_curve_test::<Bls12_377>(UseCompression::No, 2, 2);
    }

    #[test]
    fn test_serialization_bw6_761() {
        serialize_curve_test::<BW6_761>(UseCompression::Yes, 2, 2);
        serialize_curve_test::<BW6_761>(UseCompression::No, 2, 2);
    }

    #[test]
    fn test_decompress_bls12_377() {
        decompress_curve_test::<Bls12_377>();
    }

    #[test]
    fn test_decompress_bw6_761() {
        decompress_curve_test::<BW6_761>();
    }

    #[test]
    fn test_serialization_multiple_batches_bls12_377() {
        // This test ensures that we can serialize for batches which are smaller, equal
        // or _bigger_ than any of the G1/G2 vector sizes.
        for batch in 1..10 {
            serialize_curve_test::<Bls12_377>(UseCompression::Yes, 2, batch);
        }
    }

    #[test]
    fn test_serialization_multiple_batches_bw6_761() {
        // This test ensures that we can serialize for batches which are smaller, equal
        // or _bigger_ than any of the G1/G2 vector sizes.
        for batch in 1..10 {
            serialize_curve_test::<Bls12_377>(UseCompression::Yes, 2, batch);
        }
    }
}
