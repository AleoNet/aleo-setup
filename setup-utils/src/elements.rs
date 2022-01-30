#[cfg(feature = "parallel")]
use rayon::prelude::*;
use snarkvm_curves::AffineCurve;
use snarkvm_fields::{FieldParameters, PrimeField, Zero};
use snarkvm_utilities::{BitIteratorBE, CanonicalDeserialize, Read};
use std::fmt;

use crate::BatchDeserializer;

/// Determines if point compression should be used.
#[derive(Debug, Copy, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum UseCompression {
    Yes,
    No,
}

impl fmt::Display for UseCompression {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            UseCompression::Yes => write!(f, "Yes"),
            UseCompression::No => write!(f, "No"),
        }
    }
}

/// Determines if points should be checked to be infinity.
#[derive(Debug, Copy, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub enum CheckForCorrectness {
    Full,
    OnlyNonZero,
    OnlyInGroup,
    No,
}

impl fmt::Display for CheckForCorrectness {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CheckForCorrectness::Full => write!(f, "Full"),
            CheckForCorrectness::OnlyNonZero => write!(f, "OnlyNonZero"),
            CheckForCorrectness::OnlyInGroup => write!(f, "OnlyInGroup"),
            CheckForCorrectness::No => write!(f, "No"),
        }
    }
}

// todo: remove this, we can always get the size of the element
// from the `buffer_size` method
#[derive(Copy, Clone, Debug, PartialEq)]
pub enum ElementType {
    TauG1,
    TauG2,
    AlphaG1,
    BetaG1,
    BetaG2,
}

impl fmt::Display for ElementType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            ElementType::TauG1 => write!(f, "TauG1"),
            ElementType::TauG2 => write!(f, "TauG2"),
            ElementType::AlphaG1 => write!(f, "AlphaG1"),
            ElementType::BetaG1 => write!(f, "BetaG1"),
            ElementType::BetaG2 => write!(f, "BetaG2"),
        }
    }
}

pub fn read_vec<G: AffineCurve, R: Read>(
    mut reader: R,
    compressed: UseCompression,
    check_for_correctness: CheckForCorrectness,
) -> Result<Vec<G>, crate::Error> {
    let size = match compressed {
        UseCompression::Yes => G::SERIALIZED_SIZE,
        UseCompression::No => G::UNCOMPRESSED_SIZE,
    };
    let length = u64::deserialize(&mut reader)? as usize;
    let mut bytes = vec![0u8; length * size];
    reader.read_exact(&mut bytes)?;
    bytes.read_batch(compressed, check_for_correctness)
}

pub fn check_subgroup<C: AffineCurve>(elements: &[C]) -> core::result::Result<(), crate::Error> {
    let modulus = <C::ScalarField as PrimeField>::Parameters::MODULUS;
    match snarkvm_algorithms::cfg_iter!(elements).all(|p| p.mul_bits(BitIteratorBE::new(modulus)).is_zero()) {
        true => Ok(()),
        false => Err(crate::Error::IncorrectSubgroup),
    }
}
