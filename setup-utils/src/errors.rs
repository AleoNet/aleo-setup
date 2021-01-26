use crate::ElementType;

use snarkos_errors::{gadgets::SynthesisError, serialization::SerializationError};

use std::io;
use thiserror::Error;

/// Errors that might occur during deserialization.
#[derive(Debug, Error)]
pub enum Error {
    #[error("Disk IO error: {0}")]
    IoError(#[from] io::Error),
    #[error("Serialization error in Zexe: {0}")]
    ZexeSerializationError(#[from] SerializationError),
    #[error("Got point at infinity")]
    PointAtInfinity,
    #[error("Index of {0} must not exceed {1} (got {2}.")]
    PositionError(ElementType, usize, usize),
    #[error("Error during verification: {0}")]
    VerificationError(#[from] VerificationError),
    #[error("Invalid variable length: expected {expected}, got {got}")]
    InvalidLength { expected: usize, got: usize },
    #[error("Chunk does not have a min and max")]
    InvalidChunk,
    #[error("R1CS Error: {0}")]
    SynthesisError(#[from] SynthesisError),
    #[error("Phase 2 Error: {0}")]
    Phase2Error(#[from] Phase2Error),
    #[error("Crossbeam error during while joining the thread")]
    CrossBeamError,
    #[error("Got point not in the prime order subgroup")]
    IncorrectSubgroup,
    #[error("Got invalid decompression parameters")]
    InvalidDecompressionParametersError,
}

impl From<Box<dyn std::any::Any + Send>> for Error {
    fn from(_: Box<dyn std::any::Any + Send>) -> Error {
        Error::CrossBeamError
    }
}

#[derive(Debug, Error, PartialEq)]
pub enum Phase2Error {
    #[error("Parameter should not change: {0}")]
    BrokenInvariant(InvariantKind),
    #[error("Length should not change")]
    InvalidLength,
    #[error("There were no contributions found")]
    NoContributions,
    #[error("The Transcript was not consistent")]
    InvalidTranscript,
}

#[derive(PartialEq, Debug, Clone)]
pub enum InvariantKind {
    Contributions,
    CsHash,
    AlphaG1,
    BetaG1,
    BetaG2,
    GammaAbcG1,
    GammaG2,
    DeltaG1,
    Transcript,
    AlphaG1Query,
    BetaG1Query,
    BetaG2Query,
}

use std::fmt;
impl fmt::Display for InvariantKind {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            InvariantKind::Contributions => write!(f, "Contributions"),
            InvariantKind::CsHash => write!(f, "CsHash"),
            InvariantKind::AlphaG1 => write!(f, "AlphaG1"),
            InvariantKind::BetaG1 => write!(f, "BetaG1"),
            InvariantKind::BetaG2 => write!(f, "BetaG2"),
            InvariantKind::GammaAbcG1 => write!(f, "GammaAbcG1"),
            InvariantKind::GammaG2 => write!(f, "GammaG2"),
            InvariantKind::DeltaG1 => write!(f, "DeltaG1"),
            InvariantKind::Transcript => write!(f, "Transcript"),
            InvariantKind::AlphaG1Query => write!(f, "AlphaG1Query"),
            InvariantKind::BetaG1Query => write!(f, "BetaG1Query"),
            InvariantKind::BetaG2Query => write!(f, "BetaG2Query"),
        }
    }
}

// todo: make this more detailed so that we can know which
// exact pairing ratio check failed
#[derive(Debug, Error)]
pub enum VerificationError {
    #[error("Invalid ratio! Context: {0}")]
    /// The ratio check via the pairing of the provided elements failed
    InvalidRatio(&'static str),
    #[error("Invalid generator for {0} powers")]
    /// The first power of Tau was not the generator of that group
    InvalidGenerator(ElementType),
}
