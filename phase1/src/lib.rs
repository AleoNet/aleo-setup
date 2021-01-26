pub mod helpers;

pub mod objects;
pub use objects::*;

#[cfg(not(feature = "wasm"))]
mod aggregation;
mod computation;
mod initialization;
mod key_generation;
mod serialization;
#[cfg(not(feature = "wasm"))]
mod verification;

use crate::helpers::{
    accumulator::{self},
    buffers::*,
};
use setup_utils::*;

#[cfg(not(feature = "wasm"))]
use crate::helpers::accumulator::*;

#[cfg(not(feature = "wasm"))]
use snarkos_models::curves::Zero;

use snarkos_models::curves::{AffineCurve, PairingEngine, ProjectiveCurve};
use snarkos_utilities::UniformRand;

use rand::Rng;
use tracing::{debug, info, info_span, trace};

/// `Phase1` is an object that participants of the ceremony contribute
/// randomness to. This object contains powers of trapdoor `tau` in G1 and in G2 over
/// fixed generators, and additionally in G1 over two other generators of exponents
/// `alpha` and `beta` over those fixed generators. In other words:
///
/// * (τ, τ<sup>2</sup>, ..., τ<sup>2<sup>22</sup> - 2</sup>, α, ατ, ατ<sup>2</sup>, ..., ατ<sup>2<sup>21</sup> - 1</sup>, β, βτ, βτ<sup>2</sup>, ..., βτ<sup>2<sup>21</sup> - 1</sup>)<sub>1</sub>
/// * (β, τ, τ<sup>2</sup>, ..., τ<sup>2<sup>21</sup> - 1</sup>)<sub>2</sub>
#[derive(Debug)]
pub struct Phase1<'a, E: PairingEngine> {
    /// Groth16: tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_G1_LENGTH - 1}
    /// Marlin: tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_LENGTH - 1}
    pub tau_powers_g1: Vec<E::G1Affine>,
    /// Groth16: tau^0, tau^1, tau^2, ..., tau^{TAU_POWERS_LENGTH - 1}
    /// Marlin: tau^0, tau^1 and then 1/tau^{TAU_POWERS_LENGTH - 2^i + 1}, for i = 0,...,log2(TAU_POWERS_LENGTH)
    pub tau_powers_g2: Vec<E::G2Affine>,
    /// Groth16: alpha * tau^0, alpha * tau^1, alpha * tau^2, ..., alpha * tau^{TAU_POWERS_LENGTH - 1}
    /// Marlin: alpha * tau^0, alpha * tau^1, alpha * tau^2 and then triples of
    /// alpha * tau^{TAU_POWERS_LENGTH - 2^i + 1}, alpha * tau^{TAU_POWERS_LENGTH - 2^i + 2}, alpha * tau^{TAU_POWERS_LENGTH - 2^i + 3}
    /// for i = 0,...,log2(TAU_POWERS_LENGTH)
    pub alpha_tau_powers_g1: Vec<E::G1Affine>,
    /// Groth16: beta * tau^0, beta * tau^1, beta * tau^2, ..., beta * tau^{TAU_POWERS_LENGTH - 1}
    /// Marlin: empty
    pub beta_tau_powers_g1: Vec<E::G1Affine>,
    /// Groth16: beta
    /// Marlin: empty
    pub beta_g2: E::G2Affine,
    /// Hash chain hash
    pub hash: GenericArray<u8, U64>,
    /// The parameters used for the setup of this accumulator
    pub parameters: &'a Phase1Parameters<E>,
}

impl<'a, E: PairingEngine> PartialEq for Phase1<'a, E> {
    fn eq(&self, other: &Self) -> bool {
        self.tau_powers_g1 == other.tau_powers_g1
            && self.tau_powers_g2 == other.tau_powers_g2
            && self.alpha_tau_powers_g1 == other.alpha_tau_powers_g1
            && self.beta_tau_powers_g1 == other.beta_tau_powers_g1
            && self.beta_g2 == other.beta_g2
            && self.hash == other.hash
    }
}
