use snarkos_models::curves::PairingEngine;

/// Contains the secrets τ, α and β that the participant of the ceremony must destroy.
#[derive(PartialEq, Debug)]
pub struct PrivateKey<E: PairingEngine> {
    pub tau: E::Fr,
    pub alpha: E::Fr,
    pub beta: E::Fr,
}
