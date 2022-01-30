use phase1::{ContributionMode, Phase1Parameters};
use phase1_coordinator::{
    environment::{Development, Environment, Parameters, Production},
    objects::{ContributionFileSignature, ContributionState},
};
use setup1_shared::structures::SetupKind;
use snarkvm_curves::PairingEngine;
use snarkvm_dpc::{testnet2::Testnet2, Address, PrivateKey};
use snarkvm_utilities::ToBytes;

use anyhow::Result;
#[cfg(test)]
use fs_err::{create_dir_all, write};
use rand::{CryptoRng, Rng};
use std::{
    convert::TryFrom,
    fs::{remove_file, File},
    io::Read,
    path::Path,
    str::FromStr,
};
#[cfg(test)]
use tracing::error;

pub fn remove_file_if_exists(file_path: &str) -> Result<()> {
    if Path::new(file_path).exists() {
        remove_file(file_path)?;
    }
    Ok(())
}

pub fn read_from_file(file_name: &str) -> Result<Vec<u8>> {
    let mut file = vec![];
    File::open(file_name)?.read_to_end(&mut file)?;
    Ok(file)
}

///
/// This function creates the `file_path`'s parent directories if it
/// does not already exists.
///
#[cfg(test)]
pub fn create_parent_directory(file_path: &str) {
    let file_path = Path::new(&file_path);
    if let Some(file_path_parent) = file_path.parent() {
        if let Err(err) = create_dir_all(file_path_parent) {
            error!(
                "Error initializing file path parent directory {:?} {}",
                &file_path_parent, err
            );
        }
    }
}

///
/// This function writes a `file_bytes` to the `file_path`.
///
/// If a parent directory doesn't already exists, this function will
/// automatically generate one.
///
#[cfg(test)]
pub fn write_to_file(file_path: &str, file_bytes: Vec<u8>) -> Result<()> {
    create_parent_directory(file_path);
    remove_file_if_exists(file_path)?;

    if let Err(err) = write(file_path, file_bytes) {
        error!("Error writing file to {} {}", &file_path, err);
    }

    Ok(())
}

pub fn create_parameters_for_chunk<E: PairingEngine>(
    environment: &Environment,
    chunk_id: usize,
) -> Result<Phase1Parameters<E>> {
    let settings = environment.parameters();

    let parameters = Phase1Parameters::<E>::new_chunk(
        ContributionMode::Chunked,
        chunk_id,
        settings.chunk_size(),
        settings.proving_system(),
        settings.power(),
        settings.batch_size(),
    );
    Ok(parameters)
}

pub fn get_authorization_value<R: Rng + CryptoRng>(
    private_key: &PrivateKey<Testnet2>,
    method: &str,
    path: &str,
    rng: &mut R,
) -> Result<String> {
    let address = Address::try_from(private_key)?.to_string();

    let message = format!("{} {}", method.to_lowercase(), path.to_lowercase());
    let signature = hex::encode(&private_key.sign(message.as_bytes(), rng)?.to_bytes_le()?);

    let authorization = format!("Aleo {}:{}", address, signature);
    Ok(authorization)
}

///
/// Signs and returns the contribution file signature.
///
pub fn sign_contribution_state<R: Rng + CryptoRng>(
    signing_key: &str,
    challenge_hash: &[u8; 64],
    response_hash: &[u8; 64],
    next_challenge_hash: Option<&[u8; 64]>,
    rng: &mut R,
) -> Result<ContributionFileSignature> {
    let contribution_state = ContributionState::new(challenge_hash, response_hash, next_challenge_hash);
    let message = contribution_state.signature_message()?;

    let private_key = PrivateKey::<Testnet2>::from_str(signing_key)?;
    let signature = hex::encode(&private_key.sign(message.as_bytes(), rng)?.to_bytes_le()?);

    let contribution_file_signature = ContributionFileSignature::new(signature, contribution_state)?;

    Ok(contribution_file_signature)
}

#[inline]
fn development_environment() -> Environment {
    let environment = Development::from(Parameters::TestCustom {
        number_of_chunks: 64,
        power: 16,
        batch_size: 512,
    });
    environment.into()
}

#[inline]
fn inner_environment() -> Environment {
    Production::from(Parameters::AleoInner).into()
}

#[inline]
fn outer_environment() -> Environment {
    Production::from(Parameters::AleoOuter).into()
}

#[inline]
fn universal_environment() -> Environment {
    Production::from(Parameters::AleoUniversal).into()
}

/// Returns the [Environment] settings based on a setup kind
pub fn environment_by_setup_kind(kind: &SetupKind) -> Environment {
    match kind {
        SetupKind::Development => development_environment(),
        SetupKind::Inner => inner_environment(),
        SetupKind::Outer => outer_environment(),
        SetupKind::Universal => universal_environment(),
    }
}
