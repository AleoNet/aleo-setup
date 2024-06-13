use crate::structures::*;
use blake2::{Blake2b, Digest};
use rand::{CryptoRng, Rng};
use snarkvm_dpc::{parameters::testnet2::Testnet2Parameters, Address, PrivateKey, ViewKey};
use snarkvm_utilities::ToBytes;
use std::convert::TryFrom;
use wasm_bindgen::prelude::*;

/// Map an error that implements [std::fmt::Display] to a [JsValue].
pub(crate) fn map_js_err(e: impl std::fmt::Display) -> JsValue {
    // Use alternate selector # to activate anyhow::Error inclusion of causes.
    // See https://docs.rs/anyhow/1.0.81/anyhow/struct.Error.html#display-representations
    JsValue::from_str(&format!("{:#}", e))
}

/// Map an error that implements [std::fmt::Debug] to a [JsValue].
pub(crate) fn map_js_err_dbg(e: impl std::fmt::Debug) -> JsValue {
    JsValue::from_str(&format!("{:?}", e))
}

/// Construct the authentication string for requests made to the coordinator.
pub fn get_authorization_value<R: Rng + CryptoRng>(
    private_key: &PrivateKey<Testnet2Parameters>,
    method: &str,
    path: &str,
    rng: &mut R,
) -> anyhow::Result<String> {
    let view_key = ViewKey::try_from(private_key)?;
    let address = Address::try_from(private_key)?.to_string();

    let message = format!("{} {}", method.to_lowercase(), path.to_lowercase());
    let signature = hex::encode(&view_key.sign(message.as_bytes(), rng)?.to_bytes_le()?);

    let authorization = format!("Aleo {}:{}", address, signature);
    Ok(authorization)
}

pub fn sign_contribution_state<R: Rng + CryptoRng>(
    signing_key: &PrivateKey<Testnet2Parameters>,
    challenge_hash: &[u8],
    response_hash: &[u8],
    next_challenge_hash: Option<Vec<u8>>,
    rng: &mut R,
) -> anyhow::Result<ContributionFileSignature> {
    let contribution_state =
        ContributionState::new(challenge_hash.to_vec(), response_hash.to_vec(), next_challenge_hash)?;
    let message = contribution_state.signature_message()?;

    let view_key = ViewKey::try_from(signing_key)?;
    let signature = hex::encode(&view_key.sign(message.as_bytes(), rng)?.to_bytes_le()?);

    let contribution_file_signature = ContributionFileSignature::new(signature, contribution_state)?;

    Ok(contribution_file_signature)
}

pub fn calculate_hash(input_map: &[u8]) -> Vec<u8> {
    let chunk_size = 1 << 30; // read by 1GB from map
    let mut hasher = Blake2b::default();
    for chunk in input_map.chunks(chunk_size) {
        hasher.update(&chunk);
    }
    hasher.finalize().to_vec()
}
