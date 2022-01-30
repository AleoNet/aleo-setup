use blake2::{Blake2s, Digest};
use rand::{CryptoRng, Rng};
use snarkvm_dpc::{testnet2::Testnet2, Address, PrivateKey};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub fn generate_keys() -> Result<JsValue, JsValue> {
    let mut rng = rand::thread_rng();
    let private_key = PrivateKey::new(&mut rng);
    let address = Address::from_private_key(&private_key);
    let (confirmation_key, new_private_key) = generate_confirmation_key(&address, &mut rng);

    Ok(JsValue::from_serde(&(
        address.to_string(),
        private_key.to_string(),
        confirmation_key,
        new_private_key.to_string(),
    ))
    .map_err(|e| JsValue::from_str(&format!("{:?}", e)))?)
}

fn generate_confirmation_key<R: Rng + CryptoRng>(
    address: &Address<Testnet2>,
    rng: &mut R,
) -> (String, PrivateKey<Testnet2>) {
    let new_private_key = PrivateKey::new(rng);
    let concatenated = format!("{}{}", address.to_string(), new_private_key.to_string());
    let mut hasher = Blake2s::new();
    hasher.update(concatenated.as_bytes());
    let bytes = hasher.finalize().to_vec();
    (hex::encode(&bytes), new_private_key)
}
