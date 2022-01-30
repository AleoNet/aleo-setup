use cfg_if::cfg_if;

pub mod helpers;

pub mod keypair;

pub mod parameters;
#[cfg(not(feature = "wasm"))]
mod polynomial;

pub mod chunked_groth16;

cfg_if! {
    if #[cfg(feature = "wasm")] {
        use wasm_bindgen::prelude::*;
        use itertools::Itertools;
        use parameters::MPCParameters;
        use snarkvm_curves::{bls12_377::Bls12_377, bw6_761::BW6_761, PairingEngine};
        use setup_utils::{ get_rng, user_system_randomness };

        macro_rules! log {
            ($($t:tt)*) => (web_sys::console::log_1(&format_args!($($t)*).to_string().into()))
        }

        #[wasm_bindgen]
        pub fn contribute(is_inner: bool, params: Vec<u8>) -> Result<Vec<u8>, JsValue> {
            console_error_panic_hook::set_once();

            log!("Initializing phase2");
            let res = match is_inner {
                true => contribute_challenge(&mut MPCParameters::<Bls12_377>::read(&*params).unwrap()),
                false => contribute_challenge(&mut MPCParameters::<BW6_761>::read(&*params).unwrap()),
            };

            Ok(res)
        }

        fn contribute_challenge<E: PairingEngine>(params: &mut MPCParameters<E>) -> Vec<u8> {
            let mut rng = get_rng(&user_system_randomness());
            log!("Contributing...");
            let hash = params.contribute(&mut rng);
            log!("Contribution hash: 0x{:02x}", hash.unwrap().iter().format(""));

            let mut output: Vec<u8> = vec![];
            params.write(&mut output).expect("failed to write updated parameters");
            log!("Returning parameters");
            return output;
        }
    }
}
