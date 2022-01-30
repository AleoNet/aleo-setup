use snarkvm_dpc::{testnet2::Testnet2, PrivateKey};

fn main() {
    let mut rng = rand::thread_rng();
    let private_key = PrivateKey::<Testnet2>::new(&mut rng);
    print!("Private key: {}", private_key);
}
