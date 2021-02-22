use snarkos_toolkit::account::{PrivateKey, ViewKey};

fn main() {
    let mut rng = rand::thread_rng();
    let private_key = PrivateKey::new(&mut rng).unwrap();
    let view_key = ViewKey::from(&private_key).unwrap();
    println!("{}", view_key);
}
