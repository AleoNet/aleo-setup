use hex::ToHex;
use snarkvm_algorithms::EncryptionScheme;
use snarkvm_dpc::{parameters::testnet2::Testnet2Parameters, Address, Parameters};

use structopt::StructOpt;

#[derive(Debug, StructOpt)]
#[structopt(name = "Encrypt Text")]
struct Options {
    #[structopt(short, long)]
    address: Address<Testnet2Parameters>,
    #[structopt(short, long)]
    plaintext: String,
}

fn main() {
    let options = Options::from_args();

    let scheme = Testnet2Parameters::account_encryption_scheme();
    let pubkey = options.address.to_encryption_key();
    let randomness = scheme
        .generate_randomness(pubkey, &mut rand::thread_rng())
        .expect("Unable to generate randomness");
    let ciphertext = scheme
        .encrypt(pubkey, &randomness, options.plaintext.as_bytes())
        .expect("Unable to encrypt the text");

    println!("{}", ciphertext.encode_hex::<String>());
}
