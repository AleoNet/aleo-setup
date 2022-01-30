use snarkvm_dpc::{testnet2::Testnet2, Address, PrivateKey};

use age::Decryptor;
use anyhow::{anyhow, Result};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use serde::Deserialize;
use std::{fs, io::Read, str::FromStr};
use structopt::StructOpt;
use unic_langid::LanguageIdentifier;

#[derive(Debug, StructOpt)]
#[structopt(name = "Public key extractor")]
struct Options {
    #[structopt(long)]
    path: String,
}

// Should be the same as the one from setup1-contributor/src/objects.rs
// Copied here to reduce the compile time, which is
// about 50% longer with setup1-contributor included
#[derive(Deserialize, Debug, Clone)]
#[serde(rename_all = "camelCase")]
pub struct AleoSetupKeys {
    pub encrypted_seed: String,
    pub encrypted_private_key: String,
}

fn decrypt(passphrase: &SecretString, encrypted: &str) -> Result<SecretVec<u8>> {
    let decoded = SecretVec::new(hex::decode(encrypted)?);
    let decryptor = Decryptor::new(decoded.expose_secret().as_slice())?;
    match decryptor {
        Decryptor::Passphrase(decryptor) => {
            let mut output = vec![];
            let mut reader = decryptor.decrypt(passphrase, None)?;
            reader.read_to_end(&mut output)?;
            Ok(SecretVec::new(output))
        }
        Decryptor::Recipients(_) => Err(anyhow!("Wrong age Decryptor, should be Passphrase, but got Recipients")),
    }
}

fn read_private_key(keys_path: &str) -> Result<PrivateKey<Testnet2>> {
    let file_contents = fs::read(&keys_path)?;
    let keys: AleoSetupKeys = serde_json::from_slice(&file_contents)?;
    let passphrase = age::cli_common::read_secret("Enter your Aleo setup passphrase", "Passphrase", None)
        .map_err(|e| anyhow!("Error reading passphrase: {}", e))?;
    let decrypted = decrypt(&passphrase, &keys.encrypted_private_key)?;
    PrivateKey::from_str(std::str::from_utf8(decrypted.expose_secret())?).map_err(Into::into)
}

fn main() {
    let options = Options::from_args();

    let default_language: LanguageIdentifier = "en-US".parse().expect("Should parse a language indentifier");
    age::localizer()
        .select(&[default_language])
        .expect("Should select the default language");

    let private_key = read_private_key(&options.path).expect("Should read a private key");

    let address = Address::from_private_key(&private_key).to_string();
    println!("{}", address);
}
