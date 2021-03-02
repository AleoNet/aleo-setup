use anyhow::Result;
use clap::{App, Arg};
use secrecy::{ExposeSecret, SecretString, SecretVec};
use setup1_contributor::{errors::ContributeError, objects::AleoSetupKeys};
use snarkos_toolkit::account::{Address, PrivateKey};
use std::{fs::File, io::Read, str::FromStr};
use unic_langid::LanguageIdentifier;

fn decrypt(passphrase: &SecretString, encrypted: &str) -> Result<Vec<u8>> {
    let decoded = SecretVec::new(hex::decode(encrypted)?);
    let decryptor = age::Decryptor::new(decoded.expose_secret().as_slice())?;
    let mut output = vec![];
    let default_language: LanguageIdentifier = "en-US".parse()?;
    age::localizer().select(&[default_language])?;
    if let age::Decryptor::Passphrase(decryptor) = decryptor {
        let mut reader = decryptor.decrypt(passphrase, None)?;
        reader.read_to_end(&mut output)?;
    } else {
        return Err(ContributeError::UnsupportedDecryptorError.into());
    }

    Ok(output)
}

fn read_private_key(keys_path: &str) -> Result<PrivateKey> {
    let mut contents = String::new();
    File::open(&keys_path)?.read_to_string(&mut contents)?;
    let keys: AleoSetupKeys = serde_json::from_str(&contents)?;
    let passphrase = age::cli_common::read_secret("Enter your Aleo setup passphrase", "Passphrase", None)
        .map_err(|_| ContributeError::CouldNotReadPassphraseError)?;
    let decrypted = SecretVec::new(decrypt(&passphrase, &keys.encrypted_private_key)?);
    let key = PrivateKey::from_str(std::str::from_utf8(decrypted.expose_secret())?)?;

    Ok(key)
}

fn main() {
    let matches = App::new("Public key extractor")
        .arg(
            Arg::with_name("path")
                .short("p")
                .long("path")
                .help("Path to a file containing the private key")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let key_path = matches.value_of("path").expect("Should have a path");
    let private_key = read_private_key(&key_path).expect("Should read a private key");

    let address = Address::from(&private_key)
        .expect("Should produce a public key out of a private key")
        .to_string();
    println!("{}", address);
}
