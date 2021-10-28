use crate::{
    cli::commands::contribute::ContributeOptions,
    errors::ContributeError,
    objects::LockResponse,
    setup_keys::{
        confirmation_key::{print_key_and_remove_the_file, ConfirmationKey},
        AleoSetupKeys,
    },
    utils::{create_parameters_for_chunk, get_authorization_value, sign_contribution_state},
};

use phase1::helpers::converters::CurveKind;
use phase1_cli::contribute;
use phase1_coordinator::{
    environment::Environment,
    objects::{Chunk, Round},
};
use setup1_shared::structures::{ContributorStatus, PublicSettings, TwitterInfo};
use setup_utils::calculate_hash;
use snarkvm_curves::{bls12_377::Bls12_377, bw6_761::BW6_761, PairingEngine};
use snarkvm_dpc::{parameters::testnet2::Testnet2Parameters, Address, PrivateKey, ViewKey};

use age::DecryptError;
use anyhow::{Context, Result};
use dialoguer::{theme::ColorfulTheme, Confirm, Input};
use fs_err::File;
use indicatif::{ProgressBar, ProgressStyle};
use rand::{CryptoRng, Rng};
use regex::Regex;
use secrecy::{ExposeSecret, SecretString, SecretVec};
use setup_utils::derive_rng_from_seed;
use std::{collections::HashSet, convert::TryFrom, io::Read, path::PathBuf, str::FromStr, sync::Arc, time::Duration};
use tokio::time::{sleep, Instant};
use tracing::{error, info};
use url::Url;

const DELAY_AFTER_ERROR: Duration = Duration::from_secs(60);
const DELAY_POLL_CEREMONY: Duration = Duration::from_secs(5);
const HEARTBEAT_POLL_DELAY: Duration = Duration::from_secs(30);

// Version constants
const MAJOR: u8 = 0;
const MINOR: u8 = 1;
const PATCH: u8 = 0;

#[derive(Clone)]
pub struct Contribute {
    pub server_url: Url,
    /// Public key id for this contributor: e.g.
    /// `aleo1h7pwa3dh2egahqj7yvq7f7e533lr0ueysaxde2ktmtu2pxdjvqfqsj607a`
    pub participant_id: Address<Testnet2Parameters>,
    pub private_key: PrivateKey<Testnet2Parameters>,
    seed: Arc<SecretVec<u8>>,
    pub environment: Environment,
}

impl Contribute {
    pub fn new(
        opts: &ContributeOptions,
        environment: &Environment,
        private_key: PrivateKey<Testnet2Parameters>,
        seed: SecretVec<u8>,
    ) -> Self {
        // TODO (raychu86): Pass in pipelining options from the CLI.

        Self {
            server_url: opts.api_url.clone(),
            participant_id: Address::try_from(&private_key).expect("Should have derived an Aleo address"),
            private_key,
            seed: Arc::new(seed),
            environment: environment.clone(),
        }
    }

    async fn run_and_catch_errors<E: PairingEngine>(&mut self) -> Result<()> {
        println!("Attempting to join the queue...");

        loop {
            let join_result = self.join_queue(&mut rand::thread_rng()).await;
            match join_result {
                Ok(joined) => {
                    info!("Attempted to join the queue with response: {}", joined);
                    if !joined {
                        // it means contributor either already contributed,
                        // or has a low reliability score, or unable to
                        // join the queue
                        return Err(anyhow::anyhow!("Queue join returned false"));
                    }

                    break;
                }
                Err(err) => {
                    let text = format!("Failed to join the queue, error: {}", err);
                    error!("{}", text);
                    sleep(DELAY_POLL_CEREMONY).await;
                }
            }
        }

        // XXX: This *needs* to be ran before the loop, so that heartbeats will
        // still come in while the contributor is queued or working and waiting for
        // an available chunk. Otherwise, the contributor will be dropped inadvertently.
        initiate_heartbeat(self.server_url.clone(), self.private_key.clone());

        let progress_bar = initialize_progress_bar();
        // Run contributor loop.
        loop {
            let result = self.run::<E>(&progress_bar).await;
            match result {
                Ok(_) => {
                    info!("Successfully contributed, thank you for participation!");
                    break;
                }
                Err(err) => {
                    tracing::error!("Error from contribution run: {}", err);
                    sleep(DELAY_AFTER_ERROR).await;
                }
            }
        }

        println!("You have completed your contribution! Thank you!");

        print_key_and_remove_the_file().expect("Error finalizing the participation");

        // Let's see if the contributor wants to log an ETH address for their NFT
        if let Err(e) = self.prompt_eth_address(&mut rand::rngs::OsRng).await {
            tracing::error!("Error while prompting for ETH address - {}", e);
        }

        match self.prompt_tweet(&mut rand::rngs::OsRng).await {
            Ok(s) => {
                if s.is_some() {
                    println!("Thanks for making an attestation! Your tweet: {}", s.unwrap());
                }
            }
            Err(e) => {
                tracing::error!("Error while prompting for an attestation tweet - {}", e);
            }
        };

        Ok(())
    }

    async fn run<E: PairingEngine>(&mut self, progress_bar: &ProgressBar) -> Result<()> {
        loop {
            let status = get_contributor_status(&self.server_url, &self.private_key).await?;
            match status {
                ContributorStatus::Queue(position, queue_size) => {
                    progress_bar.set_length(queue_size);
                    progress_bar.set_position(position);
                    progress_bar.set_message("In the queue...");
                    tokio::time::sleep(DELAY_POLL_CEREMONY).await;
                    continue;
                }
                ContributorStatus::Round | ContributorStatus::Finished => {
                    // do nothing, let the code below to handle this case
                }
                ContributorStatus::Other => {
                    progress_bar.finish_with_message(
                        "Not in the queue for Aleo Setup ceremony. Please double check the address \
                    you are connecting to, then disconnect and try again",
                    );
                    tokio::time::sleep(DELAY_POLL_CEREMONY).await;
                    continue;
                }
            }
            let ceremony = get_ceremony(&self.server_url).await?;
            let number_of_chunks = ceremony.chunks().len();
            progress_bar.set_length(number_of_chunks as u64);
            let non_contributed_chunks = get_non_contributed_chunks(&ceremony, &self.participant_id.to_string());
            progress_bar.set_position((number_of_chunks - non_contributed_chunks.len()) as u64);

            // Check if the contributor is finished or needs to wait for an available lock
            let incomplete_chunks = self.get_non_contributed_and_available_chunks(&ceremony);
            if incomplete_chunks.is_empty() {
                if non_contributed_chunks.is_empty() {
                    let completed_message = "Finished!";
                    progress_bar.finish_with_message(completed_message);
                    info!(completed_message);

                    return Ok(());
                } else {
                    tokio::time::sleep(DELAY_POLL_CEREMONY).await;
                    continue;
                }
            }

            let auth_rng = &mut rand::rngs::OsRng;

            // Attempt to lock a chunk from the coordinator.
            let lock_response = self.lock_chunk(auth_rng).await?;

            let chunk_id = lock_response.chunk_id;

            progress_bar.set_message(&format!("Contributing to chunk {}...", chunk_id));

            let challenge_file = self
                .download_challenge(chunk_id, lock_response.contribution_id, auth_rng)
                .await?;

            let exposed_seed = self.seed.expose_secret();
            let seeded_rng = derive_rng_from_seed(&exposed_seed[..]);
            let start = Instant::now();

            // Fetch parameters required for contribution.
            let parameters = create_parameters_for_chunk::<E>(&self.environment, chunk_id as usize)?;
            let compressed_input = self.environment.compressed_inputs();
            let compressed_output = self.environment.compressed_outputs();
            let check_input_correctness = self.environment.check_input_for_correctness();

            // Run the contribution.
            let response_file = contribute(
                compressed_input,
                &challenge_file,
                compressed_output,
                check_input_correctness,
                &parameters,
                seeded_rng,
            );
            let duration = start.elapsed();

            info!("Completed chunk {} in {} seconds", chunk_id, duration.as_secs());

            // Hash the challenge and response files.
            let challenge_hash = calculate_hash(&challenge_file);
            let response_hash = calculate_hash(&response_file);

            // Sign the contribution state.
            let view_key = ViewKey::try_from(&self.private_key)?;
            let signed_contribution_state =
                sign_contribution_state(&view_key.to_string(), &challenge_hash, &response_hash, None, auth_rng)?;

            // Concatenate the signed contribution data and next challenge file.
            let verifier_flag = [0];
            let signature_bytes = hex::decode(signed_contribution_state.get_signature())?;

            let signature_and_response_file_bytes = [
                &verifier_flag[..],
                &signature_bytes[..],
                &challenge_hash[..],
                &response_hash[..],
                &response_file[..],
            ]
            .concat();

            // Upload the response and contribution file signature to the coordinator.
            loop {
                match self
                    .upload_response(
                        lock_response.response_chunk_id,
                        lock_response.response_contribution_id,
                        signature_and_response_file_bytes.clone(),
                        auth_rng,
                    )
                    .await
                {
                    Ok(_) => break,
                    Err(e) => {
                        tracing::error!("Could not upload response - {}", e);
                        sleep(DELAY_POLL_CEREMONY).await;
                    }
                };
            }

            // Attempt to perform the contribution with the uploaded response file at the `upload_url`.
            loop {
                match self
                    .notify_contribution(chunk_id, serde_json::json!({}), auth_rng)
                    .await
                {
                    Ok(_) => break,
                    Err(e) => {
                        tracing::error!("Could not notify the coordinator of contribution - {}", e);
                        sleep(DELAY_POLL_CEREMONY).await;
                    }
                };
            }

            progress_bar.set_message("Waiting for an available chunk...");
        }
    }

    /// Get references to the unlocked chunks which have been
    /// completely verified, and do not yet contain a contribution
    /// from this contributor.
    fn get_non_contributed_and_available_chunks<'r>(&self, ceremony: &'r Round) -> Vec<&'r Chunk> {
        get_non_contributed_chunks(ceremony, &self.participant_id.to_string())
            .into_iter()
            .filter(|chunk| chunk.lock_holder().is_none())
            .collect()
    }

    async fn join_queue<R: Rng + CryptoRng>(&self, auth_rng: &mut R) -> Result<bool> {
        let join_queue_path = format!("/v1/queue/contributor/join/{}/{}/{}", MAJOR, MINOR, PATCH);
        let join_queue_path_url = self.server_url.join(&join_queue_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "POST", &join_queue_path, auth_rng)?;

        let address = self.participant_id.to_string();
        let confirmation_key = ConfirmationKey::for_current_round(address)?;
        let bytes = serde_json::to_vec(&confirmation_key)?;

        let response = client
            .post(join_queue_path_url.as_str())
            .header(http::header::AUTHORIZATION, authorization)
            .header(http::header::CONTENT_LENGTH, bytes.len())
            .body(bytes)
            .send()
            .await?
            .error_for_status()?;

        let data = response.bytes().await?;
        let joined = serde_json::from_slice::<bool>(&*data)?;

        Ok(joined)
    }

    async fn lock_chunk<R: Rng + CryptoRng>(&self, auth_rng: &mut R) -> Result<LockResponse> {
        let lock_path = "/v1/contributor/try_lock";
        let lock_chunk_url = self.server_url.join(lock_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "POST", lock_path, auth_rng)?;
        let response = client
            .post(lock_chunk_url.as_str())
            .header(http::header::AUTHORIZATION, authorization)
            .header(http::header::CONTENT_LENGTH, 0)
            .send()
            .await?
            .error_for_status()?;

        let data = response.bytes().await?;
        let lock_response = serde_json::from_slice::<LockResponse>(&*data)?;

        Ok(lock_response)
    }

    async fn download_challenge<R: Rng + CryptoRng>(
        &self,
        chunk_id: u64,
        contribution_id: u64,
        auth_rng: &mut R,
    ) -> Result<Vec<u8>> {
        let download_path = format!("/v1/download/challenge/{}/{}", chunk_id, contribution_id);
        let download_path_url = self.server_url.join(&download_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "GET", &download_path, auth_rng)?;
        let challenge = client
            .get(download_path_url.as_str())
            .header(http::header::AUTHORIZATION, authorization)
            .send()
            .await?
            .error_for_status()?
            .bytes()
            .await?
            .to_vec();

        Ok(challenge)
    }

    async fn upload_response<R: Rng + CryptoRng>(
        &self,
        chunk_id: u64,
        contribution_id: u64,
        contents: Vec<u8>,
        auth_rng: &mut R,
    ) -> Result<()> {
        let upload_path = format!("/v1/upload/response/{}/{}", chunk_id, contribution_id);
        let upload_path_url = self.server_url.join(&upload_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "POST", &upload_path, auth_rng)?;
        client
            .post(upload_path_url.as_str())
            .header(http::header::AUTHORIZATION, authorization)
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .header(http::header::CONTENT_LENGTH, contents.len())
            .body(contents)
            .send()
            .await?
            .error_for_status()?;

        Ok(())
    }

    async fn notify_contribution<R: Rng + CryptoRng>(
        &self,
        chunk_id: u64,
        body: serde_json::Value,
        auth_rng: &mut R,
    ) -> Result<()> {
        let contribute_path = format!("/v1/contributor/try_contribute/{}", chunk_id);
        let contribute_chunk_url = self.server_url.join(&contribute_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "POST", &contribute_path, auth_rng)?;
        let bytes = serde_json::to_vec(&body)?;
        client
            .post(contribute_chunk_url.as_str())
            .header(http::header::AUTHORIZATION, authorization)
            .header(http::header::CONTENT_LENGTH, bytes.len())
            .body(bytes)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn prompt_tweet<R: Rng + CryptoRng>(&self, auth_rng: &mut R) -> Result<Option<String>> {
        if Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt("Would you like to tweet an attestation to your contribution?")
            .interact()
            .unwrap()
        {
            loop {
                let request_token = self.get_twitter_access_token(auth_rng).await?;
                let auth_url = egg_mode::auth::authorize_url(&request_token);

                println!(
                    "Please visit this URL and authorize the Aleo Setup application to tweet on your behalf - {}\n\nWhen you're finished, the website will give you a PIN code. Please enter it in the input below.",
                    auth_url
                );

                let re = Regex::new(r"^[0-9]{7}$").unwrap();
                let pin: String = Input::with_theme(&ColorfulTheme::default())
                    .with_prompt("Enter PIN")
                    .validate_with({
                        move |input: &String| -> Result<(), &str> {
                            if re.is_match(input) {
                                Ok(())
                            } else {
                                Err("The PIN should be 7 digits.")
                            }
                        }
                    })
                    .interact_text()
                    .unwrap();

                let info = TwitterInfo {
                    request_token: request_token.clone(),
                    pin,
                };

                match self.post_tweet(auth_rng, info).await {
                    Ok(link) => return Ok(Some(link)),
                    Err(e) => println!("Could not post tweet - {}\n\nPlease try again", e),
                };
            }
        }

        Ok(None)
    }

    async fn prompt_eth_address<R: Rng + CryptoRng>(&self, auth_rng: &mut R) -> Result<()> {
        println!(
            "Thank you for participating in Aleo Setup. As a token of appreciation, we would like to send you a commemorative NFT. This NFT is procedurally generated, but represents your unique contribution. We hope it serves as a reminder of the important role that YOU played in bringing Aleo to life.\n\nPlease enter the Ethereum address where you would like to receive the NFT:"
        );

        // Validate address
        // NOTE: this only checks that the inputted string conforms to the same structure
        // as ETH addresses - it does not actually perform a checksum validation.
        // https://ethereum.stackexchange.com/a/40670
        let re = Regex::new(r"^(0x|0X){1}[0-9a-fA-F]{40}$").unwrap();

        let address: String = Input::with_theme(&ColorfulTheme::default())
            .with_prompt("Your ETH address")
            .allow_empty(true)
            .validate_with({
                let mut opt_out = false;
                move |input: &String| -> Result<(), &str> {
                    if re.is_match(input) || (opt_out && input.len() == 0) {
                        Ok(())
                    } else if input.len() == 0 {
                        opt_out = true;
                        Err("Leaving this field blank will prevent you from receiving your NFT. Are you sure?")
                    } else {
                        opt_out = false;
                        Err("This is not a valid Ethereum address.")
                    }
                }
            })
            .interact_text()
            .unwrap();

        if address.len() > 0 {
            self.upload_eth_address(auth_rng, address).await
        } else {
            Ok(())
        }
    }

    async fn upload_eth_address<R: Rng + CryptoRng>(&self, auth_rng: &mut R, address: String) -> Result<()> {
        let upload_path = "/v1/contributor/add_eth_address";
        let upload_endpoint_url = self.server_url.join(upload_path)?;
        let authorization = get_authorization_value(&self.private_key, "POST", upload_path, auth_rng)?;
        let client = reqwest::Client::new();
        let bytes = serde_json::to_string(&address)?;
        client
            .post(upload_endpoint_url)
            .header(http::header::AUTHORIZATION, authorization)
            .header(http::header::CONTENT_LENGTH, bytes.len())
            .body(bytes)
            .send()
            .await?
            .error_for_status()?;
        Ok(())
    }

    async fn get_twitter_access_token<R: Rng + CryptoRng>(&self, auth_rng: &mut R) -> Result<egg_mode::KeyPair> {
        let get_path = "/v1/contributor/get_twitter_access_token";
        let get_endpoint_url = self.server_url.join(get_path)?;
        let authorization = get_authorization_value(&self.private_key, "GET", get_path, auth_rng)?;
        let client = reqwest::Client::new();
        let response = client
            .get(get_endpoint_url)
            .header(http::header::AUTHORIZATION, authorization)
            .send()
            .await?
            .error_for_status()?;

        let data = response.bytes().await?;
        let request_token = serde_json::from_slice::<egg_mode::KeyPair>(&*data)?;

        Ok(request_token)
    }

    async fn post_tweet<R: Rng + CryptoRng>(&self, auth_rng: &mut R, info: TwitterInfo) -> Result<String> {
        let post_path = "/v1/contributor/post_tweet";
        let post_endpoint_url = self.server_url.join(post_path)?;
        let authorization = get_authorization_value(&self.private_key, "POST", post_path, auth_rng)?;
        let client = reqwest::Client::new();
        let bytes = serde_json::to_vec(&info)?;
        let response = client
            .post(post_endpoint_url)
            .header(http::header::AUTHORIZATION, authorization)
            .header(http::header::CONTENT_LENGTH, bytes.len())
            .body(bytes)
            .send()
            .await?
            .error_for_status()?;

        let data = response.bytes().await?;
        let request_token = serde_json::from_slice::<String>(&*data)?;

        Ok(request_token)
    }
}

fn initialize_progress_bar() -> ProgressBar {
    // This function will only be called if the contributor is already
    // in the queue. So, we can just print it here and leave it.
    println!(
        "You are in the queue for an upcoming round of the ceremony. \
        Please wait for the prior round to finish, and please stay \
        connected for the duration of your contribution.",
    );

    let progress_bar = ProgressBar::new(0);
    let progress_style =
        ProgressStyle::default_bar().template("[{elapsed_precise}] {bar:40.cyan/blue} {pos}/{len} {msg}");
    progress_bar.enable_steady_tick(1000);
    progress_bar.set_style(progress_style);
    progress_bar.set_message("Getting initial data from the server...");
    progress_bar
}

async fn get_contributor_status(
    server_url: &Url,
    private_key: &PrivateKey<Testnet2Parameters>,
) -> Result<ContributorStatus> {
    let endpoint = "/v1/contributor/status";
    let ceremony_url = server_url.join(endpoint)?;

    let auth_rng = &mut rand::rngs::OsRng;
    let authorization = get_authorization_value(private_key, "POST", endpoint, auth_rng)?;

    let client = reqwest::Client::new();
    let response = client
        .post(ceremony_url)
        .header(http::header::AUTHORIZATION, authorization)
        .header(http::header::CONTENT_LENGTH, 0)
        .send()
        .await?
        .error_for_status()?;

    let data = response.bytes().await?;
    let status = serde_json::from_slice(&*data)?;

    Ok(status)
}

async fn get_ceremony(server_url: &Url) -> Result<Round> {
    let ceremony_url = server_url.join("/v1/round/current")?;
    let response = reqwest::get(ceremony_url.as_str()).await?.error_for_status()?;

    let data = response.bytes().await?;
    let ceremony = serde_json::from_slice(&*data)?;

    Ok(ceremony)
}

/// Get references to the chunks which have been completely
/// verified, and do not yet contain a contribution from this
/// contributor.
fn get_non_contributed_chunks<'r>(ceremony: &'r Round, participant_id: &str) -> Vec<&'r Chunk> {
    ceremony
        .chunks()
        .iter()
        .filter(|chunk| {
            if !chunk_all_verified(chunk) {
                return false;
            }

            !contributor_ids_in_chunk(chunk).contains(participant_id)
        })
        .collect()
}

struct HeartbeatData {
    server_url: Url,
    private_key: PrivateKey<Testnet2Parameters>,
}

impl HeartbeatData {
    async fn heartbeat<R: Rng + CryptoRng>(&self, auth_rng: &mut R) -> Result<()> {
        let heartbeat_path = "/v1/contributor/heartbeat";
        let url = self.server_url.join(heartbeat_path)?;
        let client = reqwest::Client::new();
        let authorization = get_authorization_value(&self.private_key, "POST", heartbeat_path, auth_rng)?;
        let response = client
            .post(url.as_str())
            .header(http::header::AUTHORIZATION, authorization)
            .header(http::header::CONTENT_LENGTH, 0)
            .send()
            .await?
            .error_for_status()?;

        response.error_for_status()?;

        Ok(())
    }
}

fn initiate_heartbeat(server_url: Url, private_key: PrivateKey<Testnet2Parameters>) {
    let private_key = private_key.to_string();
    std::thread::spawn(move || {
        let heartbeat_data = HeartbeatData {
            server_url,
            private_key: PrivateKey::from_str(&private_key).expect("Failed to create PrivateKey from String"),
        };

        let auth_rng = &mut rand::rngs::OsRng;
        let runtime = tokio::runtime::Runtime::new().unwrap();
        loop {
            tracing::info!("Performing heartbeat.");
            if let Err(error) = runtime.block_on(heartbeat_data.heartbeat(auth_rng)) {
                tracing::error!("Error performing heartbeat: {}", error);
            }
            std::thread::sleep(HEARTBEAT_POLL_DELAY);
        }
    });
}

fn decrypt(passphrase: &SecretString, encrypted: &str) -> Result<Vec<u8>> {
    let decoded = SecretVec::new(hex::decode(encrypted)?);
    let decryptor = age::Decryptor::new(decoded.expose_secret().as_slice())?;
    let mut output = vec![];
    if let age::Decryptor::Passphrase(decryptor) = decryptor {
        let mut reader = decryptor
            .decrypt(passphrase, None)
            .map_err(|decrypt_error: DecryptError| match decrypt_error {
                DecryptError::ExcessiveWork { .. } => anyhow::Error::from(decrypt_error)
                    .context("Perhaps you have forgotten to compile in release mode, or your hardware is too slow?"),
                _ => anyhow::Error::from(decrypt_error),
            })
            .context("Unable to create decrypt reader")?;

        reader.read_to_end(&mut output)?;
    } else {
        return Err(ContributeError::UnsupportedDecryptorError.into());
    }

    Ok(output)
}

/// Decrypts and reads the private key from the specified `keys_path`,
/// decrypting using the specified `passphrase`
fn read_keys<P: Into<PathBuf>>(
    keys_path: P,
    passphrase: &SecretString,
) -> Result<(SecretVec<u8>, PrivateKey<Testnet2Parameters>)> {
    let mut contents = String::new();
    File::open(keys_path)?.read_to_string(&mut contents)?;
    let keys: AleoSetupKeys = serde_json::from_str(&contents)?;

    let seed = SecretVec::new(decrypt(passphrase, &keys.encrypted_seed)?);
    let decrypted_private_key = SecretVec::new(decrypt(passphrase, &keys.encrypted_private_key)?);
    let private_key = PrivateKey::from_str(std::str::from_utf8(decrypted_private_key.expose_secret())?)?;

    Ok((seed, private_key))
}

async fn request_coordinator_public_settings(coordinator_url: &Url) -> anyhow::Result<PublicSettings> {
    let settings_endpoint_url = coordinator_url.join("/v1/coordinator/settings")?;
    let client = reqwest::Client::new();
    let bytes = client
        .post(settings_endpoint_url)
        .header(http::header::CONTENT_LENGTH, 0)
        .send()
        .await?
        .bytes()
        .await?;
    PublicSettings::decode(&bytes.to_vec())
        .map_err(|e| anyhow::anyhow!("Error decoding coordinator PublicSettings: {}", e))
}

pub async fn contribute_subcommand(opts: &ContributeOptions) -> anyhow::Result<()> {
    let public_settings = request_coordinator_public_settings(&opts.api_url)
        .await
        .map_err(|e| {
            tracing::error!("Failed to fetch the coordinator public settings");
            e
        })
        .with_context(|| "Failed to fetch the coordinator public settings".to_owned())?;

    start_contributor(opts, &public_settings).await
}

async fn start_contributor(opts: &ContributeOptions, public_settings: &PublicSettings) -> Result<()> {
    let environment = crate::utils::environment_by_setup_kind(&public_settings.setup);

    // Initialize tracing logger. Stored to `aleo-setup.log`.
    let appender = tracing_appender::rolling::never(".", "aleo-setup.log");
    let (non_blocking, _guard) = tracing_appender::non_blocking(appender);
    tracing_subscriber::fmt().with_writer(non_blocking).init();

    let passphrase = crate::setup_keys::read_passphrase(opts.passphrase.clone())?;

    // Read the stored contribution seed and Aleo private key.
    let (seed, private_key) = read_keys(&opts.keys_path, &passphrase).expect("Unable to load Aleo setup keys");

    let curve_kind = environment.parameters().curve();

    // Initialize the contributor.
    let mut contribute = Contribute::new(opts, &environment, private_key, seed);

    if public_settings.check_reliability {
        println!("Checking CPU performance, it may take a few minutes");
        tracing::info!("Checking reliability score before joining the queue");
        crate::reliability::check(&opts.api_url, &contribute.private_key).await?;
        println!("CPU check complete");
        tracing::info!("Reliability checks completed successfully");
    }

    // Run the contributor.
    let contribution = match curve_kind {
        CurveKind::Bls12_377 => contribute.run_and_catch_errors::<Bls12_377>().await,
        CurveKind::BW6 => contribute.run_and_catch_errors::<BW6_761>().await,
    };

    if let Err(e) = contribution {
        info!("Error occurred during contribution: {}", e.to_string());
    }

    Ok(())
}

/// Check that every contribution in the chunk has been verified.
fn chunk_all_verified(chunk: &Chunk) -> bool {
    chunk.get_contributions().iter().all(|(_, c)| c.is_verified())
}

/// Obtain a set with the id of every contributor in the chunk who's
/// contribution has been verified.
fn contributor_ids_in_chunk(chunk: &Chunk) -> HashSet<String> {
    chunk
        .get_contributions()
        .iter()
        .filter(|(_, c)| c.is_verified())
        .filter_map(|(_, c)| {
            c.get_contributor()
                .as_ref()
                .map(|c| c.to_string().split('.').collect::<Vec<_>>()[0].to_string())
        })
        .collect()
}

#[cfg(test)]
mod test {
    use super::{chunk_all_verified, contributor_ids_in_chunk};
    use phase1_coordinator::objects::{Chunk, Participant};

    #[test]
    fn test_participant_ids_in_chunk() {
        let verifier = Participant::Verifier(
            "aleo1yphn5z63acdpelyk2c3xmf6fuzpxymusp3c260ne6q0rrhrtdufqenlwqg.verifier".to_string(),
        );
        let contributor1 = Participant::Contributor(
            "aleo1fa6q44gpw0vkpx7xsfhgadz48swtg3wqf98w0xkrydwtvs62q5zsqyv5d7.contributor".to_string(),
        );
        let contributor2 = Participant::Contributor(
            "aleo1h7pwa3dh2egahqj7yvq7f7e533lr0ueysaxde2ktmtu2pxdjvqfqsj607a.contributor".to_string(),
        );

        let mut chunk = Chunk::new(0, verifier.clone(), String::new().into(), String::new().into()).unwrap();

        chunk.acquire_lock(contributor1.clone(), 3).unwrap();
        chunk
            .add_contribution(1, &contributor1, String::new().into(), String::new().into())
            .unwrap();
        assert!(!chunk_all_verified(&chunk));
        chunk.acquire_lock(verifier.clone(), 3).unwrap();
        chunk
            .verify_contribution(1, verifier.clone(), String::new().into(), String::new().into())
            .unwrap();
        assert!(chunk_all_verified(&chunk));

        chunk.acquire_lock(contributor2.clone(), 3).unwrap();
        chunk
            .add_contribution(2, &contributor2, String::new().into(), String::new().into())
            .unwrap();
        assert!(!chunk_all_verified(&chunk));
        chunk.acquire_lock(verifier.clone(), 3).unwrap();
        chunk
            .verify_contribution(2, verifier.clone(), String::new().into(), String::new().into())
            .unwrap();
        assert!(chunk_all_verified(&chunk));

        let ids = contributor_ids_in_chunk(&chunk);
        assert_eq!(2, ids.len());
        assert!(ids.contains(&contributor1.to_string().replace(".contributor", "")));
        assert!(ids.contains(&contributor2.to_string().replace(".contributor", "")));
    }
}
