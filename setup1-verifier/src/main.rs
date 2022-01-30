use std::{path::PathBuf, str::FromStr};

use phase1_coordinator::environment::{Development, Environment, Parameters, Production};
use setup1_shared::structures::{PublicSettings, SetupKind};
use snarkvm_dpc::{testnet2::Testnet2, Address, PrivateKey};
use structopt::StructOpt;
use tracing::info;
use url::Url;

mod coordinator_requests;
mod errors;
mod utils;
mod verifier;

use crate::verifier::Verifier;

fn development() -> Environment {
    Development::from(Parameters::TestCustom {
        number_of_chunks: 64,
        power: 16,
        batch_size: 512,
    })
    .into()
}

fn inner() -> Environment {
    Production::from(Parameters::AleoInner).into()
}

fn outer() -> Environment {
    Production::from(Parameters::AleoOuter).into()
}

fn universal() -> Environment {
    Production::from(Parameters::AleoUniversal).into()
}

#[derive(Debug, StructOpt)]
#[structopt(name = "Aleo setup verifier")]
struct Options {
    #[structopt(long, help = "Path to a file containing verifier private key")]
    private_key: PathBuf,
    #[structopt(long, help = "Coordinator api url, for example http://localhost:9000")]
    api_url: Url,
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

#[tokio::main]
async fn main() {
    let options = Options::from_args();

    crate::utils::init_logger();

    let public_settings = request_coordinator_public_settings(&options.api_url)
        .await
        .expect("Failed to fetch the coordinator public settings");

    let environment = match public_settings.setup {
        SetupKind::Development => development(),
        SetupKind::Inner => inner(),
        SetupKind::Outer => outer(),
        SetupKind::Universal => universal(),
    };

    let raw_private_key = std::fs::read_to_string(options.private_key).expect("View key not found");
    let private_key = PrivateKey::<Testnet2>::from_str(&raw_private_key).expect("Invalid view key");
    let address = Address::from_private_key(&private_key);

    // Initialize the verifier
    info!("Initializing verifier...");
    let verifier = Verifier::new(options.api_url.clone(), private_key, address, environment)
        .expect("Failed to initialize verifier");

    verifier.start_verifier().await;
}
