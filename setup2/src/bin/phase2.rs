use setup2::*;

use gumdrop::Options;
use snarkvm_curves::{bls12_377::Bls12_377, bw6_761::BW6_761};
use std::{process, time::Instant};
use tracing::{error, info};
use tracing_subscriber::{
    filter::EnvFilter,
    fmt::{time, Subscriber},
};

fn execute_cmd(opts: Phase2Opts) {
    let command = opts.clone().command.unwrap_or_else(|| {
        error!("No command was provided.");
        error!("{}", Phase2Opts::usage());
        process::exit(2)
    });

    let now = Instant::now();

    match command {
        Command::New(opt) => {
            new(&opts, &opt).unwrap();
        }
        Command::Contribute(opt) => {
            let seed = hex::decode(
                &std::fs::read_to_string(&opts.seed)
                    .expect("should have read seed")
                    .trim(),
            )
            .expect("seed should be a hex string");
            let mut rng = setup_utils::derive_rng_from_seed(&seed);
            contribute(&opts, &opt, &mut rng).unwrap();
        }
        Command::Verify(opt) => {
            verify(&opts, &opt).unwrap();
        }
        Command::Combine(opt) => {
            if opts.is_inner {
                combine::<Bls12_377>(&opt);
            } else {
                combine::<BW6_761>(&opt);
            }
        }
    };

    let new_now = Instant::now();
    info!("Executing {:?} took: {:?}", opts, new_now.duration_since(now));
}

fn main() {
    Subscriber::builder()
        .with_timer(time::UtcTime::rfc_3339())
        .with_env_filter(EnvFilter::from_default_env())
        .init();
    let opts = SNARKOpts::parse_args_default_or_exit();

    let opts: Phase2Opts = Phase2Opts::parse_args_default_or_exit();

    match opts.curve_kind {
        CurveKind::Bls12_377 => execute_cmd(opts),
        CurveKind::BW6 => execute_cmd(opts),
    };
}
