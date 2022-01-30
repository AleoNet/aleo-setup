use crate::{ContributeOpts, Phase2Opts};
use phase2::{chunked_groth16::contribute as chunked_contribute, keypair::PublicKey};
use setup_utils::Result;

use snarkvm_curves::{bls12_377::Bls12_377, bw6_761::BW6_761};

use fs_err::OpenOptions;
use memmap::MmapOptions;
use rand::{CryptoRng, Rng};

pub fn contribute<R: CryptoRng + Rng>(phase2_opts: &Phase2Opts, opts: &ContributeOpts, rng: &mut R) -> Result<()> {
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&opts.data)
        .expect("could not open file for writing the new MPC parameters ");
    let metadata = file.metadata()?;
    // extend the file by 1 pubkey
    if phase2_opts.is_inner {
        file.set_len(metadata.len() + PublicKey::<Bls12_377>::size() as u64)?;
    } else {
        file.set_len(metadata.len() + PublicKey::<BW6_761>::size() as u64)?;
    }
    let mut file = unsafe {
        MmapOptions::new()
            .map_mut(file.file())
            .expect("unable to create a memory map for input")
    };

    if phase2_opts.is_inner {
        chunked_contribute::<Bls12_377, _>(&mut file, rng, phase2_opts.batch_size)?;
    } else {
        chunked_contribute::<BW6_761, _>(&mut file, rng, phase2_opts.batch_size)?;
    }

    Ok(())
}
