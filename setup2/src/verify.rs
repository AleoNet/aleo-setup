use crate::{Phase2Opts, VerifyOpts};
use phase2::chunked_groth16::verify as chunked_verify;
use setup_utils::Result;

use snarkvm_curves::{bls12_377::Bls12_377, bw6_761::BW6_761};

use fs_err::OpenOptions;
use memmap::MmapOptions;

pub fn verify(phase2_opts: &Phase2Opts, opts: &VerifyOpts) -> Result<()> {
    let before = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&opts.before)
        .expect("could not read the previous participant's MPC transcript file");
    let mut before = unsafe {
        MmapOptions::new()
            .map_mut(before.file())
            .expect("unable to create a memory map for input")
    };
    let after = OpenOptions::new()
        .read(true)
        .write(true)
        .open(&opts.after)
        .expect("could not read the previous participant's MPC transcript file");
    let mut after = unsafe {
        MmapOptions::new()
            .map_mut(after.file())
            .expect("unable to create a memory map for input")
    };
    if phase2_opts.is_inner {
        chunked_verify::<Bls12_377>(&mut before, &mut after, phase2_opts.batch_size)?;
    } else {
        chunked_verify::<BW6_761>(&mut before, &mut after, phase2_opts.batch_size)?;
    }
    Ok(())
}
