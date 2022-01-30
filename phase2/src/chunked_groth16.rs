//! Chunked Phase 2
//!
//! Large MPCs can require >50GB of elements to be loaded in memory. This module provides
//! utilities for operating directly on raw items which implement `Read`, `Write` and `Seek`
//! such that contributing and verifying the MPC can be done in chunks which fit in memory.
use crate::{
    keypair::{Keypair, PublicKey},
    parameters::*,
};
use setup_utils::{batch_mul, check_same_ratio, merge_pairs, InvariantKind, Phase2Error, Result};
use snarkvm_algorithms::snark::groth16::VerifyingKey;
use snarkvm_curves::{AffineCurve, PairingEngine};
use snarkvm_fields::Field;
use snarkvm_utilities::{CanonicalDeserialize, CanonicalSerialize, ConstantSerializedSize};

use byteorder::{BigEndian, WriteBytesExt};
use rand::{CryptoRng, Rng};
use std::{
    io::{Read, Seek, SeekFrom, Write},
    ops::{Mul, Neg},
};
use tracing::{debug, info, info_span, trace};

/// Given two serialized contributions to the ceremony, this will check that `after`
/// has been correctly calculated from `before`. Large vectors will be read in
/// `batch_size` batches
#[allow(clippy::cognitive_complexity)]
pub fn verify<E: PairingEngine>(before: &mut [u8], after: &mut [u8], batch_size: usize) -> Result<Vec<[u8; 64]>> {
    let span = info_span!("phase2-verify");
    let _enter = span.enter();
    info!("starting...");

    let before = &mut std::io::Cursor::new(before);
    let after = &mut std::io::Cursor::new(after);

    let vk_before = VerifyingKey::<E>::deserialize(before)?;
    let beta_g1_before = E::G1Affine::deserialize(before)?;
    // we don't need the previous delta_g1 so we can skip it
    before.seek(SeekFrom::Current(E::G1Affine::SERIALIZED_SIZE as i64))?;

    let vk_after = VerifyingKey::<E>::deserialize(after)?;
    let beta_g1_after = E::G1Affine::deserialize(after)?;
    let delta_g1_after = E::G1Affine::deserialize(after)?;

    // VK parameters remain unchanged, except for Delta G2
    // which we check at the end of the function against the new contribution's
    // pubkey
    ensure_unchanged(vk_before.alpha_g1, vk_after.alpha_g1, InvariantKind::AlphaG1)?;
    ensure_unchanged(beta_g1_before, beta_g1_after, InvariantKind::BetaG1)?;
    ensure_unchanged(vk_before.beta_g2, vk_after.beta_g2, InvariantKind::BetaG2)?;
    ensure_unchanged(vk_before.gamma_g2, vk_after.gamma_g2, InvariantKind::GammaG2)?;
    ensure_unchanged_vec(
        &vk_before.gamma_abc_g1,
        &vk_after.gamma_abc_g1,
        &InvariantKind::GammaAbcG1,
    )?;

    debug!("initial elements unchanged");

    // Split the before-after buffers in non-overlapping slices and spawn a thread for each group
    // of variables
    let position = before.position() as usize;
    let remaining_before = &mut before.get_mut()[position..];
    let position = after.position() as usize;
    let remaining_after = &mut after.get_mut()[position..];
    let (before_alpha_g1, before_beta_g1, before_beta_g2, before_h, before_l) =
        split_transcript::<E>(remaining_before)?;
    let (after_alpha_g1, after_beta_g1, after_beta_g2, after_h, after_l) = split_transcript::<E>(remaining_after)?;
    // Save the position where the cursor should be after the threads execute
    let pos = position
        + 5 * u64::SERIALIZED_SIZE
        + before_alpha_g1.len()
        + before_beta_g1.len()
        + before_beta_g2.len()
        + before_h.len()
        + before_l.len();

    crossbeam::scope(|s| -> Result<_> {
        let _enter = span.enter();
        // Alpha G1, Beta G1/G2 queries are same
        // (do this in chunks since the vectors may be large)
        let mut threads = Vec::with_capacity(5);
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("alpha_g1_query");
            let _enter = span.enter();
            chunked_ensure_unchanged_vec::<E::G1Affine>(
                before_alpha_g1,
                after_alpha_g1,
                batch_size,
                &InvariantKind::AlphaG1Query,
            )
        }));
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("beta_g1_query");
            let _enter = span.enter();
            chunked_ensure_unchanged_vec::<E::G1Affine>(
                before_beta_g1,
                after_beta_g1,
                batch_size,
                &InvariantKind::BetaG1Query,
            )
        }));
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("beta_g2_query");
            let _enter = span.enter();
            chunked_ensure_unchanged_vec::<E::G2Affine>(
                before_beta_g2,
                after_beta_g2,
                batch_size,
                &InvariantKind::BetaG2Query,
            )
        }));

        // H and L queries should be updated with delta^-1
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("h_g1_query");
            let _enter = span.enter();
            chunked_check_ratio::<E>(
                before_h,
                vk_before.delta_g2,
                after_h,
                vk_after.delta_g2,
                batch_size,
                "H_query ratio check failed",
            )
        }));
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("l_g1_query");
            let _enter = span.enter();
            chunked_check_ratio::<E>(
                before_l,
                vk_before.delta_g2,
                after_l,
                vk_after.delta_g2,
                batch_size,
                "L_query ratio check failed",
            )
        }));

        // join the threads at the end to ensure
        // the computation is done
        for t in threads {
            t.join()??;
        }

        Ok(())
    })??;

    before.seek(SeekFrom::Start(pos as u64))?;
    after.seek(SeekFrom::Start(pos as u64))?;

    // cs_hash should be the same
    let mut cs_hash_before = [0u8; 64];
    before.read_exact(&mut cs_hash_before)?;
    let mut cs_hash_after = [0u8; 64];
    after.read_exact(&mut cs_hash_after)?;
    ensure_unchanged(&cs_hash_before[..], &cs_hash_after[..], InvariantKind::CsHash)?;

    debug!("cs hash was unchanged");

    // None of the previous transformations should change
    let contributions_before = PublicKey::<E>::read_batch(before)?;
    let contributions_after = PublicKey::<E>::read_batch(after)?;
    ensure_unchanged(
        &contributions_before[..],
        &contributions_after[0..contributions_before.len()],
        InvariantKind::Contributions,
    )?;

    debug!("previous contributions were unchanged");

    // Ensure that the new pubkey has been properly calculated
    let pubkey = if let Some(pubkey) = contributions_after.last() {
        pubkey
    } else {
        // if there were no new contributions then we should error
        return Err(Phase2Error::NoContributions.into());
    };
    ensure_unchanged(pubkey.delta_after, delta_g1_after, InvariantKind::DeltaG1)?;
    debug!("public key was updated correctly");

    check_same_ratio::<E>(
        &(E::G1Affine::prime_subgroup_generator(), pubkey.delta_after),
        &(E::G2Affine::prime_subgroup_generator(), vk_after.delta_g2),
        "Inconsistent G2 Delta",
    )?;

    debug!("verifying key was updated correctly");

    let res = verify_transcript(cs_hash_before, &contributions_after)?;

    debug!("verified transcript");

    info!("done.");
    Ok(res)
}

/// Given a buffer which corresponds to the format of `MPCParameters` (Groth16 Parameters
/// followed by the contributions array and the contributions hash), this will modify the
/// Delta_g1, the VK's Delta_g2 and will update the H and L queries in place while leaving
/// everything else unchanged
pub fn contribute<E: PairingEngine, R: Rng + CryptoRng>(
    buffer: &mut [u8],
    rng: &mut R,
    batch_size: usize,
) -> Result<[u8; 64]> {
    let span = info_span!("phase2-contribute");
    let _enter = span.enter();

    info!("starting...");

    let buffer = &mut std::io::Cursor::new(buffer);
    // The VK is small so we read it directly from the start
    let mut vk = VerifyingKey::<E>::deserialize(buffer)?;
    // leave beta_g1 unchanged
    buffer.seek(SeekFrom::Current(E::G1Affine::SERIALIZED_SIZE as i64))?;
    // read delta_g1
    let mut delta_g1 = E::G1Affine::deserialize(buffer)?;

    // Skip the vector elements for now so that we can read the contributions
    skip_vec::<E::G1Affine, _>(buffer)?; // Alpha G1
    skip_vec::<E::G1Affine, _>(buffer)?; // Beta G1
    skip_vec::<E::G2Affine, _>(buffer)?; // Beta G2
    skip_vec::<E::G1Affine, _>(buffer)?; // H
    skip_vec::<E::G1Affine, _>(buffer)?; // L

    // Read the transcript hash and the contributions
    let mut cs_hash = [0u8; 64];
    buffer.read_exact(&mut cs_hash)?;
    let contributions = PublicKey::<E>::read_batch(buffer)?;

    // Create the keypair
    let Keypair {
        public_key,
        private_key,
    } = Keypair::new(delta_g1, cs_hash, &contributions, rng);
    let hash = public_key.hash();
    // THIS MUST BE DESTROYED
    let delta = private_key.delta;
    let delta_inv = private_key.delta.inverse().expect("nonzero");

    // update the values
    delta_g1 = delta_g1.mul(delta);
    vk.delta_g2 = vk.delta_g2.mul(delta);

    // go back to the start of the buffer to write the updated vk and delta_g1
    buffer.seek(SeekFrom::Start(0))?;
    // write the vk
    vk.serialize(buffer)?;
    // leave beta_g1 unchanged
    buffer.seek(SeekFrom::Current(E::G1Affine::SERIALIZED_SIZE as i64))?;
    // write delta_g1
    delta_g1.serialize(buffer)?;

    debug!("updated delta g1 and vk delta g2");

    skip_vec::<E::G1Affine, _>(buffer)?; // Alpha G1
    skip_vec::<E::G1Affine, _>(buffer)?; // Beta G1
    skip_vec::<E::G2Affine, _>(buffer)?; // Beta G2

    debug!("skipped unused elements...");

    // The previous operations are all on small size elements so do them serially
    // the `h` and `l` queries are relatively large, so we can get a nice speedup
    // by performing the reads and writes in parallel
    let h_query_len = u64::deserialize(buffer)? as usize;
    let position = buffer.position() as usize;
    let remaining = &mut buffer.get_mut()[position..];
    let (h, l) = remaining.split_at_mut(h_query_len * E::G1Affine::SERIALIZED_SIZE);
    let l_query_len = u64::deserialize(&mut &*l)? as usize;

    // spawn 2 scoped threads to perform the contribution
    crossbeam::scope(|s| -> Result<_> {
        let mut threads = Vec::with_capacity(2);
        let _enter = span.enter();
        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("h_query");
            let _enter = span.enter();
            chunked_mul_queries::<E::G1Affine>(h, h_query_len, &delta_inv, batch_size)
        }));

        threads.push(s.spawn(|_| {
            let _enter1 = span.enter();
            let span = info_span!("l_query");
            let _enter = span.enter();
            chunked_mul_queries::<E::G1Affine>(
                // since we read the l_query length we will pass the buffer
                // after it
                &mut l[u64::SERIALIZED_SIZE..],
                l_query_len,
                &delta_inv,
                batch_size,
            )
        }));

        for t in threads {
            t.join()??;
        }

        Ok(())
    })??;

    debug!("appending contribution...");

    // we processed the 2 elements via the raw buffer, so we have to modify the cursor accordingly
    let pos = position + (l_query_len + h_query_len) * E::G1Affine::SERIALIZED_SIZE + u64::SERIALIZED_SIZE;
    buffer.seek(SeekFrom::Start(pos as u64))?;

    // leave the cs_hash unchanged (64 bytes size)
    buffer.seek(SeekFrom::Current(64))?;

    // update the pubkeys length
    buffer.write_u32::<BigEndian>((contributions.len() + 1) as u32)?;

    // advance to where the next pubkey would be in the buffer and append it
    buffer.seek(SeekFrom::Current((PublicKey::<E>::size() * contributions.len()) as i64))?;
    public_key.write(buffer)?;

    info!("done.");

    Ok(hash)
}

/// Skips the vector ahead of the cursor.
fn skip_vec<C: AffineCurve, B: Read + Seek>(buffer: &mut B) -> Result<()> {
    let len = u64::deserialize(buffer)? as usize;
    let skip_len = len * C::SERIALIZED_SIZE;
    buffer.seek(SeekFrom::Current(skip_len as i64))?;
    Ok(())
}

/// Multiplies a vector of affine elements by `element` in `batch_size` batches
/// The first 8 bytes read from the buffer are the vector's length. The result
/// is written back to the buffer in place
#[allow(clippy::cognitive_complexity)]
fn chunked_mul_queries<C: AffineCurve>(
    buffer: &mut [u8],
    query_len: usize,
    element: &C::ScalarField,
    batch_size: usize,
) -> Result<()> {
    let span = info_span!("multiply_query");
    let _enter = span.enter();
    debug!("starting...");
    let buffer = &mut std::io::Cursor::new(buffer);

    let iters = query_len / batch_size;
    let leftovers = query_len % batch_size;
    // naive chunking, probably room for parallelization
    for i in 0..iters {
        let span = info_span!("iter", i);
        let _enter = span.enter();

        mul_query::<C, _>(buffer, element, batch_size)?;

        trace!("ok");
    }
    // in case the batch size did not evenly divide the number of queries
    if leftovers > 0 {
        let span = info_span!("iter", i = iters);
        let _enter = span.enter();

        mul_query::<C, _>(buffer, element, leftovers)?;

        trace!("ok");
    }

    debug!("done");
    Ok(())
}

/// Deserializes `num_els` elements, multiplies them by `element`
/// and writes them back in place
fn mul_query<C: AffineCurve, B: Read + Write + Seek>(
    buffer: &mut B,
    element: &C::ScalarField,
    num_els: usize,
) -> Result<()> {
    let mut query = (0..num_els)
        .map(|_| CanonicalDeserialize::deserialize(buffer))
        .collect::<std::result::Result<Vec<_>, _>>()?; // why can't we use the aliased error type here?

    batch_mul(&mut query, element)?;

    // seek back to update the elements
    buffer.seek(SeekFrom::Current(((num_els * C::SERIALIZED_SIZE) as i64).neg()))?;
    query
        .iter()
        .map(|el: &C| CanonicalSerialize::serialize(el, buffer))
        .collect::<std::result::Result<Vec<_>, _>>()?;

    Ok(())
}

/// Checks that 2 vectors read from the 2 buffers are the same in chunks
#[allow(clippy::cognitive_complexity)]
fn chunked_ensure_unchanged_vec<C: AffineCurve>(
    before: &mut [u8],
    after: &mut [u8],
    batch_size: usize,
    kind: &InvariantKind,
) -> Result<()> {
    let span = info_span!("unchanged_vec");
    let _enter = span.enter();
    debug!("starting...");

    let len_before = before.len() / C::SERIALIZED_SIZE;
    let len_after = after.len() / C::SERIALIZED_SIZE;
    ensure_unchanged(len_before, len_after, kind.clone())?;

    let before = &mut std::io::Cursor::new(before);
    let after = &mut std::io::Cursor::new(after);

    let iters = len_before / batch_size;
    let leftovers = len_before % batch_size;
    for i in 0..iters {
        let span1 = info_span!("iter", i);
        let _enter = span1.enter();

        let (els_before, els_after) = read_batch::<C, _>(before, after, batch_size)?;
        ensure_unchanged_vec(&els_before, &els_after, kind)?;

        trace!("ok");
    }

    // in case the batch size did not evenly divide the number of queries
    if leftovers > 0 {
        let span1 = info_span!("iter", i = iters);
        let _enter = span1.enter();

        let (els_before, els_after) = read_batch::<C, _>(before, after, leftovers)?;
        ensure_unchanged_vec(&els_before, &els_after, kind)?;

        trace!("ok");
    }

    debug!("done.");

    Ok(())
}

/// Checks that 2 vectors read from the 2 buffers are the same in chunks
fn chunked_check_ratio<E: PairingEngine>(
    before: &mut [u8],
    before_delta_g2: E::G2Affine,
    after: &mut [u8],
    after_delta_g2: E::G2Affine,
    batch_size: usize,
    err: &'static str,
) -> Result<()> {
    let span = info_span!("check_ratio");
    let _enter = span.enter();
    debug!("starting...");

    // read total length
    let len_before = before.len() / E::G1Affine::SERIALIZED_SIZE;
    let len_after = after.len() / E::G1Affine::SERIALIZED_SIZE;
    if len_before != len_after {
        return Err(Phase2Error::InvalidLength.into());
    }

    let before = &mut std::io::Cursor::new(before);
    let after = &mut std::io::Cursor::new(after);

    let iters = len_before / batch_size;
    let leftovers = len_before % batch_size;
    for _ in 0..iters {
        let (els_before, els_after) = read_batch::<E::G1Affine, _>(before, after, batch_size)?;
        let pairs = merge_pairs(&els_before, &els_after);
        check_same_ratio::<E>(&pairs, &(after_delta_g2, before_delta_g2), err)?;
    }
    // in case the batch size did not evenly divide the number of queries
    if leftovers > 0 {
        let (els_before, els_after) = read_batch::<E::G1Affine, _>(before, after, leftovers)?;
        let pairs = merge_pairs(&els_before, &els_after);
        check_same_ratio::<E>(&pairs, &(after_delta_g2, before_delta_g2), err)?;
    }

    debug!("done.");

    Ok(())
}

fn read_batch<C: AffineCurve, B: Read + Write + Seek>(
    before: &mut B,
    after: &mut B,
    batch_size: usize,
) -> Result<(Vec<C>, Vec<C>)> {
    let els_before = (0..batch_size)
        .map(|_| CanonicalDeserialize::deserialize(before))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    let els_after = (0..batch_size)
        .map(|_| CanonicalDeserialize::deserialize(after))
        .collect::<std::result::Result<Vec<_>, _>>()?;
    Ok((els_before, els_after))
}

type SplitBuf<'a> = (&'a mut [u8], &'a mut [u8], &'a mut [u8], &'a mut [u8], &'a mut [u8]);

/// splits the transcript from phase 1 after it's been prepared and converted to coefficient form
fn split_transcript<E: PairingEngine>(input: &mut [u8]) -> Result<SplitBuf> {
    // A, bg1, bg2, h, l
    let len_size = u64::SERIALIZED_SIZE;
    let a_g1_length = u64::deserialize(&mut &*input)? as usize;
    let (a_g1, others) = input[len_size..].split_at_mut(a_g1_length * E::G1Affine::SERIALIZED_SIZE);

    let b_g1_length = u64::deserialize(&mut &*others)? as usize;
    let (b_g1, others) = others[len_size..].split_at_mut(b_g1_length * E::G1Affine::SERIALIZED_SIZE);

    let b_g2_length = u64::deserialize(&mut &*others)? as usize;
    let (b_g2, others) = others[len_size..].split_at_mut(b_g2_length * E::G2Affine::SERIALIZED_SIZE);

    let h_g1_length = u64::deserialize(&mut &*others)? as usize;
    let (h_g1, others) = others[len_size..].split_at_mut(h_g1_length * E::G1Affine::SERIALIZED_SIZE);

    let l_g1_length = u64::deserialize(&mut &*others)? as usize;
    let (l_g1, _) = others[len_size..].split_at_mut(l_g1_length * E::G1Affine::SERIALIZED_SIZE);

    Ok((a_g1, b_g1, b_g2, h_g1, l_g1))
}
