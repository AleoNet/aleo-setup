use crate::{
    errors::{Error, VerificationError},
    Result,
};

use snarkvm_algorithms::{cfg_into_iter, cfg_iter, cfg_iter_mut};
use snarkvm_curves::{AffineCurve, Group, PairingEngine, ProjectiveCurve};
use snarkvm_fields::{Field, One, PrimeField, Zero};
use snarkvm_utilities::{
    biginteger::BigInteger,
    rand::UniformRand,
    BitIteratorBE,
    CanonicalSerialize,
    ConstantSerializedSize,
};

use blake2::{Blake2b, Digest};
use rand::{rngs::OsRng, thread_rng, CryptoRng, Rng, SeedableRng};
use rand_chacha::ChaChaRng;
use std::{
    convert::TryInto,
    io::{self, Write},
    ops::AddAssign,
    sync::Arc,
};

#[cfg(not(feature = "wasm"))]
use sha2::Sha256;

#[cfg(feature = "parallel")]
use rayon::prelude::*;

/// Generate the powers by raising the key's `tau` to all powers
/// belonging to this chunk
pub fn generate_powers_of_tau<E: PairingEngine>(tau: &E::Fr, start: usize, end: usize) -> Vec<E::Fr> {
    // Uh no better way to do this, this should never fail
    let start: u64 = start.try_into().expect("could not convert to u64");
    let end: u64 = end.try_into().expect("could not convert to u64");
    cfg_into_iter!(start..end).map(|i| tau.pow([i])).collect()
}

pub fn print_hash(hash: &[u8]) {
    for line in hash.chunks(16) {
        print!("\t");
        for section in line.chunks(4) {
            for b in section {
                print!("{:02x}", b);
            }
            print!(" ");
        }
        println!();
    }
}

/// Multiply a large number of points by a scalar
pub fn batch_mul<C: AffineCurve>(bases: &mut [C], coeff: &C::ScalarField) -> Result<()> {
    let coeff = coeff.to_repr();
    let mut points: Vec<_> = cfg_iter!(bases)
        .map(|base| base.mul_bits(BitIteratorBE::new(coeff)))
        .collect();
    C::Projective::batch_normalization(points.as_mut_slice());
    cfg_iter_mut!(bases)
        .zip(points)
        .for_each(|(base, proj)| *base = proj.into_affine());

    Ok(())
}

/// Exponentiate a large number of points, with an optional coefficient to be applied to the
/// exponent.
pub fn batch_exp<C: AffineCurve>(
    bases: &mut [C],
    exps: &[C::ScalarField],
    coeff: Option<&C::ScalarField>,
) -> Result<()> {
    if bases.len() != exps.len() {
        return Err(Error::InvalidLength {
            expected: bases.len(),
            got: exps.len(),
        });
    }
    // raise the base to the exponent and assign it back to the base
    // this will return the points as projective
    let mut points: Vec<<C as AffineCurve>::Projective> = cfg_iter_mut!(bases)
        .zip(exps)
        .map(|(base, exp)| {
            // If a coefficient was provided, multiply the exponent
            // by that coefficient
            let mut exp = *exp;
            if let Some(coeff) = coeff {
                exp *= coeff;
            }
            // Raise the base to the exponent (additive notation so it is executed
            // via a multiplication)
            base.mul_bits(BitIteratorBE::new(exp.to_repr()))
        })
        .collect();
    // we do not use batch_normalization_into_affine because it allocates
    // a new vector
    C::Projective::batch_normalization(points.as_mut_slice());
    cfg_iter_mut!(bases)
        .zip(points)
        .for_each(|(base, proj)| *base = proj.into_affine());

    Ok(())
}

// Create an RNG based on a mixture of system randomness and user provided randomness
pub fn user_system_randomness() -> [u8; 64] {
    let mut system_rng = OsRng;
    let mut h = Blake2b::default();

    // Gather 1024 bytes of entropy from the system
    for _ in 0..1024 {
        let r: u8 = system_rng.gen();
        h.update(&[r]);
    }

    // Ask the user to provide some information for additional entropy
    let mut user_input = String::new();
    println!("Type some random text and press [ENTER] to provide additional entropy...");
    std::io::stdin()
        .read_line(&mut user_input)
        .expect("expected to read some random text from the user");

    // Hash it all up to make a seed
    h.update(&user_input.as_bytes());
    h.finalize().into()
}

#[allow(clippy::modulo_one)]
#[cfg(not(feature = "wasm"))]
pub fn beacon_randomness(mut beacon_hash: [u8; 32]) -> [u8; 32] {
    // Performs 2^n hash iterations over it
    const N: u64 = 10;

    for i in 0..(1u64 << N) {
        // Print 1024 of the interstitial states
        // so that verification can be
        // parallelized

        if i % (1u64 << (N - 10)) == 0 {
            print!("{}: ", i);
            for b in beacon_hash.iter() {
                print!("{:02x}", b);
            }
            println!();
        }

        let mut h = Sha256::new();
        h.update(&beacon_hash);
        let result = h.finalize();
        beacon_hash.copy_from_slice(&result);
    }

    print!("Final result of beacon: ");
    for b in beacon_hash.iter() {
        print!("{:02x}", b);
    }
    println!();

    beacon_hash
}

/// Interpret the first 32 bytes of the digest as 8 32-bit words
pub fn get_rng(digest: &[u8]) -> impl Rng + CryptoRng {
    let seed = from_slice(digest);
    ChaChaRng::from_seed(seed)
}

/// Gets the number of bits of the provided type
pub const fn num_bits<T>() -> usize {
    std::mem::size_of::<T>() * 8
}

pub fn log_2(x: usize) -> usize {
    assert!(x > 0);
    num_bits::<usize>() - (x.leading_zeros() as usize) - 1
}

/// Abstraction over a writer which hashes the data being written.
pub struct HashWriter<W: Write> {
    writer: W,
    hasher: Blake2b,
}

impl Clone for HashWriter<io::Sink> {
    fn clone(&self) -> HashWriter<io::Sink> {
        HashWriter {
            writer: io::sink(),
            hasher: self.hasher.clone(),
        }
    }
}

impl<W: Write> HashWriter<W> {
    /// Construct a new `HashWriter` given an existing `writer` by value.
    pub fn new(writer: W) -> Self {
        HashWriter {
            writer,
            hasher: Blake2b::default(),
        }
    }

    /// Destroy this writer and return the hash of what was written.
    pub fn into_hash(self) -> [u8; 64] {
        self.hasher.finalize().into()
    }
}

impl<W: Write> Write for HashWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let bytes = self.writer.write(buf)?;

        if bytes > 0 {
            self.hasher.update(&buf[0..bytes]);
        }

        Ok(bytes)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

/// Calculate the contribution hash from the resulting file. Original powers of tau implementation
/// used a specially formed writer to write to the file and calculate a hash on the fly, but memory-constrained
/// implementation now writes without a particular order, so plain recalculation at the end
/// of the procedure is more efficient
pub fn calculate_hash(input_map: &[u8]) -> [u8; 64] {
    let chunk_size = 1 << 30; // read by 1GB from map
    let mut hasher = Blake2b::default();
    for chunk in input_map.chunks(chunk_size) {
        hasher.update(&chunk);
    }
    hasher.finalize().into()
}

pub fn hash_to_g2<E: PairingEngine>(digest: &[u8]) -> E::G2Projective {
    let seed = from_slice(digest);
    let mut rng = ChaChaRng::from_seed(seed);
    loop {
        let bytes: Vec<u8> = (0..E::G2Affine::SERIALIZED_SIZE).map(|_| rng.gen()).collect();
        if let Some(p) = E::G2Affine::from_random_bytes(&bytes) {
            let scaled = p.mul_by_cofactor_to_projective();
            if !scaled.is_zero() {
                return scaled;
            }
        }
    }
}

pub fn from_slice(bytes: &[u8]) -> [u8; 32] {
    let mut array = [0; 32];
    let bytes = &bytes[..array.len()]; // panics if not enough data
    array.copy_from_slice(bytes);
    array
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ops::Mul;
    use snarkvm_curves::bls12_377::{Bls12_377, Fr, G1Affine, G2Affine};

    #[test]
    fn test_hash_to_g2() {
        test_hash_to_g2_curve::<Bls12_377>();
    }

    fn test_hash_to_g2_curve<E: PairingEngine>() {
        assert!(
            hash_to_g2::<E>(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                29, 30, 31, 32, 33
            ]) == hash_to_g2::<E>(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                29, 30, 31, 32, 34
            ])
        );

        assert!(
            hash_to_g2::<E>(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                29, 30, 31, 32
            ]) != hash_to_g2::<E>(&[
                1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28,
                29, 30, 31, 33
            ])
        );
    }

    #[test]
    fn test_same_ratio() {
        let rng = &mut thread_rng();

        let s = Fr::rand(rng);
        let g1 = G1Affine::prime_subgroup_generator();
        let g2 = G2Affine::prime_subgroup_generator();
        let g1_s = g1.mul(s);
        let g2_s = g2.mul(s);

        assert!(same_ratio::<Bls12_377>(&(g1, g1_s), &(g2, g2_s)));
        assert!(!same_ratio::<Bls12_377>(&(g1_s, g1), &(g2, g2_s)));
    }

    #[test]
    fn test_power_pairs() {
        use std::ops::MulAssign;
        let rng = &mut thread_rng();

        let mut v = vec![];
        let x = Fr::rand(rng);
        let mut acc = Fr::one();
        for _ in 0..100 {
            v.push(G1Affine::prime_subgroup_generator().mul(acc));
            acc.mul_assign(&x);
        }

        let gx = G2Affine::prime_subgroup_generator().mul(x);

        assert!(same_ratio::<Bls12_377>(
            &power_pairs(&v),
            &(G2Affine::prime_subgroup_generator(), gx)
        ));

        v[1] = v[1].mul(Fr::rand(rng));

        assert!(!same_ratio::<Bls12_377>(
            &power_pairs(&v),
            &(G2Affine::prime_subgroup_generator(), gx)
        ));
    }
}

pub fn merge_pairs<G: AffineCurve>(v1: &[G], v2: &[G]) -> (G, G) {
    assert_eq!(v1.len(), v2.len());
    let rng = &mut thread_rng();

    let randomness: Vec<<G::ScalarField as PrimeField>::BigInteger> =
        (0..v1.len()).map(|_| G::ScalarField::rand(rng).to_repr()).collect();

    let s = dense_multiexp(&v1, &randomness[..]).into_affine();
    let sx = dense_multiexp(&v2, &randomness[..]).into_affine();

    (s, sx)
}

/// Construct a single pair (s, s^x) for a vector of
/// the form [1, x, x^2, x^3, ...].
pub fn power_pairs<G: AffineCurve>(v: &[G]) -> (G, G) {
    merge_pairs(&v[0..(v.len() - 1)], &v[1..])
}

/// Compute BLAKE2b("")
pub fn blank_hash() -> [u8; 64] {
    Blake2b::new().finalize().into()
}

pub fn reduced_hash(old_power: u8, new_power: u8) -> [u8; 64] {
    let mut hasher = Blake2b::new();
    hasher.update(&[old_power, new_power]);
    hasher.finalize().into()
}

/// Checks if pairs have the same ratio.
/// Under the hood uses pairing to check
/// x1/x2 = y1/y2 => x1*y2 = x2*y1
pub fn same_ratio<E: PairingEngine>(g1: &(E::G1Affine, E::G1Affine), g2: &(E::G2Affine, E::G2Affine)) -> bool {
    E::pairing(g1.0, g2.1) == E::pairing(g1.1, g2.0)
}

pub fn check_same_ratio<E: PairingEngine>(
    g1: &(E::G1Affine, E::G1Affine),
    g2: &(E::G2Affine, E::G2Affine),
    err: &'static str,
) -> Result<()> {
    if E::pairing(g1.0, g2.1) != E::pairing(g1.1, g2.0) {
        return Err(VerificationError::InvalidRatio(err).into());
    }
    Ok(())
}

/// Compute BLAKE2b(personalization | transcript | g^s | g^{s*x})
/// and then hash it to G2
pub fn compute_g2_s<E: PairingEngine>(
    digest: &[u8],
    g1_s: &E::G1Affine,
    g1_s_x: &E::G1Affine,
    personalization: u8,
) -> Result<E::G2Affine> {
    let mut h = Blake2b::default();
    h.update(&[personalization]);
    h.update(digest);
    let size = E::G1Affine::SERIALIZED_SIZE;
    let mut data = vec![0; 2 * size];
    g1_s.serialize(&mut &mut data[..size])?;
    g1_s_x.serialize(&mut &mut data[size..])?;
    h.update(&data);
    Ok(hash_to_g2::<E>(h.finalize().as_ref()).into_affine())
}

/// Perform multi-exponentiation. The caller is responsible for ensuring that
/// the number of bases is the same as the number of exponents.
#[allow(dead_code)]
pub fn dense_multiexp<G: AffineCurve>(
    bases: &[G],
    exponents: &[<G::ScalarField as PrimeField>::BigInteger],
) -> G::Projective {
    if exponents.len() != bases.len() {
        panic!("invalid length")
    }
    let c = if exponents.len() < 32 {
        3u32
    } else {
        (f64::from(exponents.len() as u32)).ln().ceil() as u32
    };

    dense_multiexp_inner(bases, exponents, 0, c, true)
}

fn dense_multiexp_inner<G: AffineCurve>(
    bases: &[G],
    exponents: &[<G::ScalarField as PrimeField>::BigInteger],
    mut skip: u32,
    c: u32,
    handle_trivial: bool,
) -> <G as AffineCurve>::Projective {
    let zero = G::ScalarField::zero().to_repr();
    let one = G::ScalarField::one().to_repr();
    use std::sync::Mutex;
    // Perform this region of the multiexp. We use a different strategy - go over region in parallel,
    // then over another region, etc. No Arc required
    let chunk = (bases.len() / num_cpus::get()) + 1;
    let this = {
        // let mask = (1u64 << c) - 1u64;
        let this_region = Mutex::new(G::Projective::zero());
        let arc = Arc::new(this_region);
        crossbeam::scope(|scope| {
            for (base, exp) in bases.chunks(chunk).zip(exponents.chunks(chunk)) {
                let this_region_rwlock = arc.clone();
                // let handle =
                scope.spawn(move |_| {
                    let mut buckets = vec![<G as AffineCurve>::Projective::zero(); (1 << c) - 1];
                    // Accumulate the result
                    let mut acc = G::Projective::zero();

                    for (base, &exp) in base.iter().zip(exp.iter()) {
                        // let index = (exp.as_ref()[0] & mask) as usize;

                        // if index != 0 {
                        //     buckets[index - 1].add_assign_mixed(base);
                        // }

                        // exp.shr(c as u32);

                        if exp != zero {
                            if exp == one {
                                if handle_trivial {
                                    acc.add_assign_mixed(base);
                                }
                            } else {
                                let mut exp = exp;
                                exp.divn(skip);
                                let exp = exp.as_ref()[0] % (1 << c);
                                if exp != 0 {
                                    buckets[(exp - 1) as usize].add_assign_mixed(base);
                                }
                            }
                        }
                    }

                    // buckets are filled with the corresponding accumulated value, now sum
                    let mut running_sum = G::Projective::zero();
                    for exp in buckets.into_iter().rev() {
                        running_sum += &exp;
                        acc += &running_sum;
                    }

                    let mut guard = this_region_rwlock.lock().expect("poisoned");

                    *guard += &acc;
                });
            }
        })
        .expect("dense_multiexp failed");

        let this_region = Arc::try_unwrap(arc).unwrap();

        this_region.into_inner().unwrap()
    };

    skip += c;

    if skip >= <G::ScalarField as PrimeField>::size_in_bits() as u32 {
        // There isn't another region, and this will be the highest region
        this
    } else {
        // next region is actually higher than this one, so double it enough times
        let mut next_region = dense_multiexp_inner(bases, exponents, skip, c, false);
        for _ in 0..c {
            next_region = next_region.double();
        }

        next_region.add_assign(&this);

        next_region
    }
}
