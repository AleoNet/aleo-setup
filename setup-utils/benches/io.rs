use setup_utils::{BatchDeserializer, BatchSerializer, UseCompression};

use snarkos_curves::bls12_377::Bls12_377;
use snarkos_models::curves::{AffineCurve, PairingEngine};

use criterion::{criterion_group, criterion_main, Criterion, Throughput};

/// Benchmark comparing reading compressed/uncompressed points
/// with preallocated vectors and allocating new vectors each time.
/// Preliminary results show:
/// - reading compressed elements is MUCH slower than uncompressed
/// - preallocated is obviously always faster
/// - parallel compressed is faster than serial compressed
/// - serial uncompressed is faster than parallel uncompressed, this is probably because
///   the bottleneck for reading compressed elements is the subgroup check and the calculation of
///   `y`, allowing for more gains via the parallelization. Deserializing uncompressed elements has
///   no computational bottleneck, hence the parallelism ends up introducing more overhead than benefit
fn read<C: AffineCurve>(c: &mut Criterion, el_type: &str) {
    let mut group = c.benchmark_group(format!("read_batched_{}", el_type));
    group.sample_size(10);
    let els = (10..14).map(|i| 2u32.pow(i) as usize).collect::<Vec<usize>>();

    for compression in &[UseCompression::Yes, UseCompression::No] {
        for num_els in &els {
            group.throughput(Throughput::Elements(*num_els as u64));

            let (_, buf) = random_vec_buf::<C>(*num_els, *compression);
            group.bench_with_input(format!("normal_{}", compression), &num_els, |b, _num_els| {
                b.iter(|| buf.read_batch::<C>(*compression).unwrap());
            });

            let (mut elements, buf) = random_vec_buf(*num_els, *compression);
            group.bench_with_input(format!("preallocated_{}", compression), &num_els, |b, _num_els| {
                b.iter(|| buf.read_batch_preallocated::<C>(&mut elements, *compression).unwrap());
            });
        }
    }
}

/// Benchmark comparing writing compressed/uncompressed points in parallel & serial
/// The trait's write_batch uses a serial iterator for buffers up to 512 elements (heuristic)
/// and then switches to parallel
/// We observe that after ~512 element buffers, the parallel version starts to take over
fn write<C: AffineCurve>(c: &mut Criterion, el_type: &str) {
    let mut group = c.benchmark_group(format!("write_batched_{}", el_type));
    let els = (10..14).map(|i| 2u32.pow(i) as usize).collect::<Vec<usize>>();
    group.sample_size(10);
    for compression in &[UseCompression::Yes, UseCompression::No] {
        for num_els in &els {
            let (elements, mut buf) = random_vec_empty_buf(*num_els, *compression);

            group.throughput(Throughput::Elements(*num_els as u64));

            group.bench_with_input(format!("{}", compression), &num_els, |b, _num_els| {
                b.iter(|| buf.write_batch::<C>(&elements, *compression).unwrap());
            });
        }
    }
    group.finish()
}

fn read_curve<E: PairingEngine>(c: &mut Criterion) {
    read::<E::G1Affine>(c, "g1");
    read::<E::G2Affine>(c, "g2");
}

fn read_bls12_377(c: &mut Criterion) {
    read_curve::<Bls12_377>(c);
}

fn write_curve<E: PairingEngine>(c: &mut Criterion) {
    write::<E::G1Affine>(c, "g1");
    write::<E::G2Affine>(c, "g2");
}

fn write_bls12_377(c: &mut Criterion) {
    write_curve::<Bls12_377>(c);
}

criterion_group!(benches, read_bls12_377, write_bls12_377);
criterion_main!(benches);
