# Phase 1

Distributed generation of powers of tau for Phase 1 of [BGM17](https://eprint.iacr.org/2017/1050). 

Also contains a binary that converts the Powers of Tau to Lagrange coefficients and allows Phase 2 to produce efficient A, B and L queries for the Groth16 SNARK.

- Utilizes [Zexe's algebra crate](https://github.com/scipr-lab/zexe), meaning we support all available curves:
    - BLS12-377
    - BW6-761
    - ...
- Memory footprint can be configured by adjusting `batch-size` via CLI and via environment variable [`RAYON_NUM_THREADS`](https://github.com/rayon-rs/rayon/blob/master/FAQ.md#how-many-threads-will-rayon-spawn).

## Disclaimer

This is a fork of a [fork](https://github.com/kobigurk/phase2-bn254/)
of a [fork](https://github.com/matter-labs/powersoftau)
of a [fork](https://github.com/celo-org/snark-setup).
Credits go to all of the corresponding authors for producing the original implementations.

## License

This work is licensed under either of the following licenses, at your discretion.

- Apache License Version 2.0 (LICENSE-APACHE or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license (LICENSE-MIT or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you,
as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.
