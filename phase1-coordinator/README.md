# phase1-coordinator

## Overview

The coordinator is instantiated by calling `Coordinator::new` with an `Environment` struct that contains a set of parameters in [environment.rs](./src/environment.rs).
Once instantiated, the ceremony is initialized by calling `Coordinator::initialize` to run initialization
of round 0 and perform a transition to round 1.

Once initialized, the queue is opened up to contributors and verifiers, who may be added to and removed from the queue
by calling `Coordinator::add_to_queue` and `Coordinator::remove_from_queue` respectively.
Once operational, the coordinator state is updated periodically with a call to `Coordinator::update`, which updates the queue,
checks for dropped participants, determines if any participants meet the preset ban criteria, and monitors whether the next round is ready.

Contributors and verifiers must acquire a lock for a chunk by calling `Coordinator::try_lock` in order to update the state of a chunk.
The coordinator manages the locks held by the current contributors and verifiers, and is responsible for assigning chunks to the
round participants. When a lock is successfully acquired by a participant, the coordinator initializes the corresponding storage file
for the intended participant to upload to.

Contributors are able to contribute a chunk by calling `Coordinator::try_contribute`, which will check that the contributor
is authorized for the current round and performs rudimentary sanity checks that their contribution is valid.
Verifiers are then assigned chunks for verification, and can verify a chunk by calling `Coordinator::try_verify`, which will
check that the verifier is authorized for the current round and that the verification is uploaded. It should be noted that
verifiers are in the same trust model as the coordinator.

Once the current round is complete, the coordinator is able to advance to the next round by calling `Coordinator::try_advance`.
This command will lock the queue, and begin the prepare commit phase for transitioning to the next round. Once aggregation is complete,
the coordinator commits to the next round and the ceremony advances by one round. If the coordinator fails to aggregate the current round,
the commit is rolled back to the current round and all participants assigned to the next round are returned to the queue.

See the documentation in [lib.rs](./src/lib.rs) as an entry point to a more
detailed explanation of how this library works.

## Build Guide

To start the coordinator, run:
```
cargo run --release
```

## Testing

To compile and run the test suite, run:
```
cargo test
```

### Logging

Logging is enabled by default during tests. Use `RUST_LOG` env variable to configure
the log levels:
```bash
RUST_LOG=debug cargo test
```

Default log level is `error`. To completely hide the logs use:
```bash
RUST_LOG=none cargo test
```

### Serial Test Execution

By convention, all tests execute serially to minimize possible risk of writing over test storage.

