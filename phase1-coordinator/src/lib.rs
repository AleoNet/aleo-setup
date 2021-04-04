#[macro_use]
extern crate tracing;

#[macro_use]
mod macros;

pub mod authentication;

pub(crate) mod commands;

pub mod coordinator;
pub use coordinator::*;

#[cfg(not(feature = "operator"))]
pub(crate) mod coordinator_state;
#[cfg(not(feature = "operator"))]
pub(crate) use coordinator_state::CoordinatorState;

#[cfg(feature = "operator")]
pub mod coordinator_state;
#[cfg(feature = "operator")]
pub use coordinator_state::CoordinatorState;

pub mod environment;

#[cfg(not(test))]
pub mod logger;

pub mod objects;
pub use objects::{ContributionFileSignature, ContributionState, Participant, Round};

mod serialize;

pub(crate) mod storage;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
pub mod tests;
