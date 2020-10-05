use crate::{environment::Environment, locators::Locator};

use std::path::Path;

#[derive(Debug)]
pub struct Remote;

impl Locator for Remote {
    /// Returns the transcript directory for a given round from the coordinator.
    fn round_directory(environment: &Environment, round_height: u64) -> String
    where
        Self: Sized,
    {
        let base_url = environment.base_url();
        match environment {
            Environment::Test(_) => format!("{}/test/round/{}", base_url, round_height),
            Environment::Development(_) => format!("{}/development/round/{}", base_url, round_height),
            Environment::Production(_) => format!("{}/round/{}", base_url, round_height),
        }
    }

    /// Initializes the round directory for a given environment and round height.
    fn round_directory_init(_environment: &Environment, _round_height: u64)
    where
        Self: Sized,
    {
        unimplemented!()
    }

    /// Returns `true` if the round directory for a given round height exists.
    /// Otherwise, returns `false`.
    fn round_directory_exists(environment: &Environment, round_height: u64) -> bool
    where
        Self: Sized,
    {
        let _url = Self::round_directory(environment, round_height);
        unimplemented!()
    }

    /// Resets the round directory for a given environment and round height.
    fn round_directory_reset(_environment: &Environment, _round_height: u64) {
        unimplemented!()
    }

    /// Resets the entire round directory for a given environment.
    fn round_directory_reset_all(_environment: &Environment) {
        unimplemented!()
    }

    /// Returns the chunk directory for a given round height and chunk ID from the coordinator.
    fn chunk_directory(environment: &Environment, round_height: u64, chunk_id: u64) -> String
    where
        Self: Sized,
    {
        // Create the transcript directory path.
        let url = Self::round_directory(environment, round_height);

        // Create the chunk directory as `{round_directory}/chunk/{chunk_id}`.
        format!("{}/chunk/{}", url, chunk_id)
    }

    /// Initializes the chunk directory for a given environment, round height, and chunk ID.
    fn chunk_directory_init(_environment: &Environment, _round_height: u64, _chunk_id: u64) {
        unimplemented!()
    }

    /// Returns `true` if the chunk directory for a given round height and chunk ID exists.
    /// Otherwise, returns `false`.
    fn chunk_directory_exists(environment: &Environment, round_height: u64, chunk_id: u64) -> bool
    where
        Self: Sized,
    {
        let path = Self::chunk_directory(environment, round_height, chunk_id);
        Path::new(&path).exists()
    }

    /// Returns the contribution locator for a given round, chunk ID, and
    /// contribution ID from the coordinator.
    fn contribution_locator(
        environment: &Environment,
        round_height: u64,
        chunk_id: u64,
        contribution_id: u64,
        verified: bool,
    ) -> String
    where
        Self: Sized,
    {
        // Fetch the chunk directory path.
        let path = Self::chunk_directory(environment, round_height, chunk_id);

        match verified {
            // Set the contribution locator as `{chunk_directory}/contribution/{contribution_id}.verified`.
            true => format!("{}/contribution/{}.verified", path, contribution_id),
            // Set the contribution locator as `{chunk_directory}/contribution/{contribution_id}.unverified`.
            false => format!("{}/contribution/{}.unverified", path, contribution_id),
        }
    }

    /// Initializes the contribution locator file for a given round, chunk ID, and
    /// contribution ID from the coordinator.
    fn contribution_locator_init(
        _environment: &Environment,
        _round_height: u64,
        _chunk_id: u64,
        _contribution_id: u64,
    ) {
        unimplemented!()
    }

    /// Returns `true` if the contribution locator for a given round height, chunk ID,
    /// and contribution ID exists. Otherwise, returns `false`.
    fn contribution_locator_exists(
        environment: &Environment,
        round_height: u64,
        chunk_id: u64,
        contribution_id: u64,
        verified: bool,
    ) -> bool
    where
        Self: Sized,
    {
        let path = Self::contribution_locator(environment, round_height, chunk_id, contribution_id, verified);
        Path::new(&path).exists()
    }

    /// Returns the round locator for a given round from the coordinator.
    fn round_locator(environment: &Environment, round_height: u64) -> String
    where
        Self: Sized,
    {
        // Create the transcript directory path.
        let path = Self::round_directory(environment, round_height);

        // Create the round locator located at `{round_directory}/round`.
        format!("{}/round", path)
    }

    /// Returns `true` if the round locator for a given round height exists.
    /// Otherwise, returns `false`.
    fn round_locator_exists(environment: &Environment, round_height: u64) -> bool
    where
        Self: Sized,
    {
        let path = Self::round_locator(environment, round_height);
        Path::new(&path).exists()
    }
}
