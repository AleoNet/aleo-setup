use crate::{
    objects::{participant::*, Contribution},
    CoordinatorError,
};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use serde_aux::prelude::*;
use serde_diff::SerdeDiff;
use std::collections::BTreeMap;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, SerdeDiff)]
#[serde(rename_all = "camelCase")]
pub struct Chunk {
    #[serde(deserialize_with = "deserialize_number_from_string")]
    chunk_id: u64,
    lock_holder: Option<Participant>,
    #[serde_diff(opaque)]
    contributions: BTreeMap<u64, Contribution>,
}

impl Chunk {
    ///
    /// Creates a new instance of `Chunk`.
    ///
    /// Checks that the given participant is a verifier,
    /// as this function is intended for use to initialize
    /// a new round by the coordinator.
    ///
    /// This function creates one contribution with a
    /// contribution ID of `0`.
    ///
    #[inline]
    pub fn new(
        chunk_id: u64,
        participant: Participant,
        verifier_locator: String,
        verifier_signature_locator: String,
    ) -> Result<Self, CoordinatorError> {
        match participant.is_verifier() {
            // Construct the starting contribution template for this chunk.
            true => Ok(Self {
                chunk_id,
                lock_holder: None,
                contributions: [(
                    0,
                    Contribution::new_verifier(0, participant, verifier_locator, verifier_signature_locator)?,
                )]
                .iter()
                .cloned()
                .collect(),
            }),
            false => Err(CoordinatorError::ExpectedVerifier),
        }
    }

    /// Returns the assigned ID of this chunk.
    #[inline]
    pub fn chunk_id(&self) -> u64 {
        self.chunk_id
    }

    /// Returns the lock holder of this chunk, if the chunk is locked.
    /// Otherwise, returns `None`.
    #[allow(dead_code)]
    #[inline]
    pub fn lock_holder(&self) -> &Option<Participant> {
        &self.lock_holder
    }

    /// Returns `true` if this chunk is locked. Otherwise, returns `false`.
    #[inline]
    pub fn is_locked(&self) -> bool {
        self.lock_holder.is_some()
    }

    /// Returns `true` if this chunk is unlocked. Otherwise, returns `false`.
    #[allow(dead_code)]
    #[inline]
    pub fn is_unlocked(&self) -> bool {
        !self.is_locked()
    }

    /// Returns `true` if this chunk is locked by the given participant.
    /// Otherwise, returns `false`.
    #[inline]
    pub fn is_locked_by(&self, participant: &Participant) -> bool {
        // Check that the chunk is locked.
        if self.is_unlocked() {
            return false;
        }

        // Retrieve the current lock holder, or return `false` if the chunk is unlocked.
        match &self.lock_holder {
            Some(lock_holder) => *lock_holder == *participant,
            None => false,
        }
    }

    /// Returns a reference to the current contribution in this chunk,
    /// irrespective of the state of the contribution.
    #[inline]
    pub fn current_contribution(&self) -> Result<&Contribution, CoordinatorError> {
        self.get_contribution(self.current_contribution_id())
    }

    /// Returns a reference to a contribution given a contribution ID.
    #[inline]
    pub fn get_contribution(&self, contribution_id: u64) -> Result<&Contribution, CoordinatorError> {
        match self.contributions.get(&contribution_id) {
            Some(contribution) => Ok(contribution),
            _ => Err(CoordinatorError::ContributionMissing),
        }
    }

    /// Returns a reference to a list of contributions in this chunk.
    #[inline]
    pub fn get_contributions(&self) -> &BTreeMap<u64, Contribution> {
        &self.contributions
    }

    ///
    /// Returns the current contribution ID in this chunk.
    ///
    /// This function returns the ID corresponding to the latest contributed
    /// or verified contribution that is stored with the coordinator.
    ///
    /// This function does NOT consider the state of the current contribution.
    ///
    #[inline]
    pub fn current_contribution_id(&self) -> u64 {
        (self.contributions.len() - 1) as u64
    }

    ///
    /// Returns `true` if the given next contribution ID is valid, based on the
    /// given expected number of contributions as a basis for computing it.
    ///
    /// This function does NOT consider the *verified status* of the current contribution.
    ///
    /// If the contributions are complete, returns `false`.
    ///
    #[inline]
    pub fn is_next_contribution_id(&self, next_contribution_id: u64, expected_contributions: u64) -> bool {
        // Check that the current and next contribution ID differ by 1.
        let current_contribution_id = self.current_contribution_id();
        if current_contribution_id + 1 != next_contribution_id {
            return false;
        }

        // Check if the contributions for this chunk are complete.
        if self.only_contributions_complete(expected_contributions) {
            return false;
        }

        // Check that this chunk is not yet complete. If so, it means there is
        // no more contribution IDs to increment on here. The coordinator should
        // start the next round and reset the contribution ID.
        if self.is_complete(expected_contributions) {
            return false;
        }

        true
    }

    ///
    /// Returns the next contribution ID for this chunk.
    ///
    /// This function uses the given expected number of contributions
    /// to determine whether this chunk contains all contributions yet.
    ///
    /// This function should be called only when a contributor intends
    /// to acquire the lock for this chunk and compute the next contribution.
    ///
    /// This function should NOT be called when attempting to poll or query
    /// for the state of this chunk, as it is too restrictive for such purposes.
    ///
    /// If the current contribution is not verified,
    /// this function returns a `CoordinatorError`.
    ///
    /// If the contributions are complete,
    /// this function returns a `CoordinatorError`.
    ///
    #[inline]
    pub fn next_contribution_id(&self, expected_contributions: u64) -> Result<u64, CoordinatorError> {
        // Fetch the current contribution.
        let current_contribution = self.current_contribution()?;

        // Check if the current contribution is verified.
        if !current_contribution.is_verified() {
            return Err(CoordinatorError::ContributionMissingVerification);
        }

        // Check if all contributions in this chunk are present.
        match !self.only_contributions_complete(expected_contributions) {
            true => Ok(self.current_contribution_id() + 1),
            false => Err(CoordinatorError::ContributionsComplete),
        }
    }

    ///
    /// Returns `true` if the current number of contributions in this chunk
    /// matches the given expected number of contributions. Otherwise,
    /// returns `false`.
    ///
    /// Note that this does NOT mean the contributions in this chunk have
    /// been verified. To account for that, use `Chunk::is_complete`.
    ///
    #[inline]
    pub(crate) fn only_contributions_complete(&self, expected_contributions: u64) -> bool {
        (self.contributions.len() as u64) == expected_contributions
    }

    ///
    /// Returns `true` if the given expected number of contributions for
    /// this chunk is complete and all contributions have been verified.
    /// Otherwise, returns `false`.
    ///
    #[inline]
    pub fn is_complete(&self, expected_contributions: u64) -> bool {
        // Check if the chunk is currently locked.
        if self.is_locked() {
            trace!("Chunk {} is locked and therefore not complete", self.chunk_id());
            return false;
        }

        // Check that all contributions and verifications are present.
        let contributions_complete = self.only_contributions_complete(expected_contributions);
        let verifications_complete = (self
            .get_contributions()
            .par_iter()
            .filter(|(_, contribution)| contribution.is_verified())
            .count() as u64)
            == expected_contributions;

        trace!(
            "Chunk {} contributions complete ({}) and verifications complete ({})",
            self.chunk_id(),
            contributions_complete,
            verifications_complete
        );

        contributions_complete && verifications_complete
    }

    ///
    /// Attempts to acquire the lock for the given participant.
    ///
    /// If the chunk is locked already, returns a `CoordinatorError`.
    ///
    /// If the chunk is already complete, returns a `CoordinatorError`.
    ///
    /// If the participant is a contributor, check that they have not
    /// contributed to this chunk before and that the current contribution
    /// is already verified.
    ///
    /// If the participant is a verifier, check that the current contribution
    /// has not been verified yet.
    ///
    #[inline]
    pub(crate) fn acquire_lock(
        &mut self,
        participant: Participant,
        expected_num_contributions: u64,
    ) -> Result<(), CoordinatorError> {
        // Check that this chunk is not locked before attempting to acquire the lock.
        if self.is_locked() {
            return Err(CoordinatorError::ChunkLockAlreadyAcquired);
        }

        // Check that this chunk is still incomplete before attempting to acquire the lock.
        if self.is_complete(expected_num_contributions) {
            trace!("{} {:#?}", expected_num_contributions, self);
            return Err(CoordinatorError::ChunkAlreadyComplete);
        }

        // If the participant is a contributor, check that they have not already contributed to this chunk before.
        if participant.is_contributor() {
            // Fetch all contributions with this contributor ID.
            let matches: Vec<_> = self
                .contributions
                .par_iter()
                .filter(|(_, contribution)| *contribution.get_contributor() == Some(participant.clone()))
                .collect();
            if !matches.is_empty() {
                return Err(CoordinatorError::ContributorAlreadyContributed);
            }

            // If the lock is currently held by this participant,
            // the current contributor ID is this contributor,
            // the current contributed location is empty,
            // and the current contribution is not verified,
            // then it could mean this contributor lost their
            // connection and is attempting to reconnect.
            //
            // In this case, no further action needs to be taken,
            // and we may return true.
            let contribution = self.current_contribution()?;
            if self.is_locked_by(&participant)
                && *contribution.get_contributor() == Some(participant.clone())
                && contribution.get_contributed_location().is_none()
                && !contribution.is_verified()
            {
                return Ok(());
            }

            // Check that the current contribution in this chunk has been verified.
            if !self.current_contribution()?.is_verified() {
                return Err(CoordinatorError::ChunkMissingVerification);
            }
        }

        // If the participant is a verifier, check that they have not already contributed to this chunk before.
        if participant.is_verifier() {
            // Check that the current contribution in this chunk has NOT been verified.
            if self.current_contribution()?.is_verified() {
                return Err(CoordinatorError::ChunkAlreadyVerified);
            }
        }

        // Set the lock holder as the participant.
        self.set_lock_holder(Some(participant));
        Ok(())
    }

    ///
    /// Attempts to add a new contribution from a contributor to this chunk.
    /// Upon success, releases the lock on this chunk to allow a verifier to
    /// check the contribution for correctness.
    ///
    /// This function is intended to be used only by an authorized contributor
    /// currently holding the lock on this chunk.
    ///
    /// If the operations succeed, returns `Ok(())`. Otherwise, returns `CoordinatorError`.
    ///
    #[inline]
    pub(crate) fn add_contribution(
        &mut self,
        contribution_id: u64,
        participant: &Participant,
        contributed_locator: String,
        contributed_signature_locator: String,
    ) -> Result<(), CoordinatorError> {
        // Check that the participant is a contributor.
        if !participant.is_contributor() {
            return Err(CoordinatorError::ExpectedContributor);
        }

        // Check that this chunk is locked by the contributor before attempting to add the contribution.
        if !self.is_locked_by(&participant) {
            return Err(CoordinatorError::ChunkNotLockedOrByWrongParticipant);
        }

        // Add the contribution to this chunk.
        self.contributions.insert(
            contribution_id,
            Contribution::new_contributor(participant.clone(), contributed_locator, contributed_signature_locator)?,
        );

        // Release the lock on this chunk from the contributor.
        self.set_lock_holder(None);

        Ok(())
    }

    ///
    /// Updates the contribution corresponding to the given contribution ID as verified.
    ///
    /// This function is intended to be called by an authorized verifier
    /// holding a lock on the chunk.
    ///
    /// The underlying function checks that the contribution has a verifier assigned to it.
    ///
    #[inline]
    pub(crate) fn verify_contribution(
        &mut self,
        contribution_id: u64,
        participant: Participant,
        verified_locator: String,
        verified_signature_locator: String,
    ) -> Result<(), CoordinatorError> {
        // Check that the participant is a verifier.
        if !participant.is_verifier() {
            return Err(CoordinatorError::ExpectedVerifier);
        }

        // Check that this chunk is locked by the verifier before attempting to verify contribution.
        if !self.is_locked_by(&participant) {
            return Err(CoordinatorError::ChunkNotLockedOrByWrongParticipant);
        }

        // Fetch the contribution to be verified from the chunk.
        let contribution = match self.contributions.get_mut(&contribution_id) {
            Some(contribution) => contribution,
            _ => return Err(CoordinatorError::ContributionMissing),
        };

        // Attempt to assign the verifier to the contribution.
        contribution.assign_verifier(participant.clone(), verified_locator, verified_signature_locator)?;

        // Attempt to verify the contribution.
        match contribution.is_verified() {
            // Case 1 - Check that the contribution is not verified yet.
            true => Err(CoordinatorError::ContributionAlreadyVerified),
            // Case 2 - If the contribution is not verified, attempt to set it to verified.
            false => {
                // Attempt set the contribution as verified.
                contribution.set_verified(&participant)?;

                // Release the lock on this chunk from the verifier.
                self.set_lock_holder(None);

                trace!("Verification of contribution {} succeeded", contribution_id);
                Ok(())
            }
        }
    }

    /// Removes the contribution corresponding to the given contribution ID.
    #[inline]
    pub(super) fn remove_contribution_unsafe(&mut self, contribution_id: u64) {
        warn!("Removed chunk {} contribution {}", self.chunk_id, contribution_id);
        self.contributions.remove(&contribution_id);
    }

    /// Sets the lock holder for this chunk as the given lock holder.
    #[inline]
    pub(crate) fn set_lock_holder_unsafe(&mut self, lock_holder: Option<Participant>) {
        warn!("Resetting the lock for chunk {} to {:?}", self.chunk_id, lock_holder);
        self.set_lock_holder(lock_holder);
    }

    /// Sets the lock holder for this chunk as the given lock holder.
    #[inline]
    fn set_lock_holder(&mut self, lock_holder: Option<Participant>) {
        self.lock_holder = lock_holder;
    }
}
