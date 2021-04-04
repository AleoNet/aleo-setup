#[cfg(any(test, feature = "operator"))]
use crate::coordinator::CoordinatorError;

use serde::{Deserialize, Serialize};
use serde_diff::SerdeDiff;

///
/// The contribution state for a given chunk ID that is signed by the participant.
///
/// This state is comprised of:
/// 1. The hash of the challenge file.
/// 2. The hash of the response file.
/// 3. The hash of the next challenge file if the participant was a verifier.
///
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, SerdeDiff)]
#[serde(rename_all = "camelCase")]
pub struct ContributionState {
    /// The hash of the challenge file.
    challenge_hash: String,
    /// The hash of the response file.
    response_hash: String,
    /// The hash of the next challenge file.
    #[serde(skip_serializing_if = "Option::is_none")]
    next_challenge_hash: Option<String>,
}

#[cfg(any(test, feature = "operator"))]
impl ContributionState {
    /// Creates a new instance of `ContributionFileSignature`.
    #[inline]
    pub fn new(
        challenge_hash: Vec<u8>,
        response_hash: Vec<u8>,
        next_challenge_hash: Option<Vec<u8>>,
    ) -> Result<Self, CoordinatorError> {
        // Check that the challenge hash is 64 bytes.
        if challenge_hash.len() != 64 {
            return Err(CoordinatorError::ChallengeHashSizeInvalid);
        }

        // Check that the response hash is 64 bytes.
        if response_hash.len() != 64 {
            return Err(CoordinatorError::ResponseHashSizeInvalid);
        }

        // Check that the next challenge hash is 64 bytes, if it exists.
        if let Some(next_challenge_hash) = &next_challenge_hash {
            if next_challenge_hash.len() != 64 {
                return Err(CoordinatorError::NextChallengeHashSizeInvalid);
            }
        }

        Ok(ContributionState {
            challenge_hash: hex::encode(challenge_hash),
            response_hash: hex::encode(response_hash),
            next_challenge_hash: next_challenge_hash.map(|h| hex::encode(h)),
        })
    }

    /// Returns the message that should be signed for the `ContributionFileSignature`.
    #[inline]
    pub fn signature_message(&self) -> Result<String, CoordinatorError> {
        Ok(serde_json::to_string(&self)?)
    }
}

///
/// The signature and state of the contribution.
///
#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize, SerdeDiff)]
pub struct ContributionFileSignature {
    /// The signature of the contribution state.
    signature: String,
    /// The state of the contribution that is signed.
    state: ContributionState,
}

impl ContributionFileSignature {
    /// Creates a new instance of `ContributionFileSignature`.
    #[cfg(any(test, feature = "operator"))]
    #[inline]
    pub fn new(signature: String, state: ContributionState) -> Result<Self, CoordinatorError> {
        debug!("Starting to create contribution signature");
        // Check that the signature is 64 bytes.
        if hex::decode(&signature)?.len() != 64 {
            return Err(CoordinatorError::ContributionSignatureSizeMismatch);
        }
        debug!("Completed creating contribution signature");
        Ok(Self { signature, state })
    }

    /// Returns a reference to the signature.
    #[inline]
    pub fn get_signature(&self) -> &str {
        &self.signature
    }

    /// Returns a reference to the contribution state.
    #[inline]
    pub fn get_state(&self) -> &ContributionState {
        &self.state
    }

    /// Returns a reference to the challenge hash.
    #[inline]
    pub fn get_challenge_hash(&self) -> &str {
        &self.state.challenge_hash
    }

    /// Returns a reference to the response hash.
    #[inline]
    pub fn get_response_hash(&self) -> &str {
        &self.state.response_hash
    }

    /// Returns a reference to the next challenge hash, if it exists.
    /// Otherwise, returns `None`.
    #[inline]
    pub fn get_next_challenge_hash(&self) -> &Option<String> {
        &self.state.next_challenge_hash
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use setup_utils::calculate_hash;

    #[test]
    pub fn test_contribution_signature() {
        // Construct the dummy challenge, response, and next_challenge files.
        let dummy_challenge = vec![1; 128];
        let dummy_response = vec![2; 128];
        let dummy_next_challenge = vec![3; 128];

        // Calculate the contribution hashes.
        let challenge_hash = calculate_hash(&dummy_challenge);
        let response_hash = calculate_hash(&dummy_response);
        let next_challenge_hash = calculate_hash(&dummy_next_challenge);

        // Construct the contribution state
        let contribution_state = ContributionState::new(
            challenge_hash.to_vec(),
            response_hash.to_vec(),
            Some(next_challenge_hash.to_vec()),
        )
        .unwrap();

        // Construct a dummy signature.
        let signature = vec![4u8; 64];
        let signature_string = hex::encode(signature);

        // Construct the contribution file signature.
        let contribution_signature = ContributionFileSignature::new(signature_string.clone(), contribution_state);

        assert!(contribution_signature.is_ok())
    }

    #[test]
    pub fn test_contribution_signature_invalid_signature_size() {
        // Construct the dummy challenge, response, and next_challenge files.
        let dummy_challenge = vec![1; 128];
        let dummy_response = vec![2; 128];
        let dummy_next_challenge = vec![3; 128];

        // Calculate the contribution hashes.
        let challenge_hash = calculate_hash(&dummy_challenge);
        let response_hash = calculate_hash(&dummy_response);
        let next_challenge_hash = calculate_hash(&dummy_next_challenge);

        // Construct the contribution state
        let contribution_state = ContributionState::new(
            challenge_hash.to_vec(),
            response_hash.to_vec(),
            Some(next_challenge_hash.to_vec()),
        )
        .unwrap();

        // Construct an invalid signature.
        let signature = vec![4u8; 48];
        let signature_string = hex::encode(signature);

        // Construct the contribution file signature.
        let contribution_signature = ContributionFileSignature::new(signature_string.clone(), contribution_state);

        assert!(contribution_signature.is_err())
    }

    #[test]
    pub fn test_contribution_signature_invalid_challenge_hash_size() {
        // Construct the dummy response and next_challenge files.
        let dummy_response = vec![2; 128];
        let dummy_next_challenge = vec![3; 128];

        // Calculate the contribution hashes.
        let invalid_challenge_hash = vec![1; 48];
        let response_hash = calculate_hash(&dummy_response);
        let next_challenge_hash = calculate_hash(&dummy_next_challenge);

        // Construct the contribution state
        let contribution_state = ContributionState::new(
            invalid_challenge_hash,
            response_hash.to_vec(),
            Some(next_challenge_hash.to_vec()),
        );

        assert!(contribution_state.is_err())
    }

    #[test]
    pub fn test_contribution_signature_invalid_response_hash_size() {
        // Construct the dummy challenge and next_challenge files.
        let dummy_challenge = vec![1; 128];
        let dummy_next_challenge = vec![3; 128];

        // Calculate the contribution hashes.
        let challenge_hash = calculate_hash(&dummy_challenge);
        let invalid_response_hash = vec![2; 48];
        let next_challenge_hash = calculate_hash(&dummy_next_challenge);

        // Construct the contribution state
        let contribution_state = ContributionState::new(
            challenge_hash.to_vec(),
            invalid_response_hash,
            Some(next_challenge_hash.to_vec()),
        );

        assert!(contribution_state.is_err())
    }

    #[test]
    pub fn test_contribution_signature_invalid_next_challenge_hash_size() {
        // Construct the dummy challenge and response files.
        let dummy_challenge = vec![1; 128];
        let dummy_response = vec![2; 128];

        // Calculate the contribution hashes.
        let challenge_hash = calculate_hash(&dummy_challenge);
        let response_hash = calculate_hash(&dummy_response);
        let invalid_next_challenge_hash = vec![3; 48];

        // Construct the contribution state
        let contribution_state = ContributionState::new(
            challenge_hash.to_vec(),
            response_hash.to_vec(),
            Some(invalid_next_challenge_hash),
        );

        assert!(contribution_state.is_err())
    }
}
