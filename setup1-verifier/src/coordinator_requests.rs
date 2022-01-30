use crate::{errors::VerifierError, utils::AleoAuthentication, verifier::Verifier};

use reqwest::Client;
use tracing::{error, info};

impl Verifier {
    ///
    /// Attempts to download the unverified response file from the coordinator at
    /// a given `response_locator`
    ///
    /// On success, this function returns the full response file buffer.
    ///
    /// On failure, this function returns a `VerifierError`.
    ///
    pub(crate) async fn download_response_file(
        &self,
        chunk_id: u64,
        contribution_id: u64,
    ) -> Result<Vec<u8>, VerifierError> {
        let coordinator_api_url = &self.coordinator_api_url;
        let method = "get";
        let path = format!("/v1/download/response/{}/{}", chunk_id, contribution_id);

        info!("Verifier downloading a response file at {} ", path);

        let authentication = AleoAuthentication::authenticate(&self.private_key, &method, &path)?;
        match Client::new()
            .get(coordinator_api_url.join(&path).expect("Should create a path"))
            .header("Authorization", authentication.to_string())
            .send()
            .await
        {
            Ok(response) => {
                if !response.status().is_success() {
                    error!("Failed to download the response file {}", path);
                    return Err(VerifierError::FailedResponseDownload(path));
                }

                info!("Verifier downloaded the response file {} ", path);

                Ok(response.bytes().await?.to_vec())
            }
            Err(_) => {
                error!("Request ({}) to download a response file failed.", path);
                return Err(VerifierError::FailedRequest(
                    path.to_string(),
                    coordinator_api_url.to_string(),
                ));
            }
        }
    }

    ///
    /// Attempts to download the challenge file from the coordinator at
    /// a given `challenge_locator`
    ///
    /// On success, this function returns the full challenge file buffer.
    ///
    /// On failure, this function returns a `VerifierError`.
    ///
    pub(crate) async fn download_challenge_file(
        &self,
        chunk_id: u64,
        contribution_id: u64,
    ) -> Result<Vec<u8>, VerifierError> {
        let coordinator_api_url = &self.coordinator_api_url;
        let method = "get";
        let path = format!("/v1/download/verifier_challenge/{}/{}", chunk_id, contribution_id);

        info!("Verifier downloading a challenge file at {} ", path);

        let authentication = AleoAuthentication::authenticate(&self.private_key, &method, &path)?;
        match Client::new()
            .get(coordinator_api_url.join(&path).expect("Should create a path"))
            .header("Authorization", authentication.to_string())
            .send()
            .await
        {
            Ok(response) => {
                if !response.status().is_success() {
                    error!("Failed to download the challenge file {}", path);
                    return Err(VerifierError::FailedChallengeDownload(path));
                }

                info!("Verifier downloaded the challenge file {} ", path);

                Ok(response.bytes().await?.to_vec())
            }
            Err(_) => {
                error!("Request ({}) to download a challenge file failed.", path);
                return Err(VerifierError::FailedRequest(
                    path.to_string(),
                    coordinator_api_url.to_string(),
                ));
            }
        }
    }

    ///
    /// Attempts to upload the next challenge file to the coordinator
    /// at a given `next_challenge_locator`
    ///
    /// On success, this function returns an `ok` status
    ///
    /// On failure, this function returns a `VerifierError`.
    ///
    pub(crate) async fn upload_next_challenge_locator_file(
        &self,
        chunk_id: u64,
        contribution_id: u64,
        signature_and_next_challenge_file_bytes: Vec<u8>,
    ) -> Result<String, VerifierError> {
        let coordinator_api_url = &self.coordinator_api_url;
        let method = "post";
        let path = format!("/v1/upload/challenge/{}/{}", chunk_id, contribution_id);

        let authentication = AleoAuthentication::authenticate(&self.private_key, &method, &path)?;

        info!(
            "Verifier uploading a response with size {} to {} ",
            signature_and_next_challenge_file_bytes.len(),
            path
        );

        match Client::new()
            .post(coordinator_api_url.join(&path).expect("Should create a path"))
            .header(http::header::AUTHORIZATION, authentication.to_string())
            .header(http::header::CONTENT_TYPE, "application/octet-stream")
            .header(
                http::header::CONTENT_LENGTH,
                signature_and_next_challenge_file_bytes.len(),
            )
            .body(signature_and_next_challenge_file_bytes)
            .send()
            .await
        {
            Ok(response) => {
                if !response.status().is_success() {
                    error!("Failed to upload the new challenge file {}", path);
                    return Err(VerifierError::FailedChallengeUpload(path));
                }

                info!("Verifier uploaded the next challenge file {} ", path);

                Ok(response.text().await?)
            }
            Err(_) => {
                error!("Request ({}) to upload a new challenge file failed.", path);
                return Err(VerifierError::FailedRequest(
                    path.to_string(),
                    coordinator_api_url.to_string(),
                ));
            }
        }
    }
}
