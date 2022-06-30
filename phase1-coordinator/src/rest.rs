//! REST API endpoints exposed by the [Coordinator](`crate::Coordinator`).

use crate::{
    authentication::{KeyPair, Production, Signature},
    objects::{ContributionInfo, LockedLocators, Task, TrimmedContributionInfo},
    storage::{ContributionLocator, ContributionSignatureLocator, Locator},
    ContributionFileSignature,
    CoordinatorError,
    Participant,
};

use base64::encode;
use blake2::Digest;
use rocket::{
    data::FromData,
    error,
    get,
    http::{ContentType, Status},
    outcome::IntoOutcome,
    post,
    request::{self, FromRequest, Outcome, Request},
    response::{Responder, Response},
    serde::{
        json::{self, Json},
        Deserialize,
        DeserializeOwned,
        Serialize,
    },
    tokio::{fs, sync::RwLock, task},
    Shutdown,
    State,
};
use sha2::Sha256;
use tracing_subscriber::fmt::format;

use std::{
    borrow::Cow,
    collections::{HashMap, LinkedList},
    convert::TryFrom,
    io::Cursor,
    net::{IpAddr, SocketAddr},
    ops::Deref,
    sync::Arc,
    time::Duration,
};
use thiserror::Error;

use tracing::debug;

#[cfg(debug_assertions)]
pub const UPDATE_TIME: Duration = Duration::from_secs(5);
#[cfg(not(debug_assertions))]
pub const UPDATE_TIME: Duration = Duration::from_secs(60);

// Headers
pub const BODY_DIGEST_HEADER: &str = "Digest";
pub const PUBKEY_HEADER: &str = "ATS-Pubkey";
pub const SIGNATURE_HEADER: &str = "ATS-Signature";
pub const CONTENT_LENGTH_HEADER: &str = "Content-Length";

type Coordinator = Arc<RwLock<crate::Coordinator>>;

/// Server errors. Also includes errors generated by the managed [Coordinator](`crate::Coordinator`).
#[derive(Error, Debug)]
pub enum ResponseError {
    #[error("Coordinator failed: {0}")]
    CoordinatorError(CoordinatorError),
    #[error("Header {0} is badly formatted")]
    InvalidHeader(&'static str),
    #[error("Request's signature is invalid")]
    InvalidSignature,
    #[error("Io Error: {0}")]
    IoError(#[from] std::io::Error),
    #[error("Checksum of body doesn't match the expected one: expc {0}, act: {1}")]
    MismatchingChecksum(String, String),
    #[error("The required {0} header was missing from the incoming request")]
    MissingRequiredHeader(&'static str),
    #[error("Couldn't verify signature because of missing signing key")]
    MissingSigningKey,
    #[error("Couldn't parse string to int: {0}")]
    ParseError(#[from] std::num::ParseIntError),
    #[error("Thread panicked: {0}")]
    RuntimeError(#[from] task::JoinError),
    #[error("Error with Serde: {0}")]
    SerdeError(#[from] serde_json::error::Error),
    #[error("Error while terminating the ceremony: {0}")]
    ShutdownError(String),
    #[error("The participant {0} is not allowed to access the endpoint {1}")]
    UnauthorizedParticipant(Participant, String),
    #[error("Could not find contributor with public key {0}")]
    UnknownContributor(String),
    #[error("Could not find the provided Task {0} in coordinator state")]
    UnknownTask(Task),
    #[error("Error while verifying a contribution: {0}")]
    VerificationError(String),
    #[error("Digest of request's body is not base64 encoded: {0}")]
    WrongDigestEncoding(#[from] base64::DecodeError),
}

impl<'r> Responder<'r, 'static> for ResponseError {
    fn respond_to(self, _request: &'r Request<'_>) -> rocket::response::Result<'static> {
        let response = format!("{}", self);
        let mut builder = Response::build();

        let response_code = match self {
            ResponseError::InvalidHeader(_) => Status::BadRequest,
            ResponseError::InvalidSignature => Status::BadRequest,
            ResponseError::MismatchingChecksum(_, _) => Status::BadRequest,
            ResponseError::MissingRequiredHeader(_) => Status::BadRequest,
            ResponseError::MissingSigningKey => Status::BadRequest,
            ResponseError::UnauthorizedParticipant(_, _) => Status::Unauthorized,
            ResponseError::WrongDigestEncoding(_) => Status::BadRequest,
            _ => Status::InternalServerError,
        };

        builder
            .status(response_code)
            .header(ContentType::JSON)
            .sized_body(response.len(), Cursor::new(response))
            .ok()
    }
}

type Result<T> = std::result::Result<T, ResponseError>;
/// Content info
pub struct RequestContent<'a> {
    len: usize,
    digest: Cow<'a, str>,
}

impl<'a> RequestContent<'a> {
    pub fn new<T>(len: usize, digest: T) -> Self
    where
        T: AsRef<[u8]>,
    {
        Self {
            len,
            digest: base64::encode(digest).into(),
        }
    }

    /// Returns struct correctly formatted for the http header
    pub fn to_header(&self) -> (usize, String) {
        (self.len, format!("sha-256={}", self.digest))
    }

    /// Constructs from request's headers
    fn try_from_header(len: &str, digest: &'a str) -> Result<Self> {
        let digest = digest
            .split_once('=')
            .ok_or(ResponseError::InvalidHeader(BODY_DIGEST_HEADER))?
            .1;

        // Check encoding
        base64::decode(digest)?;
        let len = len
            .parse()
            .map_err(|_| ResponseError::InvalidHeader(CONTENT_LENGTH_HEADER))?;

        Ok(Self {
            len,
            digest: digest.into(),
        })
    }
}

/// The headers involved in the signature of the request.
#[derive(Default)]
pub struct SignatureHeaders<'r> {
    pub pubkey: &'r str,
    pub content: Option<RequestContent<'r>>,
    pub signature: Option<Cow<'r, str>>,
}

impl<'r> SignatureHeaders<'r> {
    /// Produces the message on which to compute the signature
    pub fn to_string(&self) -> Cow<'_, str> {
        match &self.content {
            Some(content) => format!("{}{}{}", self.pubkey, content.len, content.digest).into(),
            None => self.pubkey.into(),
        }
    }

    pub fn new(pubkey: &'r str, content: Option<RequestContent<'r>>, signature: Option<Cow<'r, str>>) -> Self {
        Self {
            pubkey,
            content,
            signature,
        }
    }

    fn try_verify_signature(&self) -> Result<bool> {
        match &self.signature {
            Some(sig) => Ok(Production.verify(self.pubkey, &self.to_string(), &sig)),
            None => Err(ResponseError::MissingSigningKey),
        }
    }
}

impl<'r> TryFrom<&'r Request<'_>> for SignatureHeaders<'r> {
    type Error = ResponseError;

    fn try_from(request: &'r Request<'_>) -> std::result::Result<Self, Self::Error> {
        let headers = request.headers();
        let mut body: Option<RequestContent> = None;

        let pubkey = headers
            .get_one(PUBKEY_HEADER)
            .ok_or(ResponseError::InvalidHeader(PUBKEY_HEADER))?;
        let sig = headers
            .get_one(SIGNATURE_HEADER)
            .ok_or(ResponseError::InvalidHeader(SIGNATURE_HEADER))?;

        // If post request, also get the hash of body from header (if any and if base64 encoded)
        if request.method() == rocket::http::Method::Post {
            if let Some(s) = headers.get_one(BODY_DIGEST_HEADER) {
                let content_length = headers
                    .get_one(CONTENT_LENGTH_HEADER)
                    .ok_or(ResponseError::InvalidHeader(CONTENT_LENGTH_HEADER))?;
                let content = RequestContent::try_from_header(content_length, s)?;

                body = Some(content);
            }
        }

        Ok(SignatureHeaders::new(pubkey, body, Some(sig.into())))
    }
}

trait VerifySignature<'r> {
    // Workaround to implement a single method on a foreign type instead of newtype pattern
    fn verify_signature(&'r self) -> Result<&str>;
}

impl<'r> VerifySignature<'r> for Request<'_> {
    /// Check signature of request and return the pubkey of the participant
    fn verify_signature(&'r self) -> Result<&str> {
        let headers = SignatureHeaders::try_from(self)?;

        match headers.try_verify_signature()? {
            true => Ok(headers.pubkey),
            false => Err(ResponseError::InvalidSignature),
        }
    }
}

#[rocket::async_trait]
impl<'r> FromRequest<'r> for Participant {
    type Error = ResponseError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        match request.verify_signature() {
            Ok(pubkey) => Outcome::Success(Participant::new_contributor(pubkey)),
            Err(e) => Outcome::Failure((Status::BadRequest, e)),
        }
    }
}

/// Implements the signature verification on the incoming server request via [`FromRequest`].
pub struct ServerAuth;

#[rocket::async_trait]
impl<'r> FromRequest<'r> for ServerAuth {
    type Error = ResponseError;

    async fn from_request(request: &'r Request<'_>) -> Outcome<Self, Self::Error> {
        let pubkey = match request.verify_signature() {
            Ok(h) => h,
            Err(e) => return Outcome::Failure((Status::BadRequest, e)),
        };

        // Check that the signature comes from the coordinator by matching the default verifier key
        let coordinator = request
            .guard::<&State<Coordinator>>()
            .await
            .succeeded()
            .expect("Managed state should always be retrievable");
        let verifier = Participant::new_verifier(pubkey);

        if verifier != coordinator.read().await.environment().coordinator_verifiers()[0] {
            return Outcome::Failure((
                Status::Unauthorized,
                ResponseError::UnauthorizedParticipant(verifier, request.uri().to_string()),
            ));
        }

        Outcome::Success(Self)
    }
}

/// Type to handle lazy deserialization of json encoded inputs.
pub struct LazyJson<T>(T);

impl<T> Deref for LazyJson<T> {
    type Target = T;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl<T> std::ops::DerefMut for LazyJson<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}

#[rocket::async_trait]
impl<'r, T: DeserializeOwned> FromData<'r> for LazyJson<T> {
    type Error = ResponseError;

    async fn from_data(req: &'r Request<'_>, data: rocket::data::Data<'r>) -> rocket::data::Outcome<'r, Self> {
        // Check that digest of body is the expected one
        let expected_digest = match req.headers().get_one(BODY_DIGEST_HEADER) {
            Some(h) => h,
            None => {
                return rocket::data::Outcome::Failure((
                    Status::BadRequest,
                    ResponseError::MissingRequiredHeader(BODY_DIGEST_HEADER),
                ));
            }
        };

        let content_length = match req.headers().get_one(CONTENT_LENGTH_HEADER) {
            Some(h) => h,
            None => {
                return rocket::data::Outcome::Failure((
                    Status::LengthRequired,
                    ResponseError::MissingRequiredHeader(CONTENT_LENGTH_HEADER),
                ));
            }
        };

        let expected_content = match RequestContent::try_from_header(content_length, expected_digest) {
            Ok(c) => c,
            Err(e) => return rocket::data::Outcome::Failure((Status::BadRequest, e)),
        };

        let body = match data.open(expected_content.len.into()).into_string().await {
            Ok(string) => string.into_inner(),
            Err(e) => return rocket::data::Outcome::Failure((Status::InternalServerError, ResponseError::from(e))),
        };

        let mut hasher = Sha256::new();
        hasher.update(&body);
        let digest = base64::encode(hasher.finalize());
        if digest != expected_content.digest {
            return rocket::data::Outcome::Failure((
                Status::BadRequest,
                ResponseError::MismatchingChecksum(expected_digest.to_owned(), expected_content.digest.to_string()),
            ));
        }

        // Deserialize data and pass it to the request handler
        match serde_json::from_str::<T>(body.as_str()) {
            Ok(obj) => rocket::data::Outcome::Success(LazyJson(obj)),
            Err(e) => rocket::data::Outcome::Failure((Status::UnprocessableEntity, ResponseError::from(e))),
        }
    }
}

/// The status of the contributor related to the current round.
#[derive(Clone, Debug, Deserialize, Serialize)]
pub enum ContributorStatus {
    Queue(u64, u64),
    Round,
    Finished,
    Other,
}

/// Request to post a [Chunk](`crate::objects::Chunk`).
#[derive(Clone, Deserialize, Serialize)]
pub struct PostChunkRequest {
    contribution_locator: ContributionLocator,
    contribution: Vec<u8>,
    contribution_file_signature_locator: ContributionSignatureLocator,
    contribution_file_signature: ContributionFileSignature,
}

impl PostChunkRequest {
    pub fn new(
        contribution_locator: ContributionLocator,
        contribution: Vec<u8>,
        contribution_file_signature_locator: ContributionSignatureLocator,
        contribution_file_signature: ContributionFileSignature,
    ) -> Self {
        Self {
            contribution_locator,
            contribution,
            contribution_file_signature_locator,
            contribution_file_signature,
        }
    }
}

//
// -- REST API ENDPOINTS --
//

// FIXME: review which spawn_blocking are necessary

/// Add the incoming contributor to the queue of contributors.
#[post("/contributor/join_queue")]
pub async fn join_queue(
    coordinator: &State<Coordinator>,
    participant: Participant,
    contributor_ip: IpAddr, //NOTE: if ip address cannot be retrieved this request is forwarded and fails. If we want to accept requests from unknown ips we should use Option<IpAddr>
) -> Result<()> {
    let mut write_lock = (*coordinator).clone().write_owned().await;

    match task::spawn_blocking(move || write_lock.add_to_queue(participant, Some(contributor_ip), 10)).await? {
        Ok(()) => Ok(()),
        Err(e) => Err(ResponseError::CoordinatorError(e)),
    }
}

/// Lock a [Chunk](`crate::objects::Chunk`) in the ceremony. This should be the first function called when attempting to contribute to a chunk. Once the chunk is locked, it is ready to be downloaded.
#[get("/contributor/lock_chunk", format = "json")]
pub async fn lock_chunk(coordinator: &State<Coordinator>, participant: Participant) -> Result<Json<LockedLocators>> {
    let mut write_lock = (*coordinator).clone().write_owned().await;

    match task::spawn_blocking(move || write_lock.try_lock(&participant)).await? {
        Ok((_, locked_locators)) => Ok(Json(locked_locators)),
        Err(e) => Err(ResponseError::CoordinatorError(e)),
    }
}

/// Download a chunk from the [Coordinator](`crate::Coordinator`), which should be contributed to upon receipt.
#[post("/download/chunk", format = "json", data = "<get_chunk_request>")]
pub async fn get_chunk(
    coordinator: &State<Coordinator>,
    participant: Participant,
    get_chunk_request: LazyJson<LockedLocators>,
) -> Result<Json<Task>> {
    let next_contribution = get_chunk_request.next_contribution();
    // Build and check next Task
    let task = Task::new(next_contribution.chunk_id(), next_contribution.contribution_id());

    match coordinator.read().await.state().current_participant_info(&participant) {
        Some(info) => {
            if !info.pending_tasks().contains(&task) {
                return Err(ResponseError::UnknownTask(task));
            }
            Ok(Json(task))
        }
        None => Err(ResponseError::UnknownContributor(participant.address())),
    }
}

/// Download the challenge from the [Coordinator](`crate::Coordinator`) accordingly to the [`LockedLocators`] received from the Contributor.
#[post("/contributor/challenge", format = "json", data = "<locked_locators>")]
pub async fn get_challenge(
    coordinator: &State<Coordinator>,
    _participant: Participant,
    locked_locators: LazyJson<LockedLocators>,
) -> Result<Json<Vec<u8>>> {
    let challenge_locator = locked_locators.current_contribution();
    let round_height = challenge_locator.round_height();
    let chunk_id = challenge_locator.chunk_id();

    debug!(
        "rest::get_challenge - round_height {}, chunk_id {}, contribution_id 0, is_verified true",
        round_height, chunk_id
    );

    let mut write_lock = (*coordinator).clone().write_owned().await;

    // Since we don't chunk the parameters, we have one chunk and one allowed contributor per round. Thus the challenge will always be located at round_{i}/chunk_0/contribution_0.verified
    // For example, the 1st challenge (after the initialization) is located at round_1/chunk_0/contribution_0.verified
    match task::spawn_blocking(move || write_lock.get_challenge(round_height, chunk_id, 0, true)).await? {
        Ok(challenge_hash) => Ok(Json(challenge_hash)),
        Err(e) => Err(ResponseError::CoordinatorError(e)),
    }
}

/// Upload a [Chunk](`crate::objects::Chunk`) contribution to the [Coordinator](`crate::Coordinator`). Write the contribution bytes to
/// disk at the provided [Locator](`crate::storage::Locator`). Also writes the corresponding [`ContributionFileSignature`]
#[post("/upload/chunk", format = "json", data = "<post_chunk_request>")]
pub async fn post_contribution_chunk(
    coordinator: &State<Coordinator>,
    participant: Participant,
    mut post_chunk_request: LazyJson<PostChunkRequest>,
) -> Result<()> {
    let contribution_locator = post_chunk_request.contribution_locator.clone();
    let contribution = post_chunk_request.contribution.clone();
    let mut write_lock = (*coordinator).clone().write_owned().await;

    if let Err(e) =
        task::spawn_blocking(move || write_lock.write_contribution(contribution_locator, contribution)).await?
    {
        return Err(ResponseError::CoordinatorError(e));
    }

    write_lock = (*coordinator).clone().write_owned().await;
    match task::spawn_blocking(move || {
        write_lock.write_contribution_file_signature(
            std::mem::take(&mut post_chunk_request.contribution_file_signature_locator),
            std::mem::take(&mut post_chunk_request.contribution_file_signature),
        )
    })
    .await?
    {
        Ok(()) => Ok(()),
        Err(e) => Err(ResponseError::CoordinatorError(e)),
    }
}

/// Notify the [Coordinator](`crate::Coordinator`) of a finished and uploaded [Contribution](`crate::objects::Contribution`). This will unlock the given [Chunk](`crate::objects::Chunk`) and allow the contributor to take on a new task.
#[post(
    "/contributor/contribute_chunk",
    format = "json",
    data = "<contribute_chunk_request>"
)]
pub async fn contribute_chunk(
    coordinator: &State<Coordinator>,
    participant: Participant,
    contribute_chunk_request: LazyJson<u64>,
) -> Result<Json<ContributionLocator>> {
    let mut write_lock = (*coordinator).clone().write_owned().await;

    match task::spawn_blocking(move || write_lock.try_contribute(&participant, *contribute_chunk_request)).await? {
        Ok(contribution_locator) => Ok(Json(contribution_locator)),
        Err(e) => Err(ResponseError::CoordinatorError(e)),
    }
}

/// Performs the update of the [Coordinator](`crate::Coordinator`)
pub async fn perform_coordinator_update(coordinator: Coordinator) -> Result<()> {
    let mut write_lock = coordinator.clone().write_owned().await;

    match task::spawn_blocking(move || write_lock.update()).await? {
        Ok(()) => Ok(()),
        Err(e) => Err(ResponseError::CoordinatorError(e)),
    }
}

/// Update the [Coordinator](`crate::Coordinator`) state. This endpoint is accessible only by the coordinator itself.
#[cfg(debug_assertions)]
#[get("/update")]
pub async fn update_coordinator(coordinator: &State<Coordinator>, _auth: ServerAuth) -> Result<()> {
    perform_coordinator_update(coordinator.deref().to_owned()).await
}

/// Let the [Coordinator](`crate::Coordinator`) know that the participant is still alive and participating (or waiting to participate) in the ceremony.
#[post("/contributor/heartbeat")]
pub async fn heartbeat(coordinator: &State<Coordinator>, participant: Participant) -> Result<()> {
    let mut write_lock = (*coordinator).clone().write_owned().await;

    match task::spawn_blocking(move || write_lock.heartbeat(&participant)).await? {
        Ok(()) => Ok(()),
        Err(e) => Err(ResponseError::CoordinatorError(e)),
    }
}

/// Get the pending tasks of contributor.
#[get("/contributor/get_tasks_left", format = "json")]
pub async fn get_tasks_left(
    coordinator: &State<Coordinator>,
    participant: Participant,
) -> Result<Json<LinkedList<Task>>> {
    match coordinator.read().await.state().current_participant_info(&participant) {
        Some(info) => Ok(Json(info.pending_tasks().to_owned())),
        None => Err(ResponseError::UnknownContributor(participant.address())),
    }
}

/// Stop the [Coordinator](`crate::Coordinator`) and shuts the server down. This endpoint is accessible only by the coordinator itself.
#[get("/stop")]
pub async fn stop_coordinator(coordinator: &State<Coordinator>, _auth: ServerAuth, shutdown: Shutdown) -> Result<()> {
    let mut write_lock = (*coordinator).clone().write_owned().await;
    let result = task::spawn_blocking(move || write_lock.shutdown()).await?;

    if let Err(e) = result {
        return Err(ResponseError::ShutdownError(format!("{}", e)));
    };

    // Shut Rocket server down
    shutdown.notify();

    Ok(())
}

/// Performs the verification of the pending contributions
pub async fn perform_verify_chunks(coordinator: Coordinator) -> Result<()> {
    // Get all the pending verifications, loop on each one of them and perform verification
    let pending_verifications = coordinator.read().await.get_pending_verifications().to_owned();

    for (task, _) in pending_verifications {
        let mut write_lock = coordinator.clone().write_owned().await;
        // NOTE: we are going to rely on the single default verifier built in the coordinator itself,
        //  no external verifiers
        if let Err(e) = task::spawn_blocking(move || write_lock.default_verify(&task)).await? {
            return Err(ResponseError::VerificationError(format!("{}", e)));
        }
    }

    Ok(())
}

/// Verify all the pending contributions. This endpoint is accessible only by the coordinator itself.
#[cfg(debug_assertions)]
#[get("/verify")]
pub async fn verify_chunks(coordinator: &State<Coordinator>, _auth: ServerAuth) -> Result<()> {
    perform_verify_chunks(coordinator.deref().to_owned()).await
}

/// Get the queue status of the contributor.
#[get("/contributor/queue_status", format = "json")]
pub async fn get_contributor_queue_status(
    coordinator: &State<Coordinator>,
    participant: Participant,
) -> Result<Json<ContributorStatus>> {
    let contributor = participant.clone();

    let read_lock = (*coordinator).clone().read_owned().await;
    // Check that the contributor is authorized to lock a chunk in the current round.
    if task::spawn_blocking(move || read_lock.is_current_contributor(&contributor)).await? {
        return Ok(Json(ContributorStatus::Round));
    }

    if coordinator.read().await.is_queue_contributor(&participant) {
        let queue_size = coordinator.read().await.number_of_queue_contributors() as u64;

        let queue_position = match coordinator.read().await.state().queue_contributor_info(&participant) {
            Some((_, Some(round), _, _)) => round - coordinator.read().await.state().current_round_height(),
            Some((_, None, _, _)) => queue_size,
            None => return Ok(Json(ContributorStatus::Other)),
        };

        return Ok(Json(ContributorStatus::Queue(queue_position, queue_size)));
    }

    if coordinator.read().await.is_finished_contributor(&participant) {
        return Ok(Json(ContributorStatus::Finished));
    }

    // Not in the queue, not finished, nor in the current round
    Ok(Json(ContributorStatus::Other))
}

/// Write [`ContributionInfo`] to disk
#[post("/contributor/contribution_info", format = "json", data = "<request>")]
pub async fn post_contribution_info(
    coordinator: &State<Coordinator>,
    participant: Participant,
    request: LazyJson<ContributionInfo>,
) -> Result<()> {
    // Check participant is registered in the ceremony
    let read_lock = coordinator.read().await;

    if !(read_lock.is_current_contributor(&participant) || read_lock.is_finished_contributor(&participant)) {
        // Only the current contributor can upload this file
        return Err(ResponseError::UnauthorizedParticipant(
            participant,
            String::from("/contributor/contribution_info"),
        ));
    }
    drop(read_lock);

    // Write contribution info to file
    let contribution_info = request.clone();
    let mut write_lock = (*coordinator).clone().write_owned().await;
    task::spawn_blocking(move || write_lock.write_contribution_info(contribution_info))
        .await?
        .map_err(|e| ResponseError::CoordinatorError(e))?;

    // Append summary to file
    let contribution_summary = (*request).clone().into();
    let mut write_lock = (*coordinator).clone().write_owned().await;
    task::spawn_blocking(move || write_lock.update_contribution_summary(contribution_summary))
        .await?
        .map_err(|e| ResponseError::CoordinatorError(e))?;

    Ok(())
}

/// Retrieve the contributions' info. This endpoint is accessible by anyone and does not require a signed request.
#[get("/contribution_info", format = "json")]
pub async fn get_contributions_info(coordinator: &State<Coordinator>) -> Result<Json<Vec<TrimmedContributionInfo>>> {
    let read_lock = (*coordinator).clone().read_owned().await;
    let summary = match task::spawn_blocking(move || read_lock.storage().get(&Locator::ContributionsInfoSummary))
        .await?
        .map_err(|e| ResponseError::CoordinatorError(e))?
    {
        crate::storage::Object::ContributionsInfoSummary(summary) => summary,
        _ => unreachable!(),
    };

    Ok(Json(summary))
}