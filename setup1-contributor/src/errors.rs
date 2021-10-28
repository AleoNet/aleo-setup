use thiserror::Error;

#[derive(Debug, Error)]
pub enum ContributeError {
    #[error("Could not read passphrase")]
    CouldNotReadPassphraseError,
    #[error("Unsupported decryptor")]
    UnsupportedDecryptorError,
}

#[derive(Debug, Error)]
pub enum GenerateError {}

#[derive(Debug, Error)]
pub enum CLIError {
    #[error("{}", _0)]
    ContributeError(ContributeError),

    #[error("{}", _0)]
    GenerateError(GenerateError),
}

impl From<ContributeError> for CLIError {
    fn from(error: ContributeError) -> Self {
        CLIError::ContributeError(error)
    }
}

impl From<GenerateError> for CLIError {
    fn from(error: GenerateError) -> Self {
        CLIError::GenerateError(error)
    }
}
