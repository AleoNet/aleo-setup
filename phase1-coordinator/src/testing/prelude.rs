pub use super::coordinator::*;

#[cfg(test)]
pub use function_name::named;
pub use serde_diff::{Apply, Diff, SerdeDiff};
#[cfg(test)]
pub use serial_test::serial;

use std::panic::{catch_unwind, RefUnwindSafe};

#[cfg(test)]
const BAR: &str = "\n\n-----------------------------------------------------------------------------\n\n";

#[cfg(test)]
pub fn test_report<T, F>(name: &str, function: F)
where
    F: Fn() -> anyhow::Result<T> + RefUnwindSafe,
{
    match catch_unwind(|| function()) {
        Ok(outcome) => match &outcome {
            Ok(_) => {
                let message = format!("{} [SUCCESS] {} passed.{}", BAR, name, BAR);
                info!("{}", message);
                println!("{}", message);
                outcome.unwrap();
            }
            Err(error) => {
                let message = format!("{}{}{}{} [FAILURE] {} errored.{}", BAR, error, BAR, BAR, name, BAR);
                println!("{}", message);
                outcome.unwrap();
            }
        },
        Err(error) => match error.downcast::<String>() {
            Ok(message) => {
                let message = format!("{}{}{}{} [FAILURE] {} failed.{}", BAR, message, BAR, BAR, name, BAR);
                panic!(message);
            }
            Err(error) => {
                let message = format!("{} [PANIC] {} panicked.{}", BAR, name, BAR);
                println!("{}", message);
                panic!(error);
            }
        },
    };
}
