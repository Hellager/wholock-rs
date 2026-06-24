mod elevation;
pub mod error;
mod interop;
mod json;
mod scan;
mod types;
mod unlock;
mod wait;

use crate::error::WholockError;

/// Result type returned by wholock APIs.
///
/// This is a crate-wide alias for `Result<T, WholockError>`.
pub type WholockResult<T> = Result<T, WholockError>;

pub use elevation::{
    enable_debug_privilege, is_process_elevated, restart_as_elevated, start_as_elevated,
};
pub use json::processes_to_json;
pub use scan::{find_processes_recursive, who_locks_file, who_locks_files};
pub use types::{
    ProcessInfo, ProcessTerminationFailure, ProcessTerminationFailureKind, UnlockProcessResult,
    WaitForUnlockResult,
};
pub use unlock::{unlock_file, unlock_processes};
pub use wait::{wait_for_unlock, wait_for_unlock_files};
