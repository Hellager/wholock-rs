use crate::{WholockResult, error::WholockError};
use serde::Serialize;
use std::time::Duration;

/// Describes a process that currently holds one or more matching file locks.
///
/// Values are returned by [`who_locks_file`](crate::who_locks_file),
/// [`who_locks_files`](crate::who_locks_files), and
/// [`find_processes_recursive`](crate::find_processes_recursive).
#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    /// Process identifier reported by Windows.
    pub pid: u32,
    /// Executable file name, such as `notepad.exe`.
    pub process_name: String,
    /// Full executable path when it can be queried.
    pub process_exe_path: String,
    /// Domain-qualified user name that owns the process token when available.
    pub domain_username: String,
    /// Matching file or module paths held by the process.
    pub locked_file: Vec<String>,
}

/// Result for one process termination attempt made by [`unlock_processes`](crate::unlock_processes).
#[derive(Debug)]
pub struct UnlockProcessResult {
    /// Process identifier that was targeted.
    pub pid: u32,
    /// Process name copied from the input [`ProcessInfo`].
    pub process_name: String,
    /// Success or public error returned for this process.
    pub result: WholockResult<()>,
    /// Structured failure details when termination was refused or failed.
    pub failure: Option<ProcessTerminationFailure>,
}

impl UnlockProcessResult {
    /// Returns whether this termination attempt succeeded.
    ///
    /// # Returns
    ///
    /// Returns `true` when [`UnlockProcessResult::result`] is `Ok(())`.
    ///
    /// # Examples
    ///
    /// ```
    /// use wholock::{ProcessInfo, unlock_processes};
    ///
    /// let results = unlock_processes(&[] as &[ProcessInfo]);
    /// assert!(results.is_empty());
    /// ```
    pub fn is_success(&self) -> bool {
        self.result.is_ok()
    }

    /// Returns the human-readable failure reason, if any.
    ///
    /// # Returns
    ///
    /// Returns `Some(&str)` when [`UnlockProcessResult::failure`] contains
    /// structured failure details, otherwise `None`.
    pub fn failure_reason(&self) -> Option<&str> {
        self.failure.as_ref().map(|failure| failure.reason.as_str())
    }
}

/// Classifies why a process termination attempt failed or was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessTerminationFailureKind {
    /// The PID did not identify a live process.
    InvalidPid,
    /// The PID or process name is protected by wholock safety checks.
    ProtectedProcess,
    /// The PID no longer identifies the same process from the lock scan.
    StaleProcessIdentity,
    /// The process no longer appears to hold the recorded locks.
    LockNoLongerHeld,
    /// The lock revalidation query failed before termination.
    LockVerification,
    /// Opening the process for termination failed.
    OpenProcess,
    /// The Windows termination call failed.
    TerminateProcess,
}

/// Structured details for a failed process termination attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessTerminationFailure {
    /// Process identifier that was targeted.
    pub pid: u32,
    /// Machine-readable failure category.
    pub kind: ProcessTerminationFailureKind,
    /// Human-readable failure reason.
    pub reason: String,
}

impl ProcessTerminationFailure {
    pub(crate) fn to_wholock_error(&self) -> WholockError {
        match self.kind {
            ProcessTerminationFailureKind::InvalidPid => WholockError::InvalidPID(self.pid),
            ProcessTerminationFailureKind::ProtectedProcess => WholockError::permission(format!(
                "Refusing to terminate protected system process {}: {}",
                self.pid, self.reason
            )),
            ProcessTerminationFailureKind::StaleProcessIdentity => WholockError::process(format!(
                "Refusing to terminate process {} because its identity changed: {}",
                self.pid, self.reason
            )),
            ProcessTerminationFailureKind::LockNoLongerHeld => WholockError::process(format!(
                "Refusing to terminate process {} because it no longer holds the requested locks: {}",
                self.pid, self.reason
            )),
            ProcessTerminationFailureKind::LockVerification => WholockError::process(format!(
                "Failed to verify locks before terminating process {}: {}",
                self.pid, self.reason
            )),
            ProcessTerminationFailureKind::OpenProcess => WholockError::process(format!(
                "Failed to open process {} for termination: {}",
                self.pid, self.reason
            )),
            ProcessTerminationFailureKind::TerminateProcess => WholockError::process(format!(
                "Failed to terminate process {}: {}",
                self.pid, self.reason
            )),
        }
    }
}

/// Result returned by [`wait_for_unlock`](crate::wait_for_unlock) and
/// [`wait_for_unlock_files`](crate::wait_for_unlock_files).
#[derive(Debug, Clone)]
pub struct WaitForUnlockResult {
    /// Whether all matching locks disappeared before the timeout elapsed.
    pub unlocked: bool,
    /// Time spent polling for locks.
    pub elapsed: Duration,
    /// Lock holders still present when the wait timed out.
    pub remaining_locks: Vec<ProcessInfo>,
}

impl WaitForUnlockResult {
    /// Returns whether waiting ended because the timeout elapsed.
    ///
    /// # Returns
    ///
    /// Returns `true` when [`WaitForUnlockResult::unlocked`] is `false`.
    pub fn timed_out(&self) -> bool {
        !self.unlocked
    }
}
