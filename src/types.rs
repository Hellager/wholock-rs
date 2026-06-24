use crate::{WholockResult, error::WholockError};
use serde::Serialize;
use std::time::Duration;

#[derive(Debug, Clone, Serialize)]
pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: String,
    pub process_exe_path: String,
    pub domain_username: String,
    pub locked_file: Vec<String>,
}

#[derive(Debug)]
pub struct UnlockProcessResult {
    pub pid: u32,
    pub process_name: String,
    pub result: WholockResult<()>,
    pub failure: Option<ProcessTerminationFailure>,
}

impl UnlockProcessResult {
    pub fn is_success(&self) -> bool {
        self.result.is_ok()
    }

    pub fn failure_reason(&self) -> Option<&str> {
        self.failure.as_ref().map(|failure| failure.reason.as_str())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProcessTerminationFailureKind {
    InvalidPid,
    ProtectedProcess,
    StaleProcessIdentity,
    LockNoLongerHeld,
    LockVerification,
    OpenProcess,
    TerminateProcess,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcessTerminationFailure {
    pub pid: u32,
    pub kind: ProcessTerminationFailureKind,
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

#[derive(Debug, Clone)]
pub struct WaitForUnlockResult {
    pub unlocked: bool,
    pub elapsed: Duration,
    pub remaining_locks: Vec<ProcessInfo>,
}

impl WaitForUnlockResult {
    pub fn timed_out(&self) -> bool {
        !self.unlocked
    }
}
