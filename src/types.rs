use crate::{
    WholockResult,
    error::{LockScanWarning, WholockError},
};
use std::time::Duration;

/// Describes a process that currently holds one or more matching file locks.
///
/// Values are returned by [`who_locks_file`](crate::who_locks_file) and
/// [`scan_locks`](crate::scan_locks).
#[derive(Debug, Clone)]
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

/// Options controlling how file lock scans are performed.
///
/// The default configuration follows PowerToys File Locksmith's behavior: wholock
/// attempts to enable debug privilege to improve visibility, but continues with a
/// best-effort scan if the privilege is unavailable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LockScanOptions {
    /// Whether failing to enable `SeDebugPrivilege` should abort the scan.
    require_debug_privilege: bool,
    /// Whether loaded process modules should be scanned in addition to open handles.
    include_modules: bool,
    /// Maximum time spent probing one duplicated handle before recording a warning.
    handle_probe_timeout: Duration,
}

impl Default for LockScanOptions {
    fn default() -> Self {
        Self {
            require_debug_privilege: false,
            include_modules: true,
            handle_probe_timeout: Duration::from_millis(200),
        }
    }
}

impl LockScanOptions {
    /// Creates default lock scan options.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Whether failing to enable `SeDebugPrivilege` aborts the scan.
    #[must_use]
    pub fn debug_privilege_required(&self) -> bool {
        self.require_debug_privilege
    }

    /// Sets whether failing to enable `SeDebugPrivilege` aborts the scan.
    #[must_use]
    pub fn with_require_debug_privilege(mut self, required: bool) -> Self {
        self.require_debug_privilege = required;
        self
    }

    /// Requires `SeDebugPrivilege` before scanning.
    #[must_use]
    pub fn require_debug_privilege(self) -> Self {
        self.with_require_debug_privilege(true)
    }

    /// Whether loaded process modules are scanned in addition to open handles.
    #[must_use]
    pub fn module_scan_enabled(&self) -> bool {
        self.include_modules
    }

    /// Sets whether loaded process modules are scanned in addition to open handles.
    #[must_use]
    pub fn with_module_scan(mut self, enabled: bool) -> Self {
        self.include_modules = enabled;
        self
    }

    /// Disables loaded module scanning.
    #[must_use]
    pub fn disable_module_scan(self) -> Self {
        self.with_module_scan(false)
    }

    /// Maximum time spent probing one duplicated handle before recording a warning.
    #[must_use]
    pub fn handle_probe_timeout(&self) -> Duration {
        self.handle_probe_timeout
    }

    /// Sets the maximum time spent probing one duplicated handle.
    #[must_use]
    pub fn with_handle_probe_timeout(mut self, timeout: Duration) -> Self {
        self.handle_probe_timeout = timeout;
        self
    }
}

/// Structured result returned by lock scan APIs.
///
/// `processes` contains every lock holder discovered during the scan. `warnings`
/// contains recoverable failures, such as inaccessible processes or a missing debug
/// privilege, that may make the result incomplete.
#[derive(Debug, Clone)]
pub struct LockScanResult {
    /// Processes that matched the requested locked paths.
    processes: Vec<ProcessInfo>,
    /// Recoverable scan failures that may have hidden additional lock holders.
    warnings: Vec<LockScanWarning>,
}

impl LockScanResult {
    /// Creates a scan result from discovered processes and warnings.
    #[must_use]
    pub(crate) fn new(processes: Vec<ProcessInfo>, warnings: Vec<LockScanWarning>) -> Self {
        Self {
            processes,
            warnings,
        }
    }

    /// Processes that matched the requested locked paths.
    #[must_use]
    pub fn processes(&self) -> &[ProcessInfo] {
        &self.processes
    }

    /// Recoverable scan failures that may have hidden additional lock holders.
    #[must_use]
    pub fn warnings(&self) -> &[LockScanWarning] {
        &self.warnings
    }

    /// Consumes the result and returns its raw parts.
    #[must_use]
    pub fn into_parts(self) -> (Vec<ProcessInfo>, Vec<LockScanWarning>) {
        (self.processes, self.warnings)
    }

    /// Returns whether the scan finished without recoverable warnings.
    ///
    /// # Returns
    ///
    /// Returns `true` when [`LockScanResult::warnings`] is empty.
    #[must_use]
    pub fn is_complete_success(&self) -> bool {
        self.warnings.is_empty()
    }

    /// Returns whether the scan finished without recoverable warnings.
    ///
    /// Prefer [`LockScanResult::is_complete_success`] for new code.
    #[must_use]
    pub fn is_complete(&self) -> bool {
        self.is_complete_success()
    }

    /// Consumes the scan result and returns only the discovered processes.
    ///
    /// This is a convenience for callers that intentionally ignore partial-scan
    /// warnings.
    #[must_use]
    pub fn into_processes(self) -> Vec<ProcessInfo> {
        self.processes
    }
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
    /// Whether a complete scan confirmed that all matching locks disappeared.
    pub unlocked: bool,
    /// Time spent polling for locks.
    pub elapsed: Duration,
    /// Lock holders found by the final scan when the wait timed out.
    ///
    /// This can be empty when scan warnings prevented unlock confirmation.
    pub remaining_locks: Vec<ProcessInfo>,
    /// Unique recoverable scan failures observed while polling.
    pub warnings: Vec<LockScanWarning>,
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

    /// Returns whether the wait timed out without confirming either locks or unlock.
    ///
    /// This occurs when the final scan found no locks but warnings indicate that lock
    /// holders may have been missed.
    #[must_use]
    pub fn is_inconclusive(&self) -> bool {
        !self.unlocked
            && self.remaining_locks.is_empty()
            && self
                .warnings
                .iter()
                .any(LockScanWarning::affects_completeness)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::LockScanWarningKind;

    fn process(pid: u32) -> ProcessInfo {
        ProcessInfo {
            pid,
            process_name: format!("process-{pid}.exe"),
            process_exe_path: String::new(),
            domain_username: String::new(),
            locked_file: vec![format!(r"C:\data\locked-{pid}.txt")],
        }
    }

    #[test]
    fn test_lock_scan_options_default_matches_best_effort_scan() {
        let options = LockScanOptions::new();

        assert!(!options.debug_privilege_required());
        assert!(options.module_scan_enabled());
        assert_eq!(options.handle_probe_timeout(), Duration::from_millis(200));
        assert_eq!(options, LockScanOptions::default());
    }

    #[test]
    fn test_lock_scan_options_builders_update_values() {
        let options = LockScanOptions::new()
            .require_debug_privilege()
            .disable_module_scan()
            .with_handle_probe_timeout(Duration::from_millis(50));

        assert!(options.debug_privilege_required());
        assert!(!options.module_scan_enabled());
        assert_eq!(options.handle_probe_timeout(), Duration::from_millis(50));

        let options = options
            .with_require_debug_privilege(false)
            .with_module_scan(true);
        assert!(!options.debug_privilege_required());
        assert!(options.module_scan_enabled());
    }

    #[test]
    fn test_lock_scan_result_accessors_and_parts() {
        let processes = vec![process(42)];
        let warnings = vec![LockScanWarning::new(
            Some(42),
            LockScanWarningKind::HandleEnumeration,
            "handle probe timed out",
        )];
        let result = LockScanResult::new(processes.clone(), warnings.clone());

        assert_eq!(result.processes().len(), 1);
        assert_eq!(result.warnings().len(), 1);
        assert!(!result.is_complete_success());
        assert_eq!(result.processes()[0].pid, 42);

        let (actual_processes, actual_warnings) = result.into_parts();
        assert_eq!(actual_processes.len(), processes.len());
        assert_eq!(actual_warnings.len(), warnings.len());
    }

    #[test]
    fn test_lock_scan_result_into_processes_ignores_warnings() {
        let result = LockScanResult::new(
            vec![process(7)],
            vec![LockScanWarning::new(
                None,
                LockScanWarningKind::DebugPrivilege,
                "debug privilege unavailable",
            )],
        );

        let processes = result.into_processes();

        assert_eq!(processes.len(), 1);
        assert_eq!(processes[0].pid, 7);
    }

    #[test]
    fn test_lock_scan_warning_accessors() {
        let warning = LockScanWarning::new(
            Some(42),
            LockScanWarningKind::ModuleEnumeration,
            "access denied",
        );

        assert_eq!(warning.pid(), Some(42));
        assert_eq!(warning.kind(), LockScanWarningKind::ModuleEnumeration);
        assert_eq!(warning.message(), "access denied");
        assert_eq!(
            warning.to_string(),
            "PID 42 module enumeration warning: access denied"
        );
    }

    #[test]
    fn test_wait_result_reports_inconclusive_scan() {
        let result = WaitForUnlockResult {
            unlocked: false,
            elapsed: Duration::from_secs(1),
            remaining_locks: Vec::new(),
            warnings: vec![LockScanWarning::new(
                None,
                LockScanWarningKind::DebugPrivilege,
                "debug privilege unavailable",
            )],
        };

        assert!(result.timed_out());
        assert!(result.is_inconclusive());
    }

    #[test]
    fn test_wait_result_with_known_locks_is_not_inconclusive() {
        let result = WaitForUnlockResult {
            unlocked: false,
            elapsed: Duration::from_secs(1),
            remaining_locks: vec![process(42)],
            warnings: vec![LockScanWarning::new(
                None,
                LockScanWarningKind::DebugPrivilege,
                "debug privilege unavailable",
            )],
        };

        assert!(!result.is_inconclusive());
    }

    #[test]
    fn test_unlocked_wait_result_is_not_inconclusive() {
        let result = WaitForUnlockResult {
            unlocked: true,
            elapsed: Duration::from_secs(1),
            remaining_locks: Vec::new(),
            warnings: vec![LockScanWarning::new(
                None,
                LockScanWarningKind::DebugPrivilege,
                "earlier scan was incomplete",
            )],
        };

        assert!(!result.is_inconclusive());
    }
}
