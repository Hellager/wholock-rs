use crate::WholockResult;
use crate::error::WholockError;
use crate::interop::{ProcessIdentity, SafeHandle, get_process_identity_by_handle};
use crate::scan::scan_locks;
use crate::types::{
    LockScanOptions, ProcessInfo, ProcessTerminationFailure, ProcessTerminationFailureKind,
    UnlockProcessResult,
};
use std::collections::BTreeSet;
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE, TerminateProcess,
};

fn sanitize_pid(pid: u32) -> WholockResult<()> {
    let system = sysinfo::System::new_all();
    if !system
        .processes()
        .contains_key(&sysinfo::Pid::from(pid as usize))
    {
        return Err(WholockError::InvalidPID(pid));
    }
    Ok(())
}

fn protected_system_process_reason(pid: u32) -> Option<&'static str> {
    if pid == std::process::id() {
        return Some("current process");
    }

    match pid {
        0 => Some("System Idle Process"),
        4 => Some("System process"),
        _ => None,
    }
}

fn protected_process_name_reason(process_name: &str) -> Option<&'static str> {
    let process_name = process_name.trim();
    if process_name.is_empty() {
        return None;
    }

    const PROTECTED_PROCESS_NAMES: &[&str] = &[
        "registry",
        "system",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "winlogon.exe",
        "services.exe",
        "lsass.exe",
        "lsaiso.exe",
    ];

    PROTECTED_PROCESS_NAMES
        .iter()
        .copied()
        .find(|protected_name| process_name.eq_ignore_ascii_case(protected_name))
}

fn check_pid_value_can_be_terminated(pid: u32) -> Result<(), ProcessTerminationFailure> {
    if let Some(reason) = protected_system_process_reason(pid) {
        return Err(ProcessTerminationFailure {
            pid,
            kind: ProcessTerminationFailureKind::ProtectedProcess,
            reason: reason.to_string(),
        });
    }

    if let Err(err) = sanitize_pid(pid) {
        return Err(ProcessTerminationFailure {
            pid,
            kind: ProcessTerminationFailureKind::InvalidPid,
            reason: err.to_string(),
        });
    }

    Ok(())
}

fn open_process_for_termination(pid: u32) -> Result<SafeHandle, ProcessTerminationFailure> {
    // SAFETY: OpenProcess is called with a validated numeric PID. The returned
    // owned handle is immediately wrapped in SafeHandle and closed on every exit.
    let handle = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE,
            false,
            pid,
        )
    }
    .map_err(|err| ProcessTerminationFailure {
        pid,
        kind: ProcessTerminationFailureKind::OpenProcess,
        reason: err.to_string(),
    })?;

    SafeHandle::new(handle).map_err(|err| ProcessTerminationFailure {
        pid,
        kind: ProcessTerminationFailureKind::OpenProcess,
        reason: err.to_string(),
    })
}

fn check_open_process_can_be_terminated(
    pid: u32,
    process_handle: &SafeHandle,
) -> Result<ProcessIdentity, ProcessTerminationFailure> {
    let identity = get_process_identity_by_handle(process_handle.as_raw()).map_err(|err| {
        ProcessTerminationFailure {
            pid,
            kind: ProcessTerminationFailureKind::StaleProcessIdentity,
            reason: format!("failed to read identity from the opened process handle: {err}"),
        }
    })?;

    if let Some(reason) = protected_process_name_reason(&identity.process_name) {
        return Err(ProcessTerminationFailure {
            pid,
            kind: ProcessTerminationFailureKind::ProtectedProcess,
            reason: format!("protected process name {reason}"),
        });
    }

    Ok(identity)
}

fn open_checked_process(
    pid: u32,
) -> Result<(SafeHandle, ProcessIdentity), ProcessTerminationFailure> {
    check_pid_value_can_be_terminated(pid)?;
    let process_handle = open_process_for_termination(pid)?;
    let identity = check_open_process_can_be_terminated(pid, &process_handle)?;
    Ok((process_handle, identity))
}

fn normalize_process_identity(value: &str) -> String {
    value
        .trim_end_matches('\0')
        .replace('/', "\\")
        .to_lowercase()
}

fn process_identity_matches_snapshot(
    expected: &ProcessInfo,
    current: &ProcessIdentity,
) -> Result<(), ProcessTerminationFailure> {
    let Some(expected_instance_id) = expected.process_instance_id else {
        return Err(ProcessTerminationFailure {
            pid: expected.pid,
            kind: ProcessTerminationFailureKind::StaleProcessIdentity,
            reason: "scan result does not contain a stable process instance identifier".to_string(),
        });
    };

    if expected_instance_id != current.creation_time {
        return Err(ProcessTerminationFailure {
            pid: expected.pid,
            kind: ProcessTerminationFailureKind::StaleProcessIdentity,
            reason: "PID now refers to a different process instance".to_string(),
        });
    }

    if !expected.process_exe_path.is_empty()
        && !current.process_exe_path.is_empty()
        && normalize_process_identity(&expected.process_exe_path)
            != normalize_process_identity(&current.process_exe_path)
    {
        return Err(ProcessTerminationFailure {
            pid: expected.pid,
            kind: ProcessTerminationFailureKind::StaleProcessIdentity,
            reason: format!(
                "expected executable path '{}', found '{}'",
                expected.process_exe_path, current.process_exe_path
            ),
        });
    }

    if expected.process_exe_path.is_empty()
        && !expected.process_name.is_empty()
        && !current
            .process_name
            .eq_ignore_ascii_case(&expected.process_name)
    {
        return Err(ProcessTerminationFailure {
            pid: expected.pid,
            kind: ProcessTerminationFailureKind::StaleProcessIdentity,
            reason: format!(
                "expected process name '{}', found '{}'",
                expected.process_name, current.process_name
            ),
        });
    }

    Ok(())
}

fn process_still_holds_snapshot_locks(
    process: &ProcessInfo,
) -> Result<(), ProcessTerminationFailure> {
    let matched_paths = if process.matches.is_empty() {
        process
            .locked_file
            .iter()
            .map(String::as_str)
            .collect::<BTreeSet<_>>()
    } else {
        process
            .matches
            .iter()
            .map(|lock_match| lock_match.path.as_str())
            .collect::<BTreeSet<_>>()
    };

    if matched_paths.is_empty() {
        return Err(ProcessTerminationFailure {
            pid: process.pid,
            kind: ProcessTerminationFailureKind::LockVerification,
            reason: "query result did not record any locked paths".to_string(),
        });
    }

    let current_locks = scan_locks(matched_paths, LockScanOptions::new()).map_err(|err| {
        ProcessTerminationFailure {
            pid: process.pid,
            kind: ProcessTerminationFailureKind::LockVerification,
            reason: err.to_string(),
        }
    })?;

    if current_locks
        .processes()
        .iter()
        .any(|current| current.pid == process.pid && !current.locked_file.is_empty())
    {
        return Ok(());
    }

    if !current_locks.warnings().is_empty() {
        return Err(ProcessTerminationFailure {
            pid: process.pid,
            kind: ProcessTerminationFailureKind::LockVerification,
            reason: format!(
                "lock query did not report this PID, but scan was incomplete with {} warning(s)",
                current_locks.warnings().len()
            ),
        });
    }

    Err(ProcessTerminationFailure {
        pid: process.pid,
        kind: ProcessTerminationFailureKind::LockNoLongerHeld,
        reason: "lock query no longer reports this PID for the recorded paths".to_string(),
    })
}

fn terminate_checked_process(
    pid: u32,
    process_handle: &SafeHandle,
) -> Result<(), ProcessTerminationFailure> {
    // SAFETY: `process_handle` is the same live handle used for process identity
    // validation and was opened with PROCESS_TERMINATE access.
    if let Err(err) = unsafe { TerminateProcess(process_handle.as_raw(), 1) } {
        return Err(ProcessTerminationFailure {
            pid,
            kind: ProcessTerminationFailureKind::TerminateProcess,
            reason: err.to_string(),
        });
    }

    Ok(())
}

fn terminate_process_by_pid_detailed(pid: u32) -> Result<(), ProcessTerminationFailure> {
    let (process_handle, _) = open_checked_process(pid)?;
    terminate_checked_process(pid, &process_handle)
}

fn terminate_process_from_snapshot(process: &ProcessInfo) -> Result<(), ProcessTerminationFailure> {
    let (process_handle, current_identity) = open_checked_process(process.pid)?;
    process_identity_matches_snapshot(process, &current_identity)?;
    process_still_holds_snapshot_locks(process)?;
    terminate_checked_process(process.pid, &process_handle)
}

fn terminate_process_by_pid(pid: u32) -> WholockResult<()> {
    terminate_process_by_pid_detailed(pid).map_err(|failure| failure.to_wholock_error())
}

/// Terminates a process to unlock files held by that process.
///
/// This function forcibly terminates the specified process, which will release
/// any file locks held by that process. Use with caution as terminating processes
/// can lead to data loss if the process was in the middle of writing data.
///
/// # Arguments
///
/// * `pid` - The process ID of the process to terminate
///
/// # Returns
///
/// Returns `WholockResult<()>` indicating success or failure
///
/// # Errors
///
/// Returns a `WholockError` if:
/// - The provided PID is invalid or doesn't exist
/// - The PID identifies the current process or a protected system process
/// - The process cannot be opened with termination rights
/// - The process termination fails
///
/// # Examples
///
/// ```no_run
/// use wholock::{unlock_process, who_locks_file};
///
/// // Find processes locking a file
/// let scan = who_locks_file("C:\\path\\to\\file.txt").unwrap();
///
/// // Terminate the first process found
/// if let Some(process) = scan.processes().first() {
///     match unlock_process(process.pid) {
///         Ok(_) => println!("Successfully terminated process {}", process.pid),
///         Err(e) => println!("Failed to terminate process: {:?}", e),
///     }
/// }
/// ```
pub fn unlock_process(pid: u32) -> WholockResult<()> {
    terminate_process_by_pid(pid)
}

/// Terminates all processes in a lock query result.
///
/// Each process is attempted independently and the returned vector contains one
/// result per unique PID. Before termination, this opens a stable process handle,
/// verifies the scan-time process instance and executable identity through that
/// handle, and confirms the process still appears in a fresh lock query.
///
/// # Arguments
///
/// * `processes` - Process lock results, usually returned by [`who_locks_file`](crate::who_locks_file)
///   or [`scan_locks`](crate::scan_locks)
///
/// # Returns
///
/// Returns one [`UnlockProcessResult`] per unique PID. Each item contains the public
/// `WholockResult<()>` and structured failure details when termination failed.
///
/// # Errors
///
/// This function does not return a top-level error. Per-process failures are reported
/// in each [`UnlockProcessResult`].
///
/// # Examples
///
/// ```no_run
/// use wholock::{unlock_processes, who_locks_file};
///
/// let scan = who_locks_file("C:\\path\\to\\file.txt")?;
/// let results = unlock_processes(scan.processes());
///
/// for result in results {
///     if result.is_success() {
///         println!("terminated {}", result.pid);
///     } else if let Some(reason) = result.failure_reason() {
///         println!("failed to terminate {}: {}", result.pid, reason);
///     }
/// }
/// # Ok::<(), wholock::error::WholockError>(())
/// ```
pub fn unlock_processes(processes: &[ProcessInfo]) -> Vec<UnlockProcessResult> {
    let mut seen = BTreeSet::new();
    processes
        .iter()
        .filter(|process| seen.insert(process.pid))
        .map(|process| {
            let detailed_result = terminate_process_from_snapshot(process);
            let failure = detailed_result.err();
            let result = failure
                .as_ref()
                .map_or(Ok(()), |failure| Err(failure.to_wholock_error()));

            UnlockProcessResult {
                pid: process.pid,
                process_name: process.process_name.clone(),
                result,
                failure,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{LockMatch, LockMatchSource};

    fn process_snapshot(
        pid: u32,
        process_name: &str,
        process_exe_path: &str,
        process_instance_id: Option<u64>,
    ) -> ProcessInfo {
        ProcessInfo {
            pid,
            process_name: process_name.to_string(),
            process_exe_path: process_exe_path.to_string(),
            domain_username: String::new(),
            locked_file: vec![r"C:\data\locked.txt".to_string()],
            matches: vec![LockMatch::new(
                r"C:\data\locked.txt".to_string(),
                LockMatchSource::FileHandle,
            )],
            process_instance_id,
        }
    }

    fn process_identity(
        process_name: &str,
        process_exe_path: &str,
        creation_time: u64,
    ) -> ProcessIdentity {
        ProcessIdentity {
            process_name: process_name.to_string(),
            process_exe_path: process_exe_path.to_string(),
            creation_time,
        }
    }

    #[test]
    fn test_unlock_processes_empty() {
        assert!(unlock_processes(&[]).is_empty());
    }

    #[test]
    fn test_unlock_processes_reports_invalid_pid_once() {
        let processes = vec![
            process_snapshot(u32::MAX, "missing.exe", "", None),
            process_snapshot(u32::MAX, "missing-again.exe", "", None),
        ];

        let results = unlock_processes(&processes);

        assert_eq!(results.len(), 1);
        assert_eq!(results[0].pid, u32::MAX);
        assert_eq!(results[0].process_name, "missing.exe");
        assert!(!results[0].is_success());
        assert_eq!(
            results[0].failure.as_ref().map(|failure| failure.kind),
            Some(ProcessTerminationFailureKind::InvalidPid)
        );
        assert!(
            results[0]
                .failure_reason()
                .is_some_and(|reason| reason.contains("Invalid PID"))
        );
        assert!(matches!(
            &results[0].result,
            Err(WholockError::InvalidPID(pid)) if *pid == u32::MAX
        ));
    }

    #[test]
    fn test_unlock_process_rejects_protected_system_pid() {
        let result = unlock_process(4);

        assert!(matches!(result, Err(WholockError::PermissionError(_))));
    }

    #[test]
    fn test_unlock_process_rejects_current_process() {
        let result = unlock_process(std::process::id());

        assert!(matches!(result, Err(WholockError::PermissionError(_))));
    }

    #[test]
    fn test_protected_process_name_reason() {
        assert_eq!(
            protected_process_name_reason("lsass.exe"),
            Some("lsass.exe")
        );
        assert_eq!(
            protected_process_name_reason("LSASS.EXE"),
            Some("lsass.exe")
        );
        assert_eq!(protected_process_name_reason("notepad.exe"), None);
        assert_eq!(protected_process_name_reason(""), None);
    }

    #[test]
    fn test_process_identity_matches_snapshot_detects_name_change() {
        let process = process_snapshot(42, "expected.exe", "", Some(100));
        let current = process_identity("replacement.exe", "", 100);

        let result = process_identity_matches_snapshot(&process, &current);

        assert!(matches!(
            result,
            Err(ProcessTerminationFailure {
                kind: ProcessTerminationFailureKind::StaleProcessIdentity,
                ..
            })
        ));
    }

    #[test]
    fn test_process_identity_matches_snapshot_detects_pid_reuse() {
        let process = process_snapshot(42, "worker.exe", r"C:\apps\worker.exe", Some(100));
        let current = process_identity("worker.exe", r"C:\apps\worker.exe", 200);

        let result = process_identity_matches_snapshot(&process, &current);

        assert!(matches!(
            result,
            Err(ProcessTerminationFailure {
                kind: ProcessTerminationFailureKind::StaleProcessIdentity,
                ..
            })
        ));
    }

    #[test]
    fn test_process_identity_matches_snapshot_requires_instance_id() {
        let process = process_snapshot(42, "worker.exe", r"C:\apps\worker.exe", None);
        let current = process_identity("worker.exe", r"C:\apps\worker.exe", 100);

        let result = process_identity_matches_snapshot(&process, &current);

        assert!(matches!(
            result,
            Err(ProcessTerminationFailure {
                kind: ProcessTerminationFailureKind::StaleProcessIdentity,
                ..
            })
        ));
    }

    #[test]
    fn test_process_identity_matches_snapshot_accepts_same_instance() {
        let process = process_snapshot(42, "worker.exe", r"C:\apps\worker.exe", Some(100));
        let current = process_identity("worker.exe", r"C:\apps\worker.exe", 100);

        assert!(process_identity_matches_snapshot(&process, &current).is_ok());
    }

    #[test]
    fn test_process_still_holds_snapshot_locks_rejects_empty_snapshot() {
        let mut process = process_snapshot(std::process::id(), "", "", Some(100));
        process.locked_file.clear();
        process.matches.clear();

        let result = process_still_holds_snapshot_locks(&process);

        assert!(matches!(
            result,
            Err(ProcessTerminationFailure {
                kind: ProcessTerminationFailureKind::LockVerification,
                ..
            })
        ));
    }

    #[test]
    fn test_unlock_processes_reports_protected_system_pid() {
        let processes = vec![process_snapshot(4, "System", "", Some(100))];

        let results = unlock_processes(&processes);

        assert_eq!(results.len(), 1);
        assert_eq!(
            results[0].failure.as_ref().map(|failure| failure.kind),
            Some(ProcessTerminationFailureKind::ProtectedProcess)
        );
        assert!(matches!(
            &results[0].result,
            Err(WholockError::PermissionError(_))
        ));
    }
}
