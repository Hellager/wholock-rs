use crate::WholockResult;
use crate::error::WholockError;
use crate::interop::get_process_info;
use crate::scan::HandleWrapper;
use crate::scan::find_processes_recursive;
use crate::types::{
    ProcessInfo, ProcessTerminationFailure, ProcessTerminationFailureKind, UnlockProcessResult,
};
use std::collections::BTreeSet;
use windows::Win32::System::Threading::{OpenProcess, TerminateProcess};

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

fn check_pid_can_be_terminated(pid: u32) -> Result<(), ProcessTerminationFailure> {
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

    if let Ok((process_name, _)) = get_process_info(pid) {
        if let Some(reason) = protected_process_name_reason(&process_name) {
            return Err(ProcessTerminationFailure {
                pid,
                kind: ProcessTerminationFailureKind::ProtectedProcess,
                reason: format!("protected process name {reason}"),
            });
        }
    }

    Ok(())
}

fn normalize_process_identity(value: &str) -> String {
    value
        .trim_end_matches('\0')
        .replace('/', "\\")
        .to_lowercase()
}

fn process_identity_matches_snapshot(
    pid: u32,
    expected: &ProcessInfo,
) -> Result<(), ProcessTerminationFailure> {
    let (current_name, current_exe_path) =
        get_process_info(pid).map_err(|err| ProcessTerminationFailure {
            pid,
            kind: ProcessTerminationFailureKind::StaleProcessIdentity,
            reason: format!("failed to read current process identity: {err}"),
        })?;

    if !expected.process_exe_path.is_empty()
        && !current_exe_path.is_empty()
        && normalize_process_identity(&expected.process_exe_path)
            != normalize_process_identity(&current_exe_path)
    {
        return Err(ProcessTerminationFailure {
            pid,
            kind: ProcessTerminationFailureKind::StaleProcessIdentity,
            reason: format!(
                "expected executable path '{}', found '{}'",
                expected.process_exe_path, current_exe_path
            ),
        });
    }

    if expected.process_exe_path.is_empty()
        && !expected.process_name.is_empty()
        && !current_name.eq_ignore_ascii_case(&expected.process_name)
    {
        return Err(ProcessTerminationFailure {
            pid,
            kind: ProcessTerminationFailureKind::StaleProcessIdentity,
            reason: format!(
                "expected process name '{}', found '{}'",
                expected.process_name, current_name
            ),
        });
    }

    Ok(())
}

fn process_still_holds_snapshot_locks(
    process: &ProcessInfo,
) -> Result<(), ProcessTerminationFailure> {
    if process.locked_file.is_empty() {
        return Err(ProcessTerminationFailure {
            pid: process.pid,
            kind: ProcessTerminationFailureKind::LockVerification,
            reason: "query result did not record any locked paths".to_string(),
        });
    }

    let current_locks = find_processes_recursive(process.locked_file.iter().map(String::as_str))
        .map_err(|err| ProcessTerminationFailure {
            pid: process.pid,
            kind: ProcessTerminationFailureKind::LockVerification,
            reason: err.to_string(),
        })?;

    if current_locks
        .iter()
        .any(|current| current.pid == process.pid && !current.locked_file.is_empty())
    {
        return Ok(());
    }

    Err(ProcessTerminationFailure {
        pid: process.pid,
        kind: ProcessTerminationFailureKind::LockNoLongerHeld,
        reason: "lock query no longer reports this PID for the recorded paths".to_string(),
    })
}

fn terminate_checked_process(pid: u32) -> Result<(), ProcessTerminationFailure> {
    use windows::Win32::System::Threading::PROCESS_TERMINATE;

    // SAFETY: `pid` has passed the safety checks above. OpenProcess returns an
    // owned process HANDLE on success, wrapped by `HandleWrapper`; TerminateProcess
    // is called only with that live handle.
    unsafe {
        let process_handle = OpenProcess(PROCESS_TERMINATE, false, pid).map_err(|err| {
            ProcessTerminationFailure {
                pid,
                kind: ProcessTerminationFailureKind::OpenProcess,
                reason: err.to_string(),
            }
        })?;
        if process_handle.is_invalid() {
            return Err(ProcessTerminationFailure {
                pid,
                kind: ProcessTerminationFailureKind::OpenProcess,
                reason: "OpenProcess returned an invalid handle".to_string(),
            });
        }
        let process_handle = HandleWrapper::new(process_handle);

        if let Err(e) = TerminateProcess(process_handle.get(), 1) {
            return Err(ProcessTerminationFailure {
                pid,
                kind: ProcessTerminationFailureKind::TerminateProcess,
                reason: e.to_string(),
            });
        }

        Ok(())
    }
}

fn terminate_process_by_pid_detailed(pid: u32) -> Result<(), ProcessTerminationFailure> {
    check_pid_can_be_terminated(pid)?;
    terminate_checked_process(pid)
}

fn terminate_process_from_snapshot(process: &ProcessInfo) -> Result<(), ProcessTerminationFailure> {
    check_pid_can_be_terminated(process.pid)?;
    process_identity_matches_snapshot(process.pid, process)?;
    process_still_holds_snapshot_locks(process)?;
    terminate_checked_process(process.pid)
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
/// use wholock::{who_locks_file, unlock_file};
///
/// // Find processes locking a file
/// let processes = who_locks_file("C:\\path\\to\\file.txt").unwrap();
///
/// // Terminate the first process found
/// if let Some(process) = processes.first() {
///     match unlock_file(process.pid) {
///         Ok(_) => println!("Successfully terminated process {}", process.pid),
///         Err(e) => println!("Failed to terminate process: {:?}", e),
///     }
/// }
/// ```
pub fn unlock_file(pid: u32) -> WholockResult<()> {
    terminate_process_by_pid(pid)
}

/// Terminates all processes in a lock query result.
///
/// Each process is attempted independently and the returned vector contains one
/// result per unique PID. Before termination, this revalidates that the PID still
/// identifies the same executable and still appears in a fresh lock query for the
/// recorded locked paths.
///
/// # Arguments
///
/// * `processes` - Process lock results, usually returned by [`who_locks_file`](crate::who_locks_file)
///   or [`who_locks_files`](crate::who_locks_files)
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
/// let processes = who_locks_file("C:\\path\\to\\file.txt")?;
/// let results = unlock_processes(&processes);
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

    #[test]
    fn test_unlock_processes_empty() {
        assert!(unlock_processes(&[]).is_empty());
    }

    #[test]
    fn test_unlock_processes_reports_invalid_pid_once() {
        let processes = vec![
            ProcessInfo {
                pid: u32::MAX,
                process_name: "missing.exe".to_string(),
                process_exe_path: String::new(),
                domain_username: String::new(),
                locked_file: Vec::new(),
            },
            ProcessInfo {
                pid: u32::MAX,
                process_name: "missing-again.exe".to_string(),
                process_exe_path: String::new(),
                domain_username: String::new(),
                locked_file: Vec::new(),
            },
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
    fn test_unlock_file_rejects_protected_system_pid() {
        let result = unlock_file(4);

        assert!(matches!(result, Err(WholockError::PermissionError(_))));
    }

    #[test]
    fn test_unlock_file_rejects_current_process() {
        let result = unlock_file(std::process::id());

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
        let process = ProcessInfo {
            pid: std::process::id(),
            process_name: "definitely-not-current.exe".to_string(),
            process_exe_path: String::new(),
            domain_username: String::new(),
            locked_file: vec![r"C:\data\locked.txt".to_string()],
        };

        let result = process_identity_matches_snapshot(process.pid, &process);

        assert!(matches!(
            result,
            Err(ProcessTerminationFailure {
                kind: ProcessTerminationFailureKind::StaleProcessIdentity,
                ..
            })
        ));
    }

    #[test]
    fn test_process_still_holds_snapshot_locks_rejects_empty_snapshot() {
        let process = ProcessInfo {
            pid: std::process::id(),
            process_name: String::new(),
            process_exe_path: String::new(),
            domain_username: String::new(),
            locked_file: Vec::new(),
        };

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
        let processes = vec![ProcessInfo {
            pid: 4,
            process_name: "System".to_string(),
            process_exe_path: String::new(),
            domain_username: String::new(),
            locked_file: Vec::new(),
        }];

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
