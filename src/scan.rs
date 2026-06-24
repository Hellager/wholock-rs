use crate::elevation::enable_debug_privilege;
use crate::error::{LockScanWarning, LockScanWarningKind, WholockError};
use crate::interop::{
    LockedPathMatchers, PROCESS_ACCESS_RIGHTS_DUP_HANDLE, PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION,
    SYSTEM_EXTENDED_HANDLE_INFORMATION, duplicate_handle_value, get_final_path_name_by_handle,
    get_handle_owner_info, get_handle_table, get_process_info, get_process_module_paths,
    is_file_handle, query_system_information_buffer,
};
use crate::{WholockResult, types::ProcessInfo};
use itertools::Itertools;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::{
    Arc, Mutex,
    atomic::{AtomicUsize, Ordering},
    mpsc::{self, RecvTimeoutError},
};
use std::time::Duration;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess};

const HANDLE_PROBE_TIMEOUT: Duration = Duration::from_millis(200);
const MAX_ACTIVE_HANDLE_PROBE_WORKERS: usize = 32;
static ACTIVE_HANDLE_PROBE_WORKERS: AtomicUsize = AtomicUsize::new(0);

pub(crate) struct HandleWrapper(HANDLE);

impl HandleWrapper {
    pub(crate) fn new(handle: HANDLE) -> Self {
        HandleWrapper(handle)
    }

    pub(crate) fn get(&self) -> HANDLE {
        self.0
    }

    fn is_invalid(&self) -> bool {
        self.0.is_invalid()
    }
}

impl Drop for HandleWrapper {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: `HandleWrapper` owns this handle and only calls CloseHandle
            // once from Drop after confirming it is not an invalid handle value.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

struct ActiveHandleProbeWorkerGuard;

impl Drop for ActiveHandleProbeWorkerGuard {
    fn drop(&mut self) {
        ACTIVE_HANDLE_PROBE_WORKERS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn acquire_active_handle_probe_worker() -> Option<ActiveHandleProbeWorkerGuard> {
    loop {
        let current = ACTIVE_HANDLE_PROBE_WORKERS.load(Ordering::Acquire);
        if current >= MAX_ACTIVE_HANDLE_PROBE_WORKERS {
            return None;
        }

        if ACTIVE_HANDLE_PROBE_WORKERS
            .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
            .is_ok()
        {
            return Some(ActiveHandleProbeWorkerGuard);
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
enum HandleProbeOutcome {
    Path(String),
    NoMatch,
    TimedOut,
    WorkerLimitReached,
    WorkerDisconnected,
    WorkerPanicked,
    SpawnFailed(String),
}

fn run_handle_probe_with_timeout<F>(timeout: Duration, probe: F) -> HandleProbeOutcome
where
    F: FnOnce() -> WholockResult<Option<String>> + Send + 'static,
{
    if timeout.is_zero() {
        return HandleProbeOutcome::TimedOut;
    }

    let Some(active_worker) = acquire_active_handle_probe_worker() else {
        return HandleProbeOutcome::WorkerLimitReached;
    };
    let (tx, rx) = mpsc::channel();

    let spawn_result = std::thread::Builder::new()
        .name("wholock-handle-probe".into())
        .spawn(move || {
            let _active_worker = active_worker;
            let result = std::panic::catch_unwind(AssertUnwindSafe(probe));
            let _ = tx.send(result);
        });

    if let Err(err) = spawn_result {
        return HandleProbeOutcome::SpawnFailed(err.to_string());
    }

    match rx.recv_timeout(timeout) {
        Ok(Ok(Ok(Some(path)))) => HandleProbeOutcome::Path(path),
        Ok(Ok(Ok(None) | Err(_))) => HandleProbeOutcome::NoMatch,
        Ok(Err(_)) => HandleProbeOutcome::WorkerPanicked,
        Err(RecvTimeoutError::Timeout) => HandleProbeOutcome::TimedOut,
        Err(RecvTimeoutError::Disconnected) => HandleProbeOutcome::WorkerDisconnected,
    }
}

fn probe_handle_path_blocking(pid: u32, source_handle: usize) -> WholockResult<Option<String>> {
    // SAFETY: OpenProcess is called with a PID read from the system handle table.
    // The returned process HANDLE is owned by this worker and closed by
    // `HandleWrapper` before the worker exits.
    let Ok(handle_owner_process) = (unsafe {
        OpenProcess(
            PROCESS_ACCESS_RIGHTS_DUP_HANDLE | PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION,
            false,
            pid,
        )
    }) else {
        return Ok(None);
    };
    let handle_owner_process = HandleWrapper::new(handle_owner_process);
    if handle_owner_process.is_invalid() {
        return Ok(None);
    }

    // SAFETY: GetCurrentProcess returns the documented pseudo-handle for the
    // current process. It must not be closed and is only passed to DuplicateHandle.
    let current_process = unsafe { GetCurrentProcess() };
    let Ok(dup_handle) =
        duplicate_handle_value(current_process, handle_owner_process.get(), source_handle)
    else {
        return Ok(None);
    };
    let dup_handle = HandleWrapper::new(dup_handle);
    if dup_handle.is_invalid() {
        return Ok(None);
    }

    if !is_file_handle(dup_handle.get()) {
        return Ok(None);
    }

    Ok(get_final_path_name_by_handle(&dup_handle.get()).ok())
}

fn probe_handle_path_with_timeout(pid: u32, source_handle: usize) -> HandleProbeOutcome {
    run_handle_probe_with_timeout(HANDLE_PROBE_TIMEOUT, move || {
        probe_handle_path_blocking(pid, source_handle)
    })
}

struct ProcessLockCollector {
    pid: u32,
    domain_username: Option<String>,
    locked_files: BTreeSet<String>,
}

impl ProcessLockCollector {
    fn new(pid: u32) -> Self {
        Self {
            pid,
            domain_username: None,
            locked_files: BTreeSet::new(),
        }
    }

    fn with_locked_files(
        pid: u32,
        domain_username: Option<String>,
        locked_files: BTreeSet<String>,
    ) -> Self {
        Self {
            pid,
            domain_username,
            locked_files,
        }
    }

    fn insert_path(&mut self, path: String) {
        self.locked_files.insert(path);
    }

    fn into_process_info(self) -> ProcessInfo {
        let domain_username = self.domain_username.unwrap_or_default();
        let (process_name, process_exe_path) = get_process_info(self.pid).unwrap_or_default();

        ProcessInfo {
            pid: self.pid,
            process_name,
            process_exe_path,
            domain_username,
            locked_file: self.locked_files.into_iter().collect(),
        }
    }
}

fn handle_scan_worker_count(task_count: usize) -> usize {
    let available = std::thread::available_parallelism()
        .map(|count| count.get())
        .unwrap_or(4);
    available.clamp(1, task_count.max(1))
}

fn collect_handle_locks_parallel(
    handle_groups: Vec<(u32, Vec<usize>)>,
    matchers: Arc<LockedPathMatchers>,
) -> (BTreeMap<u32, ProcessLockCollector>, Vec<LockScanWarning>) {
    if handle_groups.is_empty() {
        return (BTreeMap::new(), Vec::new());
    }

    let worker_count = handle_scan_worker_count(handle_groups.len());
    let queue = Arc::new(Mutex::new(VecDeque::from(handle_groups)));
    let (tx, rx) = std::sync::mpsc::channel();
    let mut workers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        let matchers = Arc::clone(&matchers);
        workers.push(std::thread::spawn(move || {
            loop {
                let task = queue.lock().ok().and_then(|mut queue| queue.pop_front());
                let Some((pid, handle_values)) = task else {
                    break;
                };

                let scan_result = scan_process_handles(pid, &handle_values, &matchers);
                let _ = tx.send(scan_result);
            }
        }));
    }

    drop(tx);

    let mut result = BTreeMap::new();
    let mut warnings = Vec::new();
    for process_scan in rx {
        if let Some(process_info) = process_scan.process_info {
            result.insert(process_info.pid, process_info);
        }
        warnings.extend(process_scan.warnings);
    }

    for worker in workers {
        let _ = worker.join();
    }

    (result, warnings)
}

struct ProcessHandleScanResult {
    process_info: Option<ProcessLockCollector>,
    warnings: Vec<LockScanWarning>,
}

impl ProcessHandleScanResult {
    fn with_process_info(
        process_info: ProcessLockCollector,
        warnings: Vec<LockScanWarning>,
    ) -> Self {
        Self {
            process_info: Some(process_info),
            warnings,
        }
    }
}

fn partial_scan_error(processes: Vec<ProcessInfo>, warnings: Vec<LockScanWarning>) -> WholockError {
    WholockError::PartialLockScan {
        processes,
        warnings,
    }
}

fn finish_lock_scan(
    result: BTreeMap<u32, ProcessLockCollector>,
    warnings: Vec<LockScanWarning>,
) -> WholockResult<Vec<ProcessInfo>> {
    let processes = result
        .into_values()
        .map(ProcessLockCollector::into_process_info)
        .collect::<Vec<_>>();

    if warnings.is_empty() {
        Ok(processes)
    } else {
        Err(partial_scan_error(processes, warnings))
    }
}

fn scan_process_handles(
    pid: u32,
    handle_values: &[usize],
    matchers: &LockedPathMatchers,
) -> ProcessHandleScanResult {
    if let Err(warning) = verify_process_can_be_scanned(pid) {
        return ProcessHandleScanResult {
            process_info: None,
            warnings: vec![warning],
        };
    }

    let mut locked_files = BTreeSet::new();
    let mut warnings = Vec::new();

    for handle_value in handle_values {
        match probe_handle_path_with_timeout(pid, *handle_value) {
            HandleProbeOutcome::Path(full_name) => {
                if matchers.matches(&full_name) {
                    locked_files.insert(full_name);
                }
            }
            HandleProbeOutcome::NoMatch => {}
            HandleProbeOutcome::TimedOut => warnings.push(LockScanWarning::new(
                Some(pid),
                LockScanWarningKind::HandleEnumeration,
                format!(
                    "handle {handle_value:#x} did not finish within {}ms",
                    HANDLE_PROBE_TIMEOUT.as_millis()
                ),
            )),
            HandleProbeOutcome::WorkerLimitReached => warnings.push(LockScanWarning::new(
                Some(pid),
                LockScanWarningKind::HandleEnumeration,
                "too many timed-out handle probes are still running",
            )),
            HandleProbeOutcome::WorkerDisconnected => warnings.push(LockScanWarning::new(
                Some(pid),
                LockScanWarningKind::HandleEnumeration,
                format!("handle {handle_value:#x} probe worker disconnected"),
            )),
            HandleProbeOutcome::WorkerPanicked => warnings.push(LockScanWarning::new(
                Some(pid),
                LockScanWarningKind::HandleEnumeration,
                format!("handle {handle_value:#x} probe worker panicked"),
            )),
            HandleProbeOutcome::SpawnFailed(message) => warnings.push(LockScanWarning::new(
                Some(pid),
                LockScanWarningKind::HandleEnumeration,
                format!("failed to spawn handle probe worker: {message}"),
            )),
        }
    }

    if locked_files.is_empty() {
        return ProcessHandleScanResult {
            process_info: None,
            warnings,
        };
    }

    let domain_username = get_process_owner_info(pid).ok();
    ProcessHandleScanResult::with_process_info(
        ProcessLockCollector::with_locked_files(pid, domain_username, locked_files),
        warnings,
    )
}

fn verify_process_can_be_scanned(pid: u32) -> Result<(), LockScanWarning> {
    // SAFETY: OpenProcess is called with a concrete PID from the system handle
    // table. The returned process HANDLE is used only as a capability preflight
    // and is closed before any timeout-protected worker is spawned.
    let Ok(handle) = (unsafe {
        OpenProcess(
            PROCESS_ACCESS_RIGHTS_DUP_HANDLE | PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION,
            false,
            pid,
        )
    }) else {
        return Err(LockScanWarning::new(
            Some(pid),
            LockScanWarningKind::OpenProcess,
            "failed to open process for handle duplication",
        ));
    };

    let handle = HandleWrapper::new(handle);
    if handle.is_invalid() {
        return Err(LockScanWarning::new(
            Some(pid),
            LockScanWarningKind::OpenProcess,
            "OpenProcess returned an invalid handle",
        ));
    }

    Ok(())
}

fn get_process_owner_info(pid: u32) -> WholockResult<String> {
    // SAFETY: OpenProcess is called with a concrete PID and returns an owned
    // process HANDLE on success, which is wrapped in `HandleWrapper` for cleanup.
    let handle = unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION, false, pid) }?;
    let handle = HandleWrapper::new(handle);
    if handle.is_invalid() {
        return Ok(String::new());
    }

    get_handle_owner_info(handle.get())
}

fn module_scan_warning(pid: u32, err: WholockError) -> LockScanWarning {
    LockScanWarning::new(
        Some(pid),
        LockScanWarningKind::ModuleEnumeration,
        err.to_string(),
    )
}

fn debug_privilege_error(err: WholockError) -> WholockError {
    WholockError::permission(format!(
        "Failed to enable SeDebugPrivilege before scanning locks: {err}"
    ))
}

/// Identifies all processes that have locked a specified file.
///
/// This is a compatibility wrapper around [`find_processes_recursive`].
///
/// # Arguments
///
/// * `path` - The path to the file to check, can be relative or absolute
///
/// # Returns
///
/// Returns `WholockResult<Vec<ProcessInfo>>` containing information about all processes
/// that have locked the file. Each `ProcessInfo` includes process ID, name, executable path,
/// user information, and a list of locked file paths.
///
/// # Errors
///
/// Returns a `WholockError` if system handle information cannot be queried or if other
/// errors occur during processing.
///
/// # Examples
///
/// ```no_run
/// use wholock::{who_locks_file, ProcessInfo};
///
/// match who_locks_file("C:\\path\\to\\file.txt") {
///     Ok(processes) => {
///         for process in processes {
///             println!("Process {} ({}) has locked the file", process.process_name, process.pid);
///         }
///     },
///     Err(e) => println!("Error occurred: {:?}", e),
/// }
/// ```
pub fn who_locks_file(path: &str) -> WholockResult<Vec<ProcessInfo>> {
    find_processes_recursive(std::iter::once(path))
}

/// Identifies all processes that have locked any of the specified files or directories.
///
/// Directory inputs are matched recursively, so files and loaded modules underneath a
/// requested directory are included in the result. Empty, malformed, inaccessible, or
/// missing paths return [`WholockError::PathError`].
///
/// # Arguments
///
/// * `paths` - The file and directory paths to check, each as a string-like value
///
/// # Returns
///
/// Returns `WholockResult<Vec<ProcessInfo>>` containing every process that matched at
/// least one requested path.
///
/// # Errors
///
/// Returns a `WholockError` if any path is invalid, if system handle information cannot
/// be queried, or if scanning only produced a partial result with warnings.
///
/// # Examples
///
/// ```no_run
/// use wholock::who_locks_files;
///
/// let processes = who_locks_files([
///     "C:\\path\\to\\file.txt",
///     "C:\\path\\to\\directory",
/// ])?;
///
/// for process in processes {
///     println!("{} locks {:?}", process.process_name, process.locked_file);
/// }
/// # Ok::<(), wholock::error::WholockError>(())
/// ```
pub fn who_locks_files<I, P>(paths: I) -> WholockResult<Vec<ProcessInfo>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    find_processes_recursive(paths)
}

/// Identifies all processes that have locked any of the specified files or directories.
///
/// This mirrors PowerToys File Locksmith's recursive multi-path query shape.
/// Directory inputs are matched recursively, and all paths are checked during one
/// system handle/module scan. Empty, malformed, inaccessible, or missing paths
/// return [`WholockError::PathError`].
///
/// # Arguments
///
/// * `paths` - The file and directory paths to scan recursively
///
/// # Returns
///
/// Returns `WholockResult<Vec<ProcessInfo>>` containing information about all matching
/// lock holders. Directory inputs match files and loaded modules below that directory.
///
/// # Errors
///
/// Returns a `WholockError` if path validation fails, if debug privilege setup fails,
/// if the system handle table cannot be queried, or if the scan result is partial.
///
/// # Examples
///
/// ```no_run
/// use wholock::find_processes_recursive;
///
/// let processes = find_processes_recursive(vec!["C:\\work", "C:\\data\\locked.txt"])?;
///
/// for process in processes {
///     println!("PID {}: {}", process.pid, process.process_name);
/// }
/// # Ok::<(), wholock::error::WholockError>(())
/// ```
pub fn find_processes_recursive<I, P>(paths: I) -> WholockResult<Vec<ProcessInfo>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    let matchers = LockedPathMatchers::new(paths)?;
    if matchers.is_empty() {
        return Ok(Vec::new());
    }

    enable_debug_privilege().map_err(debug_privilege_error)?;

    let mut result: BTreeMap<u32, ProcessLockCollector> = BTreeMap::new();
    let mut warnings = Vec::new();
    let matchers = Arc::new(matchers);

    let buffer = query_system_information_buffer(SYSTEM_EXTENDED_HANDLE_INFORMATION)?;
    let table = get_handle_table(&buffer)?;
    let handle_groups = table
        .iter()
        .filter_map(|handle| {
            let pid = u32::try_from(handle.unique_process_id()).ok()?;
            Some((pid, handle.handle_value_raw()))
        })
        .into_group_map();

    let (handle_results, handle_warnings) =
        collect_handle_locks_parallel(handle_groups.into_iter().collect(), Arc::clone(&matchers));
    result.extend(handle_results);
    warnings.extend(handle_warnings);

    let system = sysinfo::System::new_all();
    for pid in system
        .processes()
        .keys()
        .map(|pid| usize::from(*pid) as u32)
    {
        let module_paths = match get_process_module_paths(pid) {
            Ok(module_paths) => module_paths,
            Err(err) => {
                warnings.push(module_scan_warning(pid, err));
                continue;
            }
        };

        for module_path in module_paths {
            if matchers.matches(&module_path) {
                result
                    .entry(pid)
                    .or_insert_with(|| ProcessLockCollector::new(pid))
                    .insert_path(module_path);
            }
        }
    }

    finish_lock_scan(result, warnings)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    fn scan_or_skip_for_missing_debug_privilege(path: &str) -> Option<Vec<ProcessInfo>> {
        match who_locks_file(path) {
            Ok(processes) => Some(processes),
            Err(WholockError::PermissionError(message))
                if message.message().contains("SeDebugPrivilege") =>
            {
                eprintln!("skipping real lock scan test: {message}");
                None
            }
            Err(err) => panic!("lock scan failed: {err:?}"),
        }
    }

    #[test]
    fn test_find_processes_recursive_missing_paths_returns_error() {
        let dir = tempdir().unwrap();
        let paths = [
            dir.path().join("missing-a.txt"),
            dir.path().join("missing-b.txt"),
        ];
        let paths = paths
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert!(matches!(
            find_processes_recursive(paths),
            Err(WholockError::PathError(_))
        ));
    }

    #[test]
    fn test_find_processes_recursive_empty_path_returns_error() {
        assert!(matches!(
            find_processes_recursive(std::iter::once("")),
            Err(WholockError::PathError(_))
        ));
    }

    #[test]
    fn test_find_processes_recursive_nul_path_returns_error() {
        assert!(matches!(
            find_processes_recursive(std::iter::once("C:\\bad\0path")),
            Err(WholockError::PathError(_))
        ));
    }

    #[test]
    fn test_finish_lock_scan_returns_partial_error_with_warnings() {
        let warning = LockScanWarning::new(
            Some(42),
            LockScanWarningKind::HandleEnumeration,
            "handle probe timed out",
        );
        let result = finish_lock_scan(BTreeMap::new(), vec![warning]);

        assert!(matches!(
            result,
            Err(WholockError::PartialLockScan {
                processes,
                warnings,
            }) if processes.is_empty() && warnings.len() == 1
        ));
    }

    #[test]
    fn test_partial_lock_scan_display_mentions_warning() {
        let error = WholockError::PartialLockScan {
            processes: Vec::new(),
            warnings: vec![LockScanWarning::new(
                Some(42),
                LockScanWarningKind::ModuleEnumeration,
                "access is denied",
            )],
        };
        let message = error.to_string();

        assert!(message.contains("Partial lock scan"));
        assert!(message.contains("PID 42"));
        assert!(message.contains("module enumeration"));
    }

    #[test]
    fn test_handle_probe_timeout_returns_timeout_outcome() {
        let result = run_handle_probe_with_timeout(Duration::from_millis(1), || {
            std::thread::sleep(Duration::from_millis(50));
            Ok(Some("C:\\slow.txt".to_string()))
        });

        assert_eq!(result, HandleProbeOutcome::TimedOut);
    }

    #[test]
    fn test_handle_probe_worker_panic_returns_panic_outcome() {
        let result = run_handle_probe_with_timeout(Duration::from_secs(1), || {
            panic!("deliberate handle probe panic");
        });

        assert_eq!(result, HandleProbeOutcome::WorkerPanicked);
    }

    #[test]
    fn test_debug_privilege_error_maps_to_permission_error() {
        let error = debug_privilege_error(WholockError::permission(
            "SeDebugPrivilege is not assigned".to_string(),
        ));

        assert!(
            matches!(error, WholockError::PermissionError(message) if message.message().contains("SeDebugPrivilege"))
        );
    }

    #[test]
    fn test_who_locks_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("locked.txt");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "test content").unwrap();

        let Some(processes) = scan_or_skip_for_missing_debug_privilege(file_path.to_str().unwrap())
        else {
            return;
        };
        assert!(!processes.is_empty());

        let current_process = processes
            .iter()
            .find(|process| process.pid == std::process::id())
            .expect("current process should hold the open file");
        assert!(!current_process.locked_file.is_empty());
        assert!(
            current_process
                .locked_file
                .iter()
                .any(|f| f.contains("locked.txt"))
        );
    }
}
