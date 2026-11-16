use crate::elevation::enable_debug_privilege;
use crate::error::{LockScanWarning, LockScanWarningKind, WholockError, get_win32_error_message};
use crate::interop::{
    LockedPathMatchers, PROCESS_ACCESS_RIGHTS_DUP_HANDLE, PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION,
    ResolvedFilePath, SYSTEM_EXTENDED_HANDLE_INFORMATION, duplicate_handle_value,
    get_file_paths_by_handle, get_handle_owner_info, get_handle_table, get_process_identity,
    get_process_module_paths, is_disk_file_handle, kernel_path_for_path,
    query_system_information_buffer,
};
use crate::{
    WholockResult,
    types::{LockScanOptions, LockScanResult, ProcessInfo},
};
use itertools::Itertools;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::{
    Arc, Mutex,
    mpsc::{self, RecvTimeoutError},
};
use std::time::Duration;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess};

const MAX_ABANDONED_HANDLE_PROBE_WORKERS: usize = 8;

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

#[derive(Debug, PartialEq, Eq)]
enum HandleProbeOutcome {
    Path(ResolvedFilePath),
    NoMatch,
    TimedOut,
    WorkerLimitReached,
    WorkerDisconnected,
    WorkerPanicked,
    SpawnFailed(String),
    ProbeFailed(String),
}

type HandleProbeFunction =
    dyn Fn(HANDLE, usize) -> WholockResult<Option<ResolvedFilePath>> + Send + Sync + 'static;

struct HandleProbeRequest {
    pid: u32,
    source_handle: usize,
    reply: mpsc::Sender<HandleProbeReply>,
}

type HandleProbeReply =
    Result<WholockResult<Option<ResolvedFilePath>>, Box<dyn std::any::Any + Send>>;

struct HandleProbeWorker {
    probe: Arc<HandleProbeFunction>,
    sender: Option<mpsc::Sender<HandleProbeRequest>>,
    abandoned_workers: usize,
}

impl HandleProbeWorker {
    fn new<F>(probe: F) -> Self
    where
        F: Fn(HANDLE, usize) -> WholockResult<Option<ResolvedFilePath>> + Send + Sync + 'static,
    {
        Self {
            probe: Arc::new(probe),
            sender: None,
            abandoned_workers: 0,
        }
    }

    fn ensure_worker(&mut self) -> Result<(), HandleProbeOutcome> {
        if self.sender.is_some() {
            return Ok(());
        }

        if self.abandoned_workers >= MAX_ABANDONED_HANDLE_PROBE_WORKERS {
            return Err(HandleProbeOutcome::WorkerLimitReached);
        }

        let (sender, receiver) = mpsc::channel::<HandleProbeRequest>();
        let probe = Arc::clone(&self.probe);
        std::thread::Builder::new()
            .name("wholock-handle-probe".into())
            .spawn(move || {
                let mut cached_owner_process: Option<(u32, HandleWrapper)> = None;
                while let Ok(request) = receiver.recv() {
                    if cached_owner_process
                        .as_ref()
                        .is_some_and(|(cached_pid, _)| *cached_pid != request.pid)
                    {
                        cached_owner_process = None;
                    }

                    if cached_owner_process.is_none() {
                        cached_owner_process = open_handle_owner_process(request.pid);
                    }

                    let result = std::panic::catch_unwind(AssertUnwindSafe(|| {
                        cached_owner_process
                            .as_ref()
                            .map_or(Ok(None), |(_, handle)| {
                                (probe)(handle.get(), request.source_handle)
                            })
                    }));
                    let _ = request.reply.send(result);
                }
            })
            .map_err(|err| HandleProbeOutcome::SpawnFailed(err.to_string()))?;

        self.sender = Some(sender);
        Ok(())
    }

    fn probe(&mut self, pid: u32, source_handle: usize, timeout: Duration) -> HandleProbeOutcome {
        if timeout.is_zero() {
            return HandleProbeOutcome::TimedOut;
        }

        if let Err(outcome) = self.ensure_worker() {
            return outcome;
        }

        let (reply, result) = mpsc::channel();
        let request = HandleProbeRequest {
            pid,
            source_handle,
            reply,
        };

        let Some(sender) = self.sender.as_ref() else {
            return HandleProbeOutcome::WorkerDisconnected;
        };
        if sender.send(request).is_err() {
            self.sender = None;
            return HandleProbeOutcome::WorkerDisconnected;
        }

        match result.recv_timeout(timeout) {
            Ok(Ok(Ok(Some(path)))) => HandleProbeOutcome::Path(path),
            Ok(Ok(Ok(None))) => HandleProbeOutcome::NoMatch,
            Ok(Ok(Err(error))) => HandleProbeOutcome::ProbeFailed(error.to_string()),
            Ok(Err(_)) => HandleProbeOutcome::WorkerPanicked,
            Err(RecvTimeoutError::Timeout) => {
                self.sender = None;
                self.abandoned_workers += 1;
                HandleProbeOutcome::TimedOut
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.sender = None;
                HandleProbeOutcome::WorkerDisconnected
            }
        }
    }
}

fn open_handle_owner_process(pid: u32) -> Option<(u32, HandleWrapper)> {
    // SAFETY: OpenProcess is called with a PID read from the system handle table.
    // The returned process HANDLE is owned by the probe worker and closed when
    // the worker switches to another PID or exits.
    let handle = unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS_DUP_HANDLE, false, pid) }.ok()?;
    let handle = HandleWrapper::new(handle);
    (!handle.is_invalid()).then_some((pid, handle))
}

fn probe_handle_path_blocking(
    handle_owner_process: HANDLE,
    source_handle: usize,
) -> WholockResult<Option<ResolvedFilePath>> {
    // SAFETY: GetCurrentProcess returns the documented pseudo-handle for the
    // current process. It must not be closed and is only passed to DuplicateHandle.
    let current_process = unsafe { GetCurrentProcess() };
    let Ok(dup_handle) =
        duplicate_handle_value(current_process, handle_owner_process, source_handle)
    else {
        return Ok(None);
    };
    let dup_handle = HandleWrapper::new(dup_handle);
    if dup_handle.is_invalid() {
        return Ok(None);
    }

    if !is_disk_file_handle(dup_handle.get()) {
        return Ok(None);
    }

    get_file_paths_by_handle(&dup_handle.get()).map(Some)
}

struct ProcessLockCollector {
    pid: u32,
    locked_files: BTreeSet<String>,
}

impl ProcessLockCollector {
    fn new(pid: u32) -> Self {
        Self {
            pid,
            locked_files: BTreeSet::new(),
        }
    }

    fn with_locked_files(pid: u32, locked_files: BTreeSet<String>) -> Self {
        Self { pid, locked_files }
    }

    fn insert_path(&mut self, path: String) {
        self.locked_files.insert(path);
    }

    fn into_process_info(self, warnings: &mut Vec<LockScanWarning>) -> ProcessInfo {
        let domain_username = match get_process_owner_info(self.pid) {
            Ok(username) => username,
            Err(err) => {
                warnings.push(process_metadata_warning(
                    self.pid,
                    format!("failed to query process owner: {err}"),
                ));
                String::new()
            }
        };
        let (process_name, process_exe_path, process_instance_id) =
            match get_process_identity(self.pid) {
                Ok(identity) => (
                    identity.process_name,
                    identity.process_exe_path,
                    Some(identity.creation_time),
                ),
                Err(err) => {
                    warnings.push(process_metadata_warning(
                        self.pid,
                        format!("failed to query process image metadata: {err}"),
                    ));
                    (String::new(), String::new(), None)
                }
            };

        ProcessInfo {
            pid: self.pid,
            process_name,
            process_exe_path,
            domain_username,
            locked_file: self.locked_files.into_iter().collect(),
            process_instance_id,
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
    handle_probe_timeout: Duration,
) -> (BTreeMap<u32, ProcessLockCollector>, Vec<LockScanWarning>) {
    if handle_groups.is_empty() {
        return (BTreeMap::new(), Vec::new());
    }

    let worker_count = handle_scan_worker_count(handle_groups.len());
    let queue = Arc::new(Mutex::new(VecDeque::from(handle_groups)));
    let (tx, rx) = std::sync::mpsc::channel();
    let mut workers = Vec::with_capacity(worker_count);
    let mut startup_warnings = Vec::new();

    for worker_index in 0..worker_count {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        let matchers = Arc::clone(&matchers);
        let worker = std::thread::Builder::new()
            .name(format!("wholock-handle-scan-{worker_index}"))
            .spawn(move || {
                let mut probe_worker = HandleProbeWorker::new(probe_handle_path_blocking);
                loop {
                    let task = match queue.lock() {
                        Ok(mut queue) => queue.pop_front(),
                        Err(_) => {
                            let _ = tx.send(ProcessHandleScanResult {
                                process_info: None,
                                warnings: vec![LockScanWarning::new(
                                    None,
                                    LockScanWarningKind::HandleEnumeration,
                                    "handle scan work queue was poisoned",
                                )],
                            });
                            break;
                        }
                    };
                    let Some((pid, handle_values)) = task else {
                        break;
                    };

                    let scan_result = scan_process_handles(
                        pid,
                        &handle_values,
                        &matchers,
                        handle_probe_timeout,
                        &mut probe_worker,
                    );
                    let _ = tx.send(scan_result);
                }
            });

        match worker {
            Ok(worker) => workers.push(worker),
            Err(err) => startup_warnings.push(LockScanWarning::new(
                None,
                LockScanWarningKind::HandleEnumeration,
                format!("failed to spawn handle scan worker {worker_index}: {err}"),
            )),
        }
    }

    drop(tx);

    let mut result = BTreeMap::new();
    let mut warnings = startup_warnings;
    for process_scan in rx {
        if let Some(process_info) = process_scan.process_info {
            result.insert(process_info.pid, process_info);
        }
        warnings.extend(process_scan.warnings);
    }

    for worker in workers {
        if worker.join().is_err() {
            warnings.push(LockScanWarning::new(
                None,
                LockScanWarningKind::HandleEnumeration,
                "handle scan worker panicked",
            ));
        }
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

fn finish_lock_scan(
    result: BTreeMap<u32, ProcessLockCollector>,
    mut warnings: Vec<LockScanWarning>,
) -> LockScanResult {
    let processes = result
        .into_values()
        .map(|collector| collector.into_process_info(&mut warnings))
        .collect::<Vec<_>>();

    LockScanResult::new(processes, warnings)
}

fn scan_process_handles(
    pid: u32,
    handle_values: &[usize],
    matchers: &LockedPathMatchers,
    handle_probe_timeout: Duration,
    probe_worker: &mut HandleProbeWorker,
) -> ProcessHandleScanResult {
    if let Err(warning) = verify_process_can_be_scanned(pid) {
        return ProcessHandleScanResult {
            process_info: None,
            warnings: vec![warning],
        };
    }

    let mut locked_files = BTreeSet::new();
    let mut warnings = Vec::new();
    let mut probe_failures = Vec::new();
    let mut kernel_path_failures = Vec::new();

    for handle_value in handle_values {
        match probe_worker.probe(pid, *handle_value, handle_probe_timeout) {
            HandleProbeOutcome::Path(paths) => {
                if let Some(error) = paths.kernel_path_error {
                    kernel_path_failures.push(format!("handle {handle_value:#x}: {error}"));
                }
                if matchers.matches_resolved(&paths.display_path, paths.kernel_path.as_deref()) {
                    locked_files.insert(paths.display_path);
                }
            }
            HandleProbeOutcome::NoMatch => {}
            HandleProbeOutcome::TimedOut => warnings.push(LockScanWarning::new(
                Some(pid),
                LockScanWarningKind::HandleEnumeration,
                format!(
                    "handle {handle_value:#x} did not finish within {}ms",
                    handle_probe_timeout.as_millis()
                ),
            )),
            HandleProbeOutcome::WorkerLimitReached => warnings.push(LockScanWarning::new(
                Some(pid),
                LockScanWarningKind::HandleEnumeration,
                "too many timed-out handle probe workers are still running",
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
            HandleProbeOutcome::ProbeFailed(message) => {
                probe_failures.push(format!("handle {handle_value:#x}: {message}"));
            }
        }
    }

    if !probe_failures.is_empty() {
        let details = probe_failures.iter().take(3).join("; ");
        let suffix = (probe_failures.len() > 3).then_some("; additional failures omitted");
        warnings.push(LockScanWarning::new(
            Some(pid),
            LockScanWarningKind::HandleEnumeration,
            format!(
                "failed to resolve {} file handle path(s): {details}{}",
                probe_failures.len(),
                suffix.unwrap_or_default()
            ),
        ));
    }

    if !kernel_path_failures.is_empty() {
        let details = kernel_path_failures.iter().take(3).join("; ");
        let suffix = if kernel_path_failures.len() > 3 {
            "; additional failures omitted"
        } else {
            ""
        };
        warnings.push(LockScanWarning::new(
            Some(pid),
            LockScanWarningKind::HandleEnumeration,
            format!(
                "failed to resolve NT paths for {} disk handle(s); display-path matching continued: {details}{suffix}",
                kernel_path_failures.len()
            ),
        ));
    }

    if locked_files.is_empty() {
        return ProcessHandleScanResult {
            process_info: None,
            warnings,
        };
    }

    ProcessHandleScanResult::with_process_info(
        ProcessLockCollector::with_locked_files(pid, locked_files),
        warnings,
    )
}

fn verify_process_can_be_scanned(pid: u32) -> Result<(), LockScanWarning> {
    // SAFETY: OpenProcess is called with a concrete PID from the system handle
    // table. The returned process HANDLE is used only as a capability preflight
    // and is closed before any timeout-protected worker is spawned.
    let handle = match unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS_DUP_HANDLE, false, pid) } {
        Ok(handle) => handle,
        Err(error) => {
            let code = windows::Win32::Foundation::WIN32_ERROR(error.code().0 as u32);
            return Err(LockScanWarning::new(
                Some(pid),
                LockScanWarningKind::OpenProcess,
                format!(
                    "failed to open process for handle duplication: Win32 error {}: {}",
                    code.0,
                    get_win32_error_message(&code)
                ),
            ));
        }
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

fn process_metadata_warning(pid: u32, message: impl Into<String>) -> LockScanWarning {
    LockScanWarning::new(Some(pid), LockScanWarningKind::ProcessMetadata, message)
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

fn debug_privilege_warning(err: WholockError) -> LockScanWarning {
    LockScanWarning::new(
        None,
        LockScanWarningKind::DebugPrivilege,
        format!("Failed to enable SeDebugPrivilege before scanning locks: {err}"),
    )
}

fn handle_debug_privilege_result(
    result: WholockResult<()>,
    require_debug_privilege: bool,
    warnings: &mut Vec<LockScanWarning>,
) -> WholockResult<()> {
    if let Err(err) = result {
        if require_debug_privilege {
            return Err(debug_privilege_error(err));
        }
        warnings.push(debug_privilege_warning(err));
    }

    Ok(())
}

fn handle_table_warning(err: WholockError) -> LockScanWarning {
    LockScanWarning::new(
        None,
        LockScanWarningKind::HandleEnumeration,
        format!("failed to query system handle table: {err}"),
    )
}

/// Scans files and directories for matching lock holders.
///
/// This is the primary scan API. It follows PowerToys File Locksmith's default
/// behavior when [`LockScanOptions::debug_privilege_required`] is `false`: wholock
/// attempts to enable debug privilege to improve visibility, records a warning if
/// that fails, and continues scanning processes that are still accessible.
///
/// Directory inputs are matched recursively, so files and loaded modules underneath a
/// requested directory are included in the result. Empty, malformed, inaccessible, or
/// missing paths return [`WholockError::PathError`].
///
/// # Arguments
///
/// * `paths` - The file and directory paths to scan recursively
/// * `options` - Scan behavior such as privilege strictness and handle timeout
///
/// # Returns
///
/// Returns [`LockScanResult`] with discovered processes and recoverable scan warnings.
/// Use [`LockScanResult::is_complete`] to check whether any warnings occurred.
///
/// # Errors
///
/// Returns a `WholockError` if path validation fails, or if debug privilege setup fails
/// while [`LockScanOptions::debug_privilege_required`] is enabled.
///
/// # Examples
///
/// ```no_run
/// use wholock::{LockScanOptions, scan_locks};
///
/// let scan = scan_locks(["C:\\work", "C:\\data\\locked.txt"], LockScanOptions::new())?;
///
/// for process in scan.processes() {
///     println!("PID {}: {}", process.pid, process.process_name);
/// }
/// # Ok::<(), wholock::error::WholockError>(())
/// ```
pub fn scan_locks<I, P>(paths: I, options: LockScanOptions) -> WholockResult<LockScanResult>
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    let matchers = LockedPathMatchers::new(paths)?;
    if matchers.is_empty() {
        return Ok(LockScanResult::new(Vec::new(), Vec::new()));
    }

    let mut warnings = Vec::new();
    handle_debug_privilege_result(
        enable_debug_privilege(),
        options.debug_privilege_required(),
        &mut warnings,
    )?;

    let mut result: BTreeMap<u32, ProcessLockCollector> = BTreeMap::new();
    let matchers = Arc::new(matchers);

    match query_system_information_buffer(SYSTEM_EXTENDED_HANDLE_INFORMATION) {
        Ok(buffer) => match get_handle_table(&buffer) {
            Ok(table) => {
                let handle_groups = table
                    .iter()
                    .filter_map(|handle| {
                        let pid = u32::try_from(handle.unique_process_id()).ok()?;
                        Some((pid, handle.handle_value_raw()))
                    })
                    .into_group_map();

                let (handle_results, handle_warnings) = collect_handle_locks_parallel(
                    handle_groups.into_iter().collect(),
                    Arc::clone(&matchers),
                    options.handle_probe_timeout(),
                );
                result.extend(handle_results);
                warnings.extend(handle_warnings);
            }
            Err(err) => warnings.push(handle_table_warning(err)),
        },
        Err(err) => warnings.push(handle_table_warning(err)),
    }

    if options.module_scan_enabled() {
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

            let mut kernel_path_failures = Vec::new();
            for module_path in module_paths {
                let kernel_path = match kernel_path_for_path(&module_path) {
                    Ok(path) => Some(path),
                    Err(err) => {
                        kernel_path_failures.push(format!("{module_path}: {err}"));
                        None
                    }
                };
                if matchers.matches_resolved(&module_path, kernel_path.as_deref()) {
                    result
                        .entry(pid)
                        .or_insert_with(|| ProcessLockCollector::new(pid))
                        .insert_path(module_path);
                }
            }

            if !kernel_path_failures.is_empty() {
                let details = kernel_path_failures.iter().take(2).join("; ");
                let suffix = if kernel_path_failures.len() > 2 {
                    "; additional failures omitted"
                } else {
                    ""
                };
                warnings.push(LockScanWarning::new(
                    Some(pid),
                    LockScanWarningKind::ModuleEnumeration,
                    format!(
                        "failed to resolve NT paths for {} module(s); display-path matching continued: {details}{suffix}",
                        kernel_path_failures.len()
                    ),
                ));
            }
        }
    }

    Ok(finish_lock_scan(result, warnings))
}

/// Identifies all processes that have locked a specified file.
///
/// This is the simple single-path scan API. Use [`scan_locks`] when scanning
/// multiple paths or customizing scan behavior with [`LockScanOptions`].
///
/// # Arguments
///
/// * `path` - The path to the file to check, can be relative or absolute
///
/// # Returns
///
/// Returns `WholockResult<LockScanResult>` containing discovered processes and any
/// recoverable warnings observed while scanning.
///
/// # Errors
///
/// Returns a `WholockError` if the path is invalid or other hard errors occur during
/// processing. Recoverable scan failures are returned as warnings in the result.
///
/// # Examples
///
/// ```no_run
/// use wholock::who_locks_file;
///
/// match who_locks_file("C:\\path\\to\\file.txt") {
///     Ok(scan) => {
///         for process in scan.processes() {
///             println!("Process {} ({}) has locked the file", process.process_name, process.pid);
///         }
///     },
///     Err(e) => println!("Error occurred: {:?}", e),
/// }
/// ```
pub fn who_locks_file(path: &str) -> WholockResult<LockScanResult> {
    scan_locks(std::iter::once(path), LockScanOptions::new())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use tempfile::tempdir;

    fn scan_processes(path: &str) -> Vec<ProcessInfo> {
        who_locks_file(path)
            .unwrap_or_else(|err| panic!("lock scan failed: {err:?}"))
            .into_processes()
    }

    #[test]
    fn test_scan_locks_missing_paths_returns_error() {
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
            scan_locks(paths, LockScanOptions::new()),
            Err(WholockError::PathError(_))
        ));
    }

    #[test]
    fn test_scan_locks_empty_path_returns_error() {
        assert!(matches!(
            scan_locks(std::iter::once(""), LockScanOptions::new()),
            Err(WholockError::PathError(_))
        ));
    }

    #[test]
    fn test_scan_locks_nul_path_returns_error() {
        assert!(matches!(
            scan_locks(std::iter::once("C:\\bad\0path"), LockScanOptions::new()),
            Err(WholockError::PathError(_))
        ));
    }

    #[test]
    fn test_finish_lock_scan_returns_result_with_warnings() {
        let warning = LockScanWarning::new(
            Some(42),
            LockScanWarningKind::HandleEnumeration,
            "handle probe timed out",
        );
        let result = finish_lock_scan(BTreeMap::new(), vec![warning]);

        assert!(result.processes().is_empty());
        assert_eq!(result.warnings().len(), 1);
        assert!(!result.is_complete_success());
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
        let mut worker = HandleProbeWorker::new(|_, _| {
            std::thread::sleep(Duration::from_millis(50));
            Ok(Some(ResolvedFilePath {
                display_path: "C:\\slow.txt".to_string(),
                kernel_path: Some("\\Device\\HarddiskVolume1\\slow.txt".to_string()),
                kernel_path_error: None,
            }))
        });
        let result = worker.probe(std::process::id(), 1, Duration::from_millis(1));

        assert_eq!(result, HandleProbeOutcome::TimedOut);
    }

    #[test]
    fn test_handle_probe_worker_panic_returns_panic_outcome() {
        let mut worker = HandleProbeWorker::new(|_, _| {
            panic!("deliberate handle probe panic");
        });
        let result = worker.probe(std::process::id(), 1, Duration::from_secs(1));

        assert_eq!(result, HandleProbeOutcome::WorkerPanicked);
    }

    #[test]
    fn test_handle_probe_error_preserves_diagnostic() {
        let mut worker =
            HandleProbeWorker::new(|_, _| Err(WholockError::handle("failed to resolve file path")));
        let result = worker.probe(std::process::id(), 0x2a, Duration::from_secs(1));

        assert!(matches!(
            result,
            HandleProbeOutcome::ProbeFailed(message)
                if message.contains("failed to resolve file path")
        ));
    }

    #[test]
    fn test_handle_probe_failures_are_aggregated_per_process() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        File::create(&target).unwrap();
        let matchers = LockedPathMatchers::new([target.to_str().unwrap()]).unwrap();
        let mut worker =
            HandleProbeWorker::new(|_, _| Err(WholockError::handle("failed to resolve file path")));

        let result = scan_process_handles(
            std::process::id(),
            &[1, 2, 3, 4],
            &matchers,
            Duration::from_secs(1),
            &mut worker,
        );

        assert!(result.process_info.is_none());
        assert_eq!(result.warnings.len(), 1);
        assert_eq!(
            result.warnings[0].kind(),
            LockScanWarningKind::HandleEnumeration
        );
        assert!(
            result.warnings[0]
                .message()
                .contains("4 file handle path(s)")
        );
        assert!(
            result.warnings[0]
                .message()
                .contains("additional failures omitted")
        );
    }

    #[test]
    fn test_kernel_path_fallback_is_reported() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        File::create(&target).unwrap();
        let matchers = LockedPathMatchers::new([target.to_str().unwrap()]).unwrap();
        let mut worker = HandleProbeWorker::new(|_, _| {
            Ok(Some(ResolvedFilePath {
                display_path: r"C:\different.txt".to_string(),
                kernel_path: None,
                kernel_path_error: Some("NT object name unavailable".to_string()),
            }))
        });

        let result = scan_process_handles(
            std::process::id(),
            &[0x2a],
            &matchers,
            Duration::from_secs(1),
            &mut worker,
        );

        assert!(result.process_info.is_none());
        assert_eq!(result.warnings.len(), 1);
        assert!(
            result.warnings[0]
                .message()
                .contains("display-path matching continued")
        );
        assert!(result.warnings[0].message().contains("handle 0x2a"));
    }

    #[test]
    fn test_handle_probe_worker_reuses_thread_for_multiple_probes() {
        let mut worker = HandleProbeWorker::new(|_, source_handle| {
            Ok(Some(ResolvedFilePath {
                display_path: format!("C:\\file-{source_handle}.txt"),
                kernel_path: Some(format!(
                    "\\Device\\HarddiskVolume1\\file-{source_handle}.txt"
                )),
                kernel_path_error: None,
            }))
        });

        assert_eq!(
            worker.probe(std::process::id(), 1, Duration::from_secs(1)),
            HandleProbeOutcome::Path(ResolvedFilePath {
                display_path: "C:\\file-1.txt".to_string(),
                kernel_path: Some("\\Device\\HarddiskVolume1\\file-1.txt".to_string()),
                kernel_path_error: None,
            })
        );
        assert_eq!(
            worker.probe(std::process::id(), 2, Duration::from_secs(1)),
            HandleProbeOutcome::Path(ResolvedFilePath {
                display_path: "C:\\file-2.txt".to_string(),
                kernel_path: Some("\\Device\\HarddiskVolume1\\file-2.txt".to_string()),
                kernel_path_error: None,
            })
        );
        assert_eq!(worker.abandoned_workers, 0);
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
    fn test_debug_privilege_warning_allows_best_effort_scan() {
        let mut warnings = Vec::new();
        let result = handle_debug_privilege_result(
            Err(WholockError::permission("SeDebugPrivilege is not assigned")),
            false,
            &mut warnings,
        );

        assert!(result.is_ok());
        assert!(matches!(
            warnings.first().map(LockScanWarning::kind),
            Some(LockScanWarningKind::DebugPrivilege)
        ));
    }

    #[test]
    fn test_required_debug_privilege_fails_fast() {
        let mut warnings = Vec::new();
        let result = handle_debug_privilege_result(
            Err(WholockError::permission("SeDebugPrivilege is not assigned")),
            true,
            &mut warnings,
        );

        assert!(matches!(result, Err(WholockError::PermissionError(_))));
        assert!(warnings.is_empty());
    }

    #[test]
    fn test_handle_table_warning_is_recoverable_warning() {
        let warning = handle_table_warning(WholockError::system_info("buffer too small"));

        assert_eq!(warning.pid(), None);
        assert_eq!(warning.kind(), LockScanWarningKind::HandleEnumeration);
        assert!(warning.message().contains("buffer too small"));
    }

    #[test]
    fn test_process_metadata_warning_preserves_pid_and_context() {
        let warning = process_metadata_warning(42, "failed to query process owner");

        assert_eq!(warning.pid(), Some(42));
        assert_eq!(warning.kind(), LockScanWarningKind::ProcessMetadata);
        assert!(warning.message().contains("process owner"));
    }

    #[test]
    fn test_open_process_warning_includes_windows_error() {
        let warning = verify_process_can_be_scanned(u32::MAX).unwrap_err();

        assert_eq!(warning.pid(), Some(u32::MAX));
        assert_eq!(warning.kind(), LockScanWarningKind::OpenProcess);
        assert!(warning.message().contains("Win32 error"));
    }

    #[test]
    fn test_who_locks_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("locked.txt");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "test content").unwrap();

        let processes = scan_processes(file_path.to_str().unwrap());
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
