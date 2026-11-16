use crate::elevation::enable_debug_privilege;
use crate::error::{LockScanWarning, LockScanWarningKind, WholockError, get_win32_error_message};
use crate::interop::{
    LockedPathMatchers, PROCESS_ACCESS_RIGHTS_DUP_HANDLE, PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION,
    ResolvedFilePath, SYSTEM_EXTENDED_HANDLE_INFORMATION, duplicate_handle_value,
    get_file_identity_by_handle, get_final_path_name_by_handle, get_handle_owner_info,
    get_handle_table, get_object_name, get_process_identity, get_process_ids,
    get_process_module_paths, is_disk_file_handle, kernel_path_for_path,
    query_system_information_buffer,
};
use crate::{
    WholockResult,
    types::{LockMatch, LockMatchSource, LockScanOptions, LockScanResult, ProcessInfo},
};
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::panic::AssertUnwindSafe;
use std::sync::{
    Arc, Condvar, Mutex,
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
    ProcessOpenFailed(String),
    ProbeFailed(String),
}

type HandleProbeFunction =
    dyn Fn(HANDLE, usize) -> WholockResult<Option<ResolvedFilePath>> + Send + Sync + 'static;

struct HandleProbeRequest {
    pid: u32,
    source_handle: usize,
    reply: mpsc::Sender<HandleProbeReply>,
}

enum HandleProbeReplyValue {
    Probed(WholockResult<Option<ResolvedFilePath>>),
    ProcessOpenFailed(String),
}

type HandleProbeReply = Result<HandleProbeReplyValue, Box<dyn std::any::Any + Send>>;

enum CachedHandleOwnerProcess {
    Available { pid: u32, handle: HandleWrapper },
    Unavailable { pid: u32, message: String },
}

impl CachedHandleOwnerProcess {
    fn pid(&self) -> u32 {
        match self {
            Self::Available { pid, .. } | Self::Unavailable { pid, .. } => *pid,
        }
    }
}

struct HandleProbeTimeoutBudget {
    max_abandoned_workers: usize,
    state: Mutex<HandleProbeTimeoutBudgetState>,
    slot_available: Condvar,
}

#[derive(Default)]
struct HandleProbeTimeoutBudgetState {
    active_probes: usize,
    abandoned_workers: usize,
}

impl HandleProbeTimeoutBudget {
    fn new(max_abandoned_workers: usize) -> Self {
        Self {
            max_abandoned_workers,
            state: Mutex::new(HandleProbeTimeoutBudgetState::default()),
            slot_available: Condvar::new(),
        }
    }

    fn reserve(self: &Arc<Self>) -> Option<HandleProbeTimeoutReservation> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        loop {
            if state.abandoned_workers >= self.max_abandoned_workers {
                return None;
            }

            let available_slots = self.max_abandoned_workers - state.abandoned_workers;
            if state.active_probes < available_slots {
                state.active_probes += 1;
                break;
            }

            state = self
                .slot_available
                .wait(state)
                .unwrap_or_else(|poisoned| poisoned.into_inner());
        }
        drop(state);

        Some(HandleProbeTimeoutReservation {
            budget: Arc::clone(self),
            abandoned: false,
        })
    }
}

struct HandleProbeTimeoutReservation {
    budget: Arc<HandleProbeTimeoutBudget>,
    abandoned: bool,
}

impl HandleProbeTimeoutReservation {
    fn abandon(mut self) {
        self.abandoned = true;
    }
}

impl Drop for HandleProbeTimeoutReservation {
    fn drop(&mut self) {
        let mut state = self
            .budget
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        debug_assert!(state.active_probes > 0);
        state.active_probes -= 1;
        if self.abandoned {
            state.abandoned_workers += 1;
        }
        drop(state);
        self.budget.slot_available.notify_all();
    }
}

struct HandleProbeWorker {
    probe: Arc<HandleProbeFunction>,
    sender: Option<mpsc::Sender<HandleProbeRequest>>,
    timeout_budget: Arc<HandleProbeTimeoutBudget>,
}

impl HandleProbeWorker {
    #[cfg(test)]
    fn new<F>(probe: F) -> Self
    where
        F: Fn(HANDLE, usize) -> WholockResult<Option<ResolvedFilePath>> + Send + Sync + 'static,
    {
        Self::with_timeout_budget(
            probe,
            Arc::new(HandleProbeTimeoutBudget::new(
                MAX_ABANDONED_HANDLE_PROBE_WORKERS,
            )),
        )
    }

    fn with_timeout_budget<F>(probe: F, timeout_budget: Arc<HandleProbeTimeoutBudget>) -> Self
    where
        F: Fn(HANDLE, usize) -> WholockResult<Option<ResolvedFilePath>> + Send + Sync + 'static,
    {
        Self {
            probe: Arc::new(probe),
            sender: None,
            timeout_budget,
        }
    }

    fn ensure_worker(&mut self) -> Result<(), HandleProbeOutcome> {
        if self.sender.is_some() {
            return Ok(());
        }

        let (sender, receiver) = mpsc::channel::<HandleProbeRequest>();
        let probe = Arc::clone(&self.probe);
        std::thread::Builder::new()
            .name("wholock-handle-probe".into())
            .spawn(move || {
                let mut cached_owner_process: Option<CachedHandleOwnerProcess> = None;
                while let Ok(request) = receiver.recv() {
                    if cached_owner_process
                        .as_ref()
                        .is_some_and(|cached| cached.pid() != request.pid)
                    {
                        cached_owner_process = None;
                    }

                    if cached_owner_process.is_none() {
                        cached_owner_process = Some(match open_handle_owner_process(request.pid) {
                            Ok(handle) => CachedHandleOwnerProcess::Available {
                                pid: request.pid,
                                handle,
                            },
                            Err(message) => CachedHandleOwnerProcess::Unavailable {
                                pid: request.pid,
                                message,
                            },
                        });
                    }

                    let result = match cached_owner_process.as_ref() {
                        Some(CachedHandleOwnerProcess::Available { handle, .. }) => {
                            std::panic::catch_unwind(AssertUnwindSafe(|| {
                                (probe)(handle.get(), request.source_handle)
                            }))
                            .map(HandleProbeReplyValue::Probed)
                        }
                        Some(CachedHandleOwnerProcess::Unavailable { message, .. }) => {
                            Ok(HandleProbeReplyValue::ProcessOpenFailed(message.clone()))
                        }
                        None => unreachable!("handle owner process cache should be initialized"),
                    };
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

        let Some(timeout_reservation) = self.timeout_budget.reserve() else {
            return HandleProbeOutcome::WorkerLimitReached;
        };

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
            Ok(Ok(HandleProbeReplyValue::Probed(Ok(Some(path))))) => HandleProbeOutcome::Path(path),
            Ok(Ok(HandleProbeReplyValue::Probed(Ok(None)))) => HandleProbeOutcome::NoMatch,
            Ok(Ok(HandleProbeReplyValue::Probed(Err(error)))) => {
                HandleProbeOutcome::ProbeFailed(error.to_string())
            }
            Ok(Ok(HandleProbeReplyValue::ProcessOpenFailed(message))) => {
                HandleProbeOutcome::ProcessOpenFailed(message)
            }
            Ok(Err(_)) => HandleProbeOutcome::WorkerPanicked,
            Err(RecvTimeoutError::Timeout) => {
                self.sender = None;
                timeout_reservation.abandon();
                HandleProbeOutcome::TimedOut
            }
            Err(RecvTimeoutError::Disconnected) => {
                self.sender = None;
                HandleProbeOutcome::WorkerDisconnected
            }
        }
    }
}

fn open_handle_owner_process(pid: u32) -> Result<HandleWrapper, String> {
    // SAFETY: OpenProcess is called with a PID read from the system handle table.
    // The returned process HANDLE is owned by the probe worker and closed when
    // the worker switches to another PID or exits.
    let handle =
        unsafe { OpenProcess(PROCESS_ACCESS_RIGHTS_DUP_HANDLE, false, pid) }.map_err(|error| {
            let code = windows::Win32::Foundation::WIN32_ERROR(error.code().0 as u32);
            format!(
                "failed to open process for handle duplication: Win32 error {}: {}",
                code.0,
                get_win32_error_message(&code)
            )
        })?;
    let handle = HandleWrapper::new(handle);
    if handle.is_invalid() {
        return Err("OpenProcess returned an invalid handle".to_string());
    }

    Ok(handle)
}

fn probe_handle_path_blocking(
    handle_owner_process: HANDLE,
    source_handle: usize,
    matchers: &LockedPathMatchers,
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

    let (kernel_path, kernel_path_error) = match get_object_name(dup_handle.get()) {
        Ok(kernel_path) => {
            if let Some(display_path) = matchers.matching_display_path(Some(&kernel_path), None) {
                return Ok(Some(ResolvedFilePath {
                    display_path,
                    kernel_path: Some(kernel_path),
                    kernel_path_error: None,
                }));
            }
            let file_identity = get_file_identity_by_handle(dup_handle.get()).ok();
            if let Some(display_path) = matchers.matching_display_path(None, file_identity) {
                return Ok(Some(ResolvedFilePath {
                    display_path,
                    kernel_path: Some(kernel_path),
                    kernel_path_error: None,
                }));
            }
            if matchers.kernel_paths_complete() && !matchers.matches_kernel(&kernel_path) {
                return Ok(None);
            }
            (Some(kernel_path), None)
        }
        Err(err) => {
            let file_identity = get_file_identity_by_handle(dup_handle.get()).ok();
            if let Some(display_path) = matchers.matching_display_path(None, file_identity) {
                return Ok(Some(ResolvedFilePath {
                    display_path,
                    kernel_path: None,
                    kernel_path_error: Some(err.to_string()),
                }));
            }
            (None, Some(err.to_string()))
        }
    };
    let paths = ResolvedFilePath {
        display_path: get_final_path_name_by_handle(&dup_handle.get())?,
        kernel_path,
        kernel_path_error,
    };

    if paths.kernel_path_error.is_some()
        || matchers.matches_resolved(&paths.display_path, paths.kernel_path.as_deref())
    {
        Ok(Some(paths))
    } else {
        Ok(None)
    }
}

struct ProcessLockCollector {
    pid: u32,
    matches: BTreeSet<LockMatch>,
}

impl ProcessLockCollector {
    fn new(pid: u32) -> Self {
        Self {
            pid,
            matches: BTreeSet::new(),
        }
    }

    fn with_matches(pid: u32, matches: BTreeSet<LockMatch>) -> Self {
        Self { pid, matches }
    }

    fn insert_match(&mut self, path: String, source: LockMatchSource) {
        self.matches.insert(LockMatch::new(path, source));
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

        let matches = self.matches.into_iter().collect::<Vec<_>>();
        let locked_file = matches
            .iter()
            .map(|lock_match| lock_match.path.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();

        ProcessInfo {
            pid: self.pid,
            process_name,
            process_exe_path,
            domain_username,
            locked_file,
            matches,
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
    let timeout_budget = Arc::new(HandleProbeTimeoutBudget::new(
        MAX_ABANDONED_HANDLE_PROBE_WORKERS,
    ));
    let (tx, rx) = std::sync::mpsc::channel();
    let mut workers = Vec::with_capacity(worker_count);
    let mut startup_warnings = Vec::new();

    for worker_index in 0..worker_count {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        let matchers = Arc::clone(&matchers);
        let probe_matchers = Arc::clone(&matchers);
        let timeout_budget = Arc::clone(&timeout_budget);
        let worker = std::thread::Builder::new()
            .name(format!("wholock-handle-scan-{worker_index}"))
            .spawn(move || {
                let mut probe_worker = HandleProbeWorker::with_timeout_budget(
                    move |handle_owner_process, source_handle| {
                        probe_handle_path_blocking(
                            handle_owner_process,
                            source_handle,
                            &probe_matchers,
                        )
                    },
                    timeout_budget,
                );
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
    let mut matches = BTreeSet::new();
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
                    matches.insert(LockMatch::new(
                        paths.display_path,
                        LockMatchSource::FileHandle,
                    ));
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
            HandleProbeOutcome::ProcessOpenFailed(message) => {
                warnings.push(LockScanWarning::new(
                    Some(pid),
                    LockScanWarningKind::OpenProcess,
                    message,
                ));
                break;
            }
            HandleProbeOutcome::ProbeFailed(message) => {
                probe_failures.push(format!("handle {handle_value:#x}: {message}"));
            }
        }
    }

    if !probe_failures.is_empty() {
        let details = probe_failures
            .iter()
            .take(3)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("; ");
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
        let details = kernel_path_failures
            .iter()
            .take(3)
            .map(String::as_str)
            .collect::<Vec<_>>()
            .join("; ");
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

    if matches.is_empty() {
        return ProcessHandleScanResult {
            process_info: None,
            warnings,
        };
    }

    ProcessHandleScanResult::with_process_info(
        ProcessLockCollector::with_matches(pid, matches),
        warnings,
    )
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
/// Each [`ProcessInfo`] includes structured matches that distinguish open file handles
/// from loaded process modules. Use [`LockScanResult::is_complete`] to check whether
/// any warnings occurred.
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
///     for lock_match in &process.matches {
///         println!("  {} ({})", lock_match.path, lock_match.source);
///     }
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
                let mut handle_groups = BTreeMap::<u32, Vec<usize>>::new();
                for handle in table.iter() {
                    if let Ok(pid) = u32::try_from(handle.unique_process_id()) {
                        handle_groups
                            .entry(pid)
                            .or_default()
                            .push(handle.handle_value_raw());
                    }
                }

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
        let process_ids = match get_process_ids() {
            Ok(process_ids) => process_ids,
            Err(err) => {
                warnings.push(LockScanWarning::new(
                    None,
                    LockScanWarningKind::ModuleEnumeration,
                    format!("failed to enumerate processes for module scanning: {err}"),
                ));
                Vec::new()
            }
        };
        for pid in process_ids {
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
                        .insert_match(module_path, LockMatchSource::ProcessModule);
                }
            }

            if !kernel_path_failures.is_empty() {
                let details = kernel_path_failures
                    .iter()
                    .take(2)
                    .map(String::as_str)
                    .collect::<Vec<_>>()
                    .join("; ");
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
    use std::os::windows::io::AsRawHandle;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tempfile::tempdir;
    use windows::Win32::System::Diagnostics::ToolHelp::{
        CreateToolhelp32Snapshot, TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
    };
    use windows::Win32::System::Threading::GetProcessHandleCount;

    fn current_process_handle_count() -> u32 {
        let mut count = 0;
        // SAFETY: GetCurrentProcess returns a documented pseudo-handle, and
        // `count` is a valid writable output pointer for the duration of the call.
        unsafe { GetProcessHandleCount(GetCurrentProcess(), &mut count) }
            .expect("failed to count current process handles");
        count
    }

    fn current_process_thread_count() -> usize {
        // SAFETY: The snapshot call has no pointer arguments. Its owned result is
        // immediately wrapped so it is closed exactly once after enumeration.
        let snapshot = unsafe { CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0) }
            .expect("failed to create thread snapshot");
        let snapshot = HandleWrapper::new(snapshot);
        let mut entry = THREADENTRY32 {
            dwSize: std::mem::size_of::<THREADENTRY32>() as u32,
            ..THREADENTRY32::default()
        };
        let mut count = 0;

        // SAFETY: `entry` has the required size and remains writable throughout
        // the snapshot enumeration. `snapshot` is live until this function exits.
        if unsafe { Thread32First(snapshot.get(), &mut entry) }.is_ok() {
            loop {
                if entry.th32OwnerProcessID == std::process::id() {
                    count += 1;
                }
                // SAFETY: The same live snapshot and initialized writable entry
                // are reused for each subsequent enumeration call.
                if unsafe { Thread32Next(snapshot.get(), &mut entry) }.is_err() {
                    break;
                }
            }
        }

        count
    }

    fn wait_for_resource_cleanup(max_threads: usize, max_handles: u32) -> bool {
        let start = std::time::Instant::now();
        while start.elapsed() < Duration::from_secs(5) {
            if current_process_thread_count() <= max_threads
                && current_process_handle_count() <= max_handles
            {
                return true;
            }
            std::thread::sleep(Duration::from_millis(25));
        }

        current_process_thread_count() <= max_threads
            && current_process_handle_count() <= max_handles
    }

    fn run_abandoned_probe_round() {
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        let worker_release = Arc::clone(&release);
        let budget = Arc::new(HandleProbeTimeoutBudget::new(
            MAX_ABANDONED_HANDLE_PROBE_WORKERS,
        ));
        let mut worker = HandleProbeWorker::with_timeout_budget(
            move |_, _| {
                let (released, signal) = &*worker_release;
                let mut released = released
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner());
                while !*released {
                    released = signal
                        .wait(released)
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                }
                Ok(None)
            },
            budget,
        );

        for handle in 0..MAX_ABANDONED_HANDLE_PROBE_WORKERS {
            assert_eq!(
                worker.probe(std::process::id(), handle, Duration::from_millis(2)),
                HandleProbeOutcome::TimedOut
            );
        }
        assert_eq!(
            worker.probe(std::process::id(), usize::MAX, Duration::from_millis(2)),
            HandleProbeOutcome::WorkerLimitReached
        );

        let (released, signal) = &*release;
        *released
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = true;
        signal.notify_all();
        drop(worker);
    }

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
    fn test_process_info_preserves_structured_match_sources() {
        let path = r"C:\data\plugin.dll".to_string();
        let mut collector = ProcessLockCollector::new(std::process::id());
        collector.insert_match(path.clone(), LockMatchSource::FileHandle);
        collector.insert_match(path.clone(), LockMatchSource::ProcessModule);
        collector.insert_match(path.clone(), LockMatchSource::FileHandle);

        let process = collector.into_process_info(&mut Vec::new());

        assert_eq!(process.locked_file, vec![path]);
        assert_eq!(process.matches.len(), 2);
        assert!(
            process
                .matches
                .iter()
                .any(|lock_match| lock_match.source == LockMatchSource::FileHandle)
        );
        assert!(
            process
                .matches
                .iter()
                .any(|lock_match| lock_match.source == LockMatchSource::ProcessModule)
        );
    }

    #[test]
    fn test_handle_scan_reports_file_handle_match_source() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        File::create(&target).unwrap();
        let target = target.to_string_lossy().to_string();
        let matchers = LockedPathMatchers::new([target.as_str()]).unwrap();
        let worker_path = target.clone();
        let mut worker = HandleProbeWorker::new(move |_, _| {
            Ok(Some(ResolvedFilePath {
                display_path: worker_path.clone(),
                kernel_path: None,
                kernel_path_error: None,
            }))
        });

        let result = scan_process_handles(
            std::process::id(),
            &[0x2a],
            &matchers,
            Duration::from_secs(1),
            &mut worker,
        );
        let process = result
            .process_info
            .expect("handle match should be returned");

        assert_eq!(process.matches.len(), 1);
        assert_eq!(
            process
                .matches
                .iter()
                .next()
                .map(|lock_match| lock_match.source),
            Some(LockMatchSource::FileHandle)
        );
    }

    #[test]
    fn test_handle_probe_filters_unmatched_kernel_path() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        let unrelated = dir.path().join("unrelated.txt");
        File::create(&target).unwrap();
        File::create(&unrelated).unwrap();
        let matchers = LockedPathMatchers::new([target.to_str().unwrap()]).unwrap();
        let unrelated = File::open(unrelated).unwrap();
        // SAFETY: GetCurrentProcess returns the documented pseudo-handle for
        // the current process and is only used as a DuplicateHandle source.
        let current_process = unsafe { GetCurrentProcess() };

        let result = probe_handle_path_blocking(
            current_process,
            unrelated.as_raw_handle() as usize,
            &matchers,
        )
        .unwrap();

        assert!(result.is_none());
    }

    #[test]
    fn test_handle_probe_matches_hard_link_by_file_identity() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        let hard_link = dir.path().join("hard-link.txt");
        File::create(&target).unwrap();
        std::fs::hard_link(&target, &hard_link).unwrap();
        let matchers = LockedPathMatchers::new([hard_link.to_str().unwrap()]).unwrap();
        let target = File::open(target).unwrap();
        // SAFETY: GetCurrentProcess returns the documented pseudo-handle for
        // the current process and is only used as a DuplicateHandle source.
        let current_process = unsafe { GetCurrentProcess() };

        let result =
            probe_handle_path_blocking(current_process, target.as_raw_handle() as usize, &matchers)
                .unwrap()
                .expect("hard-link identity should match the open file handle");

        assert_eq!(result.display_path, hard_link.to_string_lossy());
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
    fn test_handle_probe_workers_share_timeout_budget() {
        let timeout_budget = Arc::new(HandleProbeTimeoutBudget::new(1));
        let mut timed_out_worker = HandleProbeWorker::with_timeout_budget(
            |_, _| {
                std::thread::sleep(Duration::from_millis(50));
                Ok(None)
            },
            Arc::clone(&timeout_budget),
        );
        let mut limited_worker =
            HandleProbeWorker::with_timeout_budget(|_, _| Ok(None), Arc::clone(&timeout_budget));

        assert_eq!(
            timed_out_worker.probe(std::process::id(), 1, Duration::from_millis(1)),
            HandleProbeOutcome::TimedOut
        );
        assert_eq!(
            limited_worker.probe(std::process::id(), 2, Duration::from_secs(1)),
            HandleProbeOutcome::WorkerLimitReached
        );
    }

    #[test]
    fn test_repeated_timeout_scans_release_threads_and_handles() {
        let baseline_threads = current_process_thread_count();
        let baseline_handles = current_process_handle_count();

        for _ in 0..2 {
            run_abandoned_probe_round();
            assert!(
                wait_for_resource_cleanup(baseline_threads + 2, baseline_handles + 8),
                "timed-out probes leaked resources: threads {} -> {}, handles {} -> {}",
                baseline_threads,
                current_process_thread_count(),
                baseline_handles,
                current_process_handle_count()
            );
        }
    }

    #[test]
    fn test_handle_probe_budget_waits_for_active_probe() {
        let timeout_budget = Arc::new(HandleProbeTimeoutBudget::new(1));
        let started = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        let worker_started = Arc::clone(&started);
        let worker_release = Arc::clone(&release);
        let mut active_worker = HandleProbeWorker::with_timeout_budget(
            move |_, _| {
                worker_started.wait();
                worker_release.wait();
                Ok(None)
            },
            Arc::clone(&timeout_budget),
        );
        let active_probe = std::thread::spawn(move || {
            active_worker.probe(std::process::id(), 1, Duration::from_secs(1))
        });
        started.wait();

        let mut waiting_worker =
            HandleProbeWorker::with_timeout_budget(|_, _| Ok(None), Arc::clone(&timeout_budget));
        let waiting_probe = std::thread::spawn(move || {
            waiting_worker.probe(std::process::id(), 2, Duration::from_secs(1))
        });

        release.wait();
        assert_eq!(
            active_probe.join().expect("active probe should not panic"),
            HandleProbeOutcome::NoMatch
        );
        assert_eq!(
            waiting_probe
                .join()
                .expect("waiting probe should not panic"),
            HandleProbeOutcome::NoMatch
        );
    }

    #[test]
    fn test_zero_handle_probe_timeout_does_not_consume_budget() {
        let timeout_budget = Arc::new(HandleProbeTimeoutBudget::new(1));
        let probe_calls = Arc::new(AtomicUsize::new(0));
        let worker_probe_calls = Arc::clone(&probe_calls);
        let mut worker = HandleProbeWorker::with_timeout_budget(
            move |_, _| {
                worker_probe_calls.fetch_add(1, Ordering::Relaxed);
                Ok(None)
            },
            Arc::clone(&timeout_budget),
        );

        assert_eq!(
            worker.probe(std::process::id(), 1, Duration::ZERO),
            HandleProbeOutcome::TimedOut
        );
        assert!(worker.sender.is_none());
        assert_eq!(probe_calls.load(Ordering::Relaxed), 0);
        assert_eq!(
            worker.probe(std::process::id(), 1, Duration::from_secs(1)),
            HandleProbeOutcome::NoMatch
        );
        assert_eq!(probe_calls.load(Ordering::Relaxed), 1);
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
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        File::create(&target).unwrap();
        let matchers = LockedPathMatchers::new([target.to_str().unwrap()]).unwrap();
        let mut worker = HandleProbeWorker::new(|_, _| Ok(None));
        let result = scan_process_handles(
            u32::MAX,
            &[1, 2],
            &matchers,
            Duration::from_secs(1),
            &mut worker,
        );
        let warning = result
            .warnings
            .first()
            .expect("open process failure should be reported");

        assert_eq!(warning.pid(), Some(u32::MAX));
        assert_eq!(warning.kind(), LockScanWarningKind::OpenProcess);
        assert!(warning.message().contains("Win32 error"));
        assert_eq!(result.warnings.len(), 1);
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
        assert!(!current_process.matches.is_empty());
        assert!(
            current_process
                .locked_file
                .iter()
                .any(|f| f.contains("locked.txt"))
        );
        assert!(current_process.matches.iter().any(|lock_match| {
            lock_match.path.contains("locked.txt")
                && lock_match.source == LockMatchSource::FileHandle
        }));
    }
}
