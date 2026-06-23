pub mod error;
mod interop;

use crate::error::WholockError;
use crate::interop::{
    duplicate_handle_value, enable_debug_privilege as enable_current_process_debug_privilege,
    get_final_path_name_by_handle, get_handle_owner_info, get_handle_table, get_process_info,
    get_process_module_paths, is_file_handle, is_process_elevated as current_process_is_elevated,
    query_system_information_buffer, LockedPathMatchers, PROCESS_ACCESS_RIGHTS_DUP_HANDLE,
    PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION, SYSTEM_EXTENDED_HANDLE_INFORMATION,
};
use itertools::Itertools;
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};
use windows::core::PCWSTR;
use windows::Win32::Foundation::{CloseHandle, HANDLE, HWND, WIN32_ERROR};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, TerminateProcess};
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;

pub type WholockResult<T> = Result<T, WholockError>;

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
}

impl UnlockProcessResult {
    pub fn is_success(&self) -> bool {
        self.result.is_ok()
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

#[derive(Serialize)]
struct JsonProcess<'a> {
    pid: u32,
    name: &'a str,
    user: &'a str,
    files: &'a [String],
}

#[derive(Serialize)]
struct JsonProcessList<'a> {
    processes: Vec<JsonProcess<'a>>,
}

fn json_process_list(processes: &[ProcessInfo]) -> JsonProcessList<'_> {
    JsonProcessList {
        processes: processes
            .iter()
            .map(|process| JsonProcess {
                pid: process.pid,
                name: &process.process_name,
                user: &process.domain_username,
                files: &process.locked_file,
            })
            .collect(),
    }
}

/// Serializes process lock results as PowerToys-compatible JSON.
///
/// The output shape is `{ "processes": [{ "pid", "name", "user", "files" }] }`.
pub fn processes_to_json(processes: &[ProcessInfo]) -> WholockResult<String> {
    serde_json::to_string(&json_process_list(processes))
        .map_err(|err| WholockError::Other(format!("Failed to serialize JSON output: {err}")))
}

struct HandleWrapper(HANDLE);

impl HandleWrapper {
    fn new(handle: HANDLE) -> Self {
        HandleWrapper(handle)
    }

    fn get(&self) -> HANDLE {
        self.0
    }

    fn is_invalid(&self) -> bool {
        self.0.is_invalid()
    }
}

impl Drop for HandleWrapper {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_null_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn quote_windows_arg_from_str(arg: &str) -> String {
    let needs_quotes = arg.is_empty() || arg.chars().any(|ch| ch.is_whitespace() || ch == '"');
    if !needs_quotes {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;

    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }

        if ch == '"' {
            quoted.extend(std::iter::repeat('\\').take(backslashes * 2 + 1));
            quoted.push('"');
        } else {
            quoted.extend(std::iter::repeat('\\').take(backslashes));
            quoted.push(ch);
        }

        backslashes = 0;
    }

    quoted.extend(std::iter::repeat('\\').take(backslashes * 2));
    quoted.push('"');
    quoted
}

fn quote_windows_arg(arg: &OsStr) -> String {
    quote_windows_arg_from_str(&arg.to_string_lossy())
}

/// Returns whether the current process is running with an elevated token.
pub fn is_process_elevated() -> WholockResult<bool> {
    current_process_is_elevated()
}

/// Enables `SeDebugPrivilege` on the current process token when the token has it.
pub fn enable_debug_privilege() -> WholockResult<()> {
    enable_current_process_debug_privilege()
}

/// Starts an elevated copy of the current executable with the same arguments.
///
/// The current process is left running so callers can decide whether and when to exit.
pub fn start_as_elevated() -> WholockResult<()> {
    let exe = std::env::current_exe()?;
    let file = wide_null_os(exe.as_os_str());
    let operation = wide_null("runas");
    let parameters = std::env::args_os()
        .skip(1)
        .map(|arg| quote_windows_arg(&arg))
        .join(" ");
    let parameters = if parameters.is_empty() {
        None
    } else {
        Some(wide_null(&parameters))
    };
    let parameters = parameters
        .as_ref()
        .map_or(PCWSTR::null(), |value| PCWSTR(value.as_ptr()));

    let result = unsafe {
        ShellExecuteW(
            HWND::default(),
            PCWSTR(operation.as_ptr()),
            PCWSTR(file.as_ptr()),
            parameters,
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };

    let code = result.0 as usize;
    if code <= 32 {
        return Err(WholockError::Win32Error(WIN32_ERROR(code as u32)));
    }

    Ok(())
}

/// Alias for [`start_as_elevated`].
pub fn restart_as_elevated() -> WholockResult<()> {
    start_as_elevated()
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
) -> BTreeMap<u32, ProcessLockCollector> {
    if handle_groups.is_empty() {
        return BTreeMap::new();
    }

    let worker_count = handle_scan_worker_count(handle_groups.len());
    let queue = Arc::new(Mutex::new(VecDeque::from(handle_groups)));
    let (tx, rx) = std::sync::mpsc::channel();
    let mut workers = Vec::with_capacity(worker_count);

    for _ in 0..worker_count {
        let queue = Arc::clone(&queue);
        let tx = tx.clone();
        let matchers = Arc::clone(&matchers);
        workers.push(std::thread::spawn(move || loop {
            let task = queue.lock().ok().and_then(|mut queue| queue.pop_front());
            let Some((pid, handle_values)) = task else {
                break;
            };

            if let Some(process_info) = scan_process_handles(pid, &handle_values, &matchers) {
                let _ = tx.send(process_info);
            }
        }));
    }

    drop(tx);

    let mut result = BTreeMap::new();
    for process_info in rx {
        result.insert(process_info.pid, process_info);
    }

    for worker in workers {
        let _ = worker.join();
    }

    result
}

fn scan_process_handles(
    pid: u32,
    handle_values: &[usize],
    matchers: &LockedPathMatchers,
) -> Option<ProcessLockCollector> {
    let Ok(open_process) = (unsafe {
        OpenProcess(
            PROCESS_ACCESS_RIGHTS_DUP_HANDLE | PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION,
            false,
            pid,
        )
    }) else {
        return None;
    };
    let open_process = HandleWrapper::new(open_process);
    if open_process.is_invalid() {
        return None;
    }

    let current_process: windows::Win32::Foundation::HANDLE = unsafe { GetCurrentProcess() };
    let mut locked_files = BTreeSet::new();

    for handle_value in handle_values {
        let Ok(dup_handle) =
            duplicate_handle_value(current_process, open_process.get(), *handle_value)
        else {
            continue;
        };
        let dup_handle = HandleWrapper::new(dup_handle);
        if dup_handle.is_invalid() {
            continue;
        }

        if !is_file_handle(dup_handle.get()) {
            continue;
        }

        if let Ok(full_name) = get_final_path_name_by_handle(&dup_handle.get()) {
            if matchers.matches(&full_name) {
                locked_files.insert(full_name);
            }
        }
    }

    if locked_files.is_empty() {
        return None;
    }

    let domain_username = get_handle_owner_info(open_process.get()).ok();
    Some(ProcessLockCollector::with_locked_files(
        pid,
        domain_username,
        locked_files,
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
/// requested directory are included in the result. Missing paths are ignored, matching
/// the behavior of the single-path API.
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
/// system handle/module scan.
pub fn find_processes_recursive<I, P>(paths: I) -> WholockResult<Vec<ProcessInfo>>
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    let matchers = LockedPathMatchers::new(paths);
    if matchers.is_empty() {
        return Ok(Vec::new());
    }

    let _ = enable_debug_privilege();

    let mut result: BTreeMap<u32, ProcessLockCollector> = BTreeMap::new();
    let matchers = Arc::new(matchers);

    let buffer = query_system_information_buffer(SYSTEM_EXTENDED_HANDLE_INFORMATION)?;
    let table = get_handle_table(&buffer);
    let handle_groups = table
        .iter()
        .filter_map(|handle| {
            let pid = u32::try_from(handle.unique_process_id()).ok()?;
            Some((pid, handle.handle_value_raw()))
        })
        .into_group_map();

    result.extend(collect_handle_locks_parallel(
        handle_groups.into_iter().collect(),
        Arc::clone(&matchers),
    ));

    let system = sysinfo::System::new_all();
    for pid in system
        .processes()
        .keys()
        .map(|pid| usize::from(*pid) as u32)
    {
        if let Ok(module_paths) = get_process_module_paths(pid) {
            for module_path in module_paths {
                if matchers.matches(&module_path) {
                    result
                        .entry(pid)
                        .or_insert_with(|| ProcessLockCollector::new(pid))
                        .insert_path(module_path);
                }
            }
        }
    }

    Ok(result
        .into_values()
        .map(ProcessLockCollector::into_process_info)
        .collect())
}

const WAIT_FOR_UNLOCK_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Waits until a single file or directory no longer has matching locks.
pub fn wait_for_unlock(
    path: &str,
    timeout: Option<Duration>,
) -> WholockResult<WaitForUnlockResult> {
    wait_for_unlock_files(std::iter::once(path), timeout)
}

/// Waits until all files or directories no longer have matching locks.
///
/// The query is retried every 200ms. If `timeout` is `None`, this waits
/// indefinitely.
pub fn wait_for_unlock_files<I, P>(
    paths: I,
    timeout: Option<Duration>,
) -> WholockResult<WaitForUnlockResult>
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    let paths = paths
        .into_iter()
        .map(|path| path.as_ref().to_string())
        .collect::<Vec<_>>();
    let start = Instant::now();

    loop {
        let remaining_locks = find_processes_recursive(paths.iter().map(String::as_str))?;
        let elapsed = start.elapsed();

        if remaining_locks.is_empty() {
            return Ok(WaitForUnlockResult {
                unlocked: true,
                elapsed,
                remaining_locks,
            });
        }

        if timeout.is_some_and(|timeout| elapsed > timeout) {
            return Ok(WaitForUnlockResult {
                unlocked: false,
                elapsed,
                remaining_locks,
            });
        }

        let sleep_for = timeout
            .map(|timeout| {
                timeout
                    .saturating_sub(elapsed)
                    .min(WAIT_FOR_UNLOCK_POLL_INTERVAL)
            })
            .unwrap_or(WAIT_FOR_UNLOCK_POLL_INTERVAL);
        std::thread::sleep(sleep_for);
    }
}

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

fn terminate_process_by_pid(pid: u32) -> WholockResult<()> {
    use windows::Win32::System::Threading::PROCESS_TERMINATE;

    sanitize_pid(pid)?;

    unsafe {
        let process_handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        if process_handle.is_invalid() {
            return Err(WholockError::HandleError(
                "Failed to open process".to_string(),
            ));
        }
        let process_handle = HandleWrapper::new(process_handle);

        if let Err(e) = TerminateProcess(process_handle.get(), 1) {
            return Err(e.into());
        }

        Ok(())
    }
}

/// Terminates a process to unlock files held by that process
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
/// result per unique PID.
pub fn unlock_processes(processes: &[ProcessInfo]) -> Vec<UnlockProcessResult> {
    let mut seen = BTreeSet::new();
    processes
        .iter()
        .filter(|process| seen.insert(process.pid))
        .map(|process| UnlockProcessResult {
            pid: process.pid,
            process_name: process.process_name.clone(),
            result: terminate_process_by_pid(process.pid),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

    #[test]
    fn test_is_process_elevated() {
        assert!(is_process_elevated().is_ok());
    }

    #[test]
    fn test_quote_windows_arg() {
        assert_eq!(quote_windows_arg_from_str("plain"), "plain");
        assert_eq!(quote_windows_arg_from_str("two words"), "\"two words\"");
        assert_eq!(quote_windows_arg_from_str(""), "\"\"");
        assert_eq!(
            quote_windows_arg_from_str(r#"say "hello""#),
            r#""say \"hello\"""#
        );
        assert_eq!(
            quote_windows_arg_from_str(r#"C:\path with space\"#),
            r#""C:\path with space\\""#
        );
    }

    #[test]
    fn test_find_processes_recursive_missing_paths() {
        let dir = tempdir().unwrap();
        let paths = [
            dir.path().join("missing-a.txt"),
            dir.path().join("missing-b.txt"),
        ];
        let paths = paths
            .iter()
            .map(|path| path.to_string_lossy().to_string())
            .collect::<Vec<_>>();

        assert!(find_processes_recursive(paths).unwrap().is_empty());
    }

    #[test]
    fn test_processes_to_json() {
        let processes = vec![ProcessInfo {
            pid: 42,
            process_name: "locker.exe".to_string(),
            process_exe_path: r"C:\tools\locker.exe".to_string(),
            domain_username: r"DOMAIN\user".to_string(),
            locked_file: vec![r"C:\data\locked.txt".to_string()],
        }];

        let json = processes_to_json(&processes).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["processes"][0]["pid"], 42);
        assert_eq!(value["processes"][0]["name"], "locker.exe");
        assert_eq!(value["processes"][0]["user"], r"DOMAIN\user");
        assert_eq!(value["processes"][0]["files"][0], r"C:\data\locked.txt");
        assert!(value["processes"][0].get("process_name").is_none());
    }

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
        assert!(matches!(
            &results[0].result,
            Err(WholockError::InvalidPID(pid)) if *pid == u32::MAX
        ));
    }

    #[test]
    fn test_wait_for_unlock_missing_path_returns_unlocked() {
        let dir = tempdir().unwrap();
        let missing_path = dir.path().join("missing.txt");

        let result =
            wait_for_unlock(missing_path.to_str().unwrap(), Some(Duration::from_secs(1))).unwrap();

        assert!(result.unlocked);
        assert!(!result.timed_out());
        assert!(result.remaining_locks.is_empty());
    }

    // This test is not ok for now
    #[test]
    #[ignore]
    fn test_who_locks_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("locked.txt");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "test content").unwrap();

        let result = who_locks_file(file_path.to_str().unwrap());
        println!("result: {:?}", result);
        assert!(result.is_ok());

        let processes = result.unwrap();
        assert!(!processes.is_empty());

        for process in processes {
            assert!(process.pid > 0);
            assert!(!process.domain_username.is_empty());
            assert!(!process.locked_file.is_empty());
            assert!(process.locked_file.iter().any(|f| f.contains("locked.txt")));
        }
    }

    // to be fixed
    #[test_log::test]
    #[ignore]
    fn test_unlock_file() {
        use std::process::Command;

        let child = Command::new("notepad.exe")
            .spawn()
            .expect("Failed to start test process");

        let pid = child.id();
        thread::sleep(Duration::from_secs(1));

        let result = unlock_file(pid);
        println!("result: {:?}", result);
        assert!(result.is_ok());

        thread::sleep(Duration::from_millis(500));
        let s = sysinfo::System::new_all();
        assert!(s.process(sysinfo::Pid::from(pid as usize)).is_none());
    }
}
