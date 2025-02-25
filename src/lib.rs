pub mod error;
mod interop;

use crate::error::WholockError;
use crate::interop::{
    check_if_locked_file, duplicate_handle, get_final_path_name_by_handle, get_handle_owner_info,
    get_handle_table, get_process_info, query_system_information_buffer,
    PROCESS_ACCESS_RIGHTS_DUP_HANDLE, PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION,
    SYSTEM_EXTENDED_HANDLE_INFORMATION,
};
use itertools::Itertools;
use windows::Win32::Foundation::{CloseHandle, HANDLE};
use windows::Win32::Storage::FileSystem::{ReOpenFile, FILE_FLAGS_AND_ATTRIBUTES, FILE_SHARE_MODE};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcess, TerminateProcess};

pub type WholockResult<T> = Result<T, WholockError>;

#[derive(Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: String,
    pub process_exe_path: String,
    pub domain_username: String,
    pub locked_file: Vec<String>,
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

/// Identifies all processes that have locked a specified file
///
/// This function works by enumerating all handles in the system and identifying
/// processes that currently have locks on the specified file path.
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
    let current_process: windows::Win32::Foundation::HANDLE = unsafe { GetCurrentProcess() };
    let mut result: Vec<ProcessInfo> = vec![];

    let buffer = query_system_information_buffer(SYSTEM_EXTENDED_HANDLE_INFORMATION)?;
    let table = get_handle_table(&buffer);

    for (pid, handles) in table
        .iter()
        .into_group_map_by(|elt| elt.unique_process_id())
    {
        if let Ok(open_process) = unsafe {
            OpenProcess(
                PROCESS_ACCESS_RIGHTS_DUP_HANDLE | PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION,
                false,
                pid.try_into().unwrap(),
            )
        } {
            if open_process.is_invalid() {
                continue;
            }

            let mut process_info = ProcessInfo {
                pid: pid.try_into().unwrap(),
                process_name: "".to_string(),
                process_exe_path: "".to_string(),
                domain_username: "".to_string(),
                locked_file: vec![],
            };

            for handle in handles.iter() {
                let handle_entry = *handle;
                let dup_handle = HandleWrapper::new(duplicate_handle(
                    current_process,
                    open_process,
                    handle_entry,
                )?);
                if dup_handle.is_invalid() {
                    continue;
                }

                let reopened_handle = unsafe {
                    ReOpenFile(
                        dup_handle.get(),
                        0,
                        FILE_SHARE_MODE(0),
                        FILE_FLAGS_AND_ATTRIBUTES(0),
                    )
                };

                if reopened_handle.is_err() || reopened_handle.as_ref().unwrap().is_invalid() {
                    continue;
                }

                let reopened_handle = HandleWrapper::new(reopened_handle.unwrap());

                if let Ok(full_name) = get_final_path_name_by_handle(&reopened_handle.get()) {
                    if check_if_locked_file(&full_name, path) {
                        process_info.locked_file.push(full_name);
                    }
                }
            }

            if !process_info.locked_file.is_empty() {
                process_info.domain_username = get_handle_owner_info(open_process).unwrap();
                let (name, path) = get_process_info(pid as u32).unwrap();

                process_info.process_name = name;
                process_info.process_exe_path = path;

                result.push(process_info);
            }
        }
    }

    Ok(result)
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
    use windows::Win32::System::Threading::PROCESS_TERMINATE;

    sanitize_pid(pid)?;

    unsafe {
        let process_handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        if process_handle.is_invalid() {
            return Err(WholockError::HandleError(
                "Failed to open process".to_string(),
            ));
        }

        if let Err(e) = TerminateProcess(process_handle, 1) {
            let _ = CloseHandle(process_handle);
            return Err(e.into());
        }

        let _ = CloseHandle(process_handle);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::thread;
    use std::time::Duration;
    use tempfile::tempdir;

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

    #[test]
    fn test_unlock_file() {
        use std::process::Command;

        let child = Command::new("notepad.exe")
            .spawn()
            .expect("Failed to start test process");

        let pid = child.id();
        thread::sleep(Duration::from_secs(1));

        let result = unlock_file(pid);
        assert!(result.is_ok());

        thread::sleep(Duration::from_millis(500));
        let s = sysinfo::System::new_all();
        assert!(s.process(sysinfo::Pid::from(pid as usize)).is_none());
    }
}
