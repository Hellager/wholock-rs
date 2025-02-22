pub mod error;
mod interop;

use windows::Win32::Foundation::CloseHandle;
use windows::Win32::System::Threading::{OpenProcess, GetCurrentProcess, TerminateProcess};
use windows::Win32::Storage::FileSystem::{ReOpenFile, FILE_SHARE_MODE, FILE_FLAGS_AND_ATTRIBUTES};
use itertools::Itertools;
use crate::error::WholockError;
use crate::interop::{
    SYSTEM_EXTENDED_HANDLE_INFORMATION,
    PROCESS_ACCESS_RIGHTS_DUP_HANDLE,
    PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION,
    query_system_information_buffer,
    get_handle_table,
    duplicate_handle,
    get_final_path_name_by_handle,
    check_if_locked_file,
    get_handle_owner_info
};

pub type WholockResult<T> = Result<T, WholockError>; 

#[derive(Debug)]
pub struct ProcessInfo {
    pub pid: u32,
    pub process_name: String,
    pub process_exe_path: String,
    pub domain_username: String,
    pub locked_file: Vec<String>
}

pub fn who_locks_file(path: &str) -> WholockResult<Vec<ProcessInfo>> {
    let current_process: windows::Win32::Foundation::HANDLE = unsafe {
        GetCurrentProcess()
    };
    let mut result: Vec<ProcessInfo> = vec![];

    let buffer = query_system_information_buffer(SYSTEM_EXTENDED_HANDLE_INFORMATION)?;
    let table = get_handle_table(&buffer);

    for (pid, handles) in table.into_iter().into_group_map_by(|elt| elt.unique_process_id()) {        
        if let Ok(open_process) = unsafe {
            OpenProcess(
                PROCESS_ACCESS_RIGHTS_DUP_HANDLE | PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION, 
                false, 
                pid.try_into().unwrap())
        } {
            if open_process.is_invalid() {
                continue;
            }

            let mut process_info = ProcessInfo {
                pid: pid.try_into().unwrap(),
                process_name: "".to_string(),
                process_exe_path: "".to_string(),
                domain_username: "".to_string(),
                locked_file: vec![]
            };
        
            for handle in handles.iter() {
                let handle_entry = *handle;
                let dup_handle = duplicate_handle(current_process, open_process, handle_entry)?;
                if dup_handle.is_invalid() {
                    continue;
                }
            
                let reopened_handle = unsafe { 
                    ReOpenFile(
                        dup_handle,
                        0, 
                        FILE_SHARE_MODE(0), 
                        FILE_FLAGS_AND_ATTRIBUTES(0)) 
                };

                if reopened_handle.is_err() || reopened_handle.as_ref().unwrap().is_invalid() {
                    unsafe { 
                        let _ = CloseHandle(dup_handle);
                    };
                    continue;
                }

                if let Ok(full_name) = get_final_path_name_by_handle(reopened_handle.as_ref().unwrap()) {
                    if check_if_locked_file(&full_name, path) {
                        process_info.locked_file.push(full_name);
                    }
                }

                unsafe {
                    let _ = CloseHandle(reopened_handle.unwrap());
                    let _ = CloseHandle(dup_handle);              
                };
            }

            if process_info.locked_file.len() > 0 {
                process_info.domain_username = get_handle_owner_info(open_process).unwrap();
                
                let s = sysinfo::System::new_all();
                if let Some(_process) = s.process(sysinfo::Pid::from(pid)) {
                    if let Some(exe_path) = _process.exe() {
                        process_info.process_exe_path = exe_path.to_str().unwrap().to_string();
                    }

                    process_info.process_name = _process.name().to_str().unwrap().to_string();
                }

                result.push(process_info);
            }
        }
    }

    Ok(result)
}

pub fn unlock_file(pid: u32) -> WholockResult<()> {
    use windows::Win32::System::Threading::PROCESS_TERMINATE;

    unsafe {
        let process_handle = OpenProcess(PROCESS_TERMINATE, false, pid)?;
        if process_handle.is_invalid() {
            return Err(WholockError::HandleError("Failed to open process".to_string()));
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
    use tempfile::tempdir;
    use std::thread;
    use std::time::Duration;

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
