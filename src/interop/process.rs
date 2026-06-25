use crate::{WholockResult, error::WholockError, error::get_win32_error_message};
use std::{ffi::OsString, mem, os::windows::ffi::OsStringExt};
use windows::Win32::Foundation::{HMODULE, MAX_PATH, WIN32_ERROR};
use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW};
use windows::Win32::System::Threading::{
    OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_VM_READ,
    QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use super::file_path::strip_extended_path_prefix;
use super::handle::SafeHandle;

const INITIAL_MODULE_CAPACITY: usize = 256;

#[allow(dead_code)]
pub(crate) fn build_process_name_dict() -> WholockResult<std::collections::HashMap<usize, String>> {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_all();

    let mut process_name_dict: std::collections::HashMap<usize, String> =
        std::collections::HashMap::new();
    for (pid, process) in sys.processes() {
        process_name_dict.insert((*pid).into(), process.name().to_string_lossy().to_string());
    }

    Ok(process_name_dict)
}

fn convert_wide_buffer(buffer: &[u16], len: usize) -> WholockResult<String> {
    let os_str = OsString::from_wide(&buffer[..len]);
    os_str
        .into_string()
        .map_err(|_| WholockError::encoding("Invalid UTF-16 sequence"))
}

fn extract_filename(path: &str) -> WholockResult<String> {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| WholockError::path("Invalid file path"))
}

pub(crate) fn get_process_info(pid: u32) -> WholockResult<(String, String)> {
    // SAFETY: OpenProcess returns an owned process handle for `pid` on success
    // and that handle is wrapped in SafeHandle. QueryFullProcessImageNameW
    // writes into `buffer`, whose size is supplied via `size`.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| {
            WholockError::process(format!(
                "Failed to open process {}: {}",
                pid,
                get_win32_error_message(&WIN32_ERROR(e.code().0 as u32))
            ))
        })?;

        let safe_handle = SafeHandle::new(handle)?;

        let mut buffer = [0u16; MAX_PATH as usize + 1];
        let mut size = buffer.len() as u32;

        QueryFullProcessImageNameW(
            safe_handle.as_raw(),
            windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
            PWSTR::from_raw(buffer.as_mut_ptr()),
            &mut size,
        )
        .map_err(|e| WholockError::from(WIN32_ERROR(e.code().0 as u32)))?;

        let path_str = convert_wide_buffer(&buffer, size as usize)?;
        let exe_name = extract_filename(&path_str)?;

        Ok((exe_name, path_str))
    }
}

fn module_count_from_needed_bytes(needed: u32) -> usize {
    let module_size = mem::size_of::<HMODULE>();
    (needed as usize).div_ceil(module_size)
}

pub(crate) fn get_process_module_paths(pid: u32) -> WholockResult<Vec<String>> {
    // SAFETY: OpenProcess returns an owned process handle for `pid` on success
    // and SafeHandle closes it. EnumProcessModules and GetModuleFileNameExW are
    // passed buffers whose byte/element sizes are computed from their lengths.
    unsafe {
        let handle = match OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid) {
            Ok(handle) => handle,
            Err(e) => {
                return Err(WholockError::process(format!(
                    "Failed to open process {} for module enumeration: {}",
                    pid,
                    get_win32_error_message(&WIN32_ERROR(e.code().0 as u32))
                )));
            }
        };
        let safe_handle = SafeHandle::new(handle).map_err(|err| {
            WholockError::process(format!(
                "Failed to open process {pid} for module enumeration: {err}"
            ))
        })?;

        let mut modules = vec![HMODULE::default(); INITIAL_MODULE_CAPACITY];

        loop {
            let mut needed = 0u32;
            let buffer_bytes = modules.len() * mem::size_of::<HMODULE>();
            let buffer_bytes = u32::try_from(buffer_bytes)
                .map_err(|_| WholockError::other("Module buffer is too large"))?;
            if let Err(e) = EnumProcessModules(
                safe_handle.as_raw(),
                modules.as_mut_ptr(),
                buffer_bytes,
                &mut needed,
            ) {
                return Err(WholockError::process(format!(
                    "EnumProcessModules failed for PID {}: {}",
                    pid,
                    get_win32_error_message(&WIN32_ERROR(e.code().0 as u32))
                )));
            }

            let needed_count = module_count_from_needed_bytes(needed);
            if needed > buffer_bytes {
                modules.resize(needed_count, HMODULE::default());
                continue;
            }

            if needed_count <= modules.len() {
                modules.truncate(needed as usize / mem::size_of::<HMODULE>());
                break;
            }
        }

        let mut paths = Vec::new();
        for module in modules {
            let mut buffer = vec![0u16; MAX_PATH as usize + 1];
            let len = GetModuleFileNameExW(Some(safe_handle.as_raw()), Some(module), &mut buffer);
            if len == 0 {
                continue;
            }

            if let Ok(path) = convert_wide_buffer(&buffer, len as usize) {
                if !path.is_empty() {
                    paths.push(strip_extended_path_prefix(&path));
                }
            }
        }

        Ok(paths)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WholockError;

    #[test]
    fn test_build_process_name_dict() {
        let result = build_process_name_dict();
        assert!(result.is_ok());
        let dict = result.unwrap();
        assert!(!dict.is_empty());
    }

    #[test]
    fn test_convert_wide_buffer() {
        let test_str = "Hello, 世界";
        let wide: Vec<u16> = test_str.encode_utf16().collect();
        let result = convert_wide_buffer(&wide, wide.len());
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), test_str);

        let invalid_utf16 = vec![0xD800];
        let result = convert_wide_buffer(&invalid_utf16, invalid_utf16.len());
        assert!(matches!(result, Err(WholockError::EncodingError(_))));
    }

    #[test]
    fn test_extract_filename() {
        let path = r"C:\Users\test\file.txt";
        let result = extract_filename(path);
        assert!(result.is_ok());
        assert_eq!(result.unwrap(), "file.txt");

        let invalid_path = "";
        let result = extract_filename(invalid_path);
        assert!(matches!(result, Err(WholockError::PathError(_))));
    }

    #[test]
    fn test_module_count_from_needed_bytes() {
        let module_size = mem::size_of::<HMODULE>() as u32;

        assert_eq!(module_count_from_needed_bytes(0), 0);
        assert_eq!(module_count_from_needed_bytes(module_size * 3), 3);
        assert_eq!(module_count_from_needed_bytes(module_size * 3 + 1), 4);
    }

    #[test]
    fn test_current_process() {
        let pid = std::process::id();
        let (name, path) = get_process_info(pid).unwrap();
        assert!(!name.is_empty());
        assert!(std::path::Path::new(&path).exists());
        assert_eq!(
            name,
            std::path::Path::new(&path)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn test_current_process_modules() {
        let modules = get_process_module_paths(std::process::id()).unwrap();

        assert!(!modules.is_empty());
        assert!(
            modules
                .iter()
                .any(|path| std::path::Path::new(path).exists())
        );
    }

    #[test]
    fn test_missing_process_modules_returns_error() {
        let result = get_process_module_paths(u32::MAX);

        assert!(matches!(result, Err(WholockError::ProcessError(_))));
    }
}
