use crate::{WholockResult, error::WholockError, error::get_win32_error_message};
use std::{ffi::OsString, mem, os::windows::ffi::OsStringExt};
use windows::Win32::Foundation::{
    ERROR_INSUFFICIENT_BUFFER, FILETIME, HANDLE, HMODULE, MAX_PATH, WIN32_ERROR,
};
use windows::Win32::System::ProcessStatus::{
    EnumProcessModules, EnumProcesses, GetModuleFileNameExW,
};
use windows::Win32::System::Threading::{
    GetProcessTimes, OpenProcess, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ, QueryFullProcessImageNameW,
};
use windows::core::PWSTR;

use super::file_path::strip_extended_path_prefix;
use super::handle::SafeHandle;

const INITIAL_MODULE_CAPACITY: usize = 256;
const INITIAL_PROCESS_ID_CAPACITY: usize = 1024;
const MAX_PROCESS_ID_CAPACITY: usize = 1024 * 1024;
const MAX_DYNAMIC_PATH_CAPACITY: usize = 32 * 1024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProcessIdentity {
    pub(crate) process_name: String,
    pub(crate) process_exe_path: String,
    pub(crate) creation_time: u64,
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

fn next_path_capacity(current: usize) -> WholockResult<usize> {
    if current >= MAX_DYNAMIC_PATH_CAPACITY {
        return Err(WholockError::other(
            "Path exceeds the supported Windows limit",
        ));
    }

    Ok(current
        .checked_mul(2)
        .unwrap_or(MAX_DYNAMIC_PATH_CAPACITY)
        .min(MAX_DYNAMIC_PATH_CAPACITY))
}

unsafe fn query_full_process_image_path(handle: HANDLE) -> WholockResult<String> {
    let mut buffer = vec![0u16; MAX_PATH as usize + 1];

    loop {
        let mut size = u32::try_from(buffer.len())
            .map_err(|_| WholockError::other("Process path buffer is too large"))?;
        // SAFETY: `handle` is a live process handle and `buffer` is writable
        // for the capacity supplied through `size`.
        match unsafe {
            QueryFullProcessImageNameW(
                handle,
                windows::Win32::System::Threading::PROCESS_NAME_FORMAT(0),
                PWSTR::from_raw(buffer.as_mut_ptr()),
                &mut size,
            )
        } {
            Ok(()) => return convert_wide_buffer(&buffer, size as usize),
            Err(error) if error.code().0 as u32 == ERROR_INSUFFICIENT_BUFFER.0 => {
                let required = usize::try_from(size).unwrap_or(0).saturating_add(1);
                let next = next_path_capacity(buffer.len().max(required))?;
                buffer.resize(next, 0);
            }
            Err(error) => return Err(WIN32_ERROR(error.code().0 as u32).into()),
        }
    }
}

fn filetime_value(value: FILETIME) -> u64 {
    (u64::from(value.dwHighDateTime) << 32) | u64::from(value.dwLowDateTime)
}

unsafe fn query_process_creation_time(handle: HANDLE) -> WholockResult<u64> {
    let mut creation_time = FILETIME::default();
    let mut exit_time = FILETIME::default();
    let mut kernel_time = FILETIME::default();
    let mut user_time = FILETIME::default();

    // SAFETY: `handle` is a live process handle with query access. All output
    // pointers refer to initialized writable FILETIME values for this call.
    unsafe {
        GetProcessTimes(
            handle,
            &mut creation_time,
            &mut exit_time,
            &mut kernel_time,
            &mut user_time,
        )?;
    }

    Ok(filetime_value(creation_time))
}

unsafe fn module_path_for_handle(
    process: windows::Win32::Foundation::HANDLE,
    module: HMODULE,
) -> WholockResult<Option<String>> {
    let mut buffer = vec![0u16; MAX_PATH as usize + 1];

    loop {
        // SAFETY: `process` and `module` are valid handles from the current
        // process module enumeration, and `buffer` is writable.
        let len = unsafe { GetModuleFileNameExW(Some(process), Some(module), &mut buffer) };
        if len == 0 {
            return Ok(None);
        }

        let len = len as usize;
        if len + 1 < buffer.len() {
            return convert_wide_buffer(&buffer, len).map(Some);
        }

        let next = next_path_capacity(buffer.len())?;
        buffer.resize(next, 0);
    }
}

pub(crate) fn get_process_identity_by_handle(handle: HANDLE) -> WholockResult<ProcessIdentity> {
    // SAFETY: The caller provides a live process handle with query access. Both
    // helpers only read process metadata into owned Rust values.
    unsafe {
        let process_exe_path = query_full_process_image_path(handle)?;
        let process_name = extract_filename(&process_exe_path)?;
        let creation_time = query_process_creation_time(handle)?;

        Ok(ProcessIdentity {
            process_name,
            process_exe_path,
            creation_time,
        })
    }
}

pub(crate) fn get_process_identity(pid: u32) -> WholockResult<ProcessIdentity> {
    // SAFETY: OpenProcess returns an owned process handle for `pid` on success
    // and that handle is wrapped in SafeHandle. Metadata is queried through the
    // same live handle so the image path and creation time identify one process.
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| {
            WholockError::process(format!(
                "Failed to open process {}: {}",
                pid,
                get_win32_error_message(&WIN32_ERROR(e.code().0 as u32))
            ))
        })?;

        let safe_handle = SafeHandle::new(handle)?;
        get_process_identity_by_handle(safe_handle.as_raw())
    }
}

fn module_count_from_needed_bytes(needed: u32) -> usize {
    let module_size = mem::size_of::<HMODULE>();
    (needed as usize).div_ceil(module_size)
}

pub(crate) fn get_process_ids() -> WholockResult<Vec<u32>> {
    let mut process_ids = vec![0u32; INITIAL_PROCESS_ID_CAPACITY];

    loop {
        let buffer_bytes = process_ids
            .len()
            .checked_mul(mem::size_of::<u32>())
            .and_then(|bytes| u32::try_from(bytes).ok())
            .ok_or_else(|| WholockError::other("Process ID buffer is too large"))?;
        let mut needed = 0u32;

        // SAFETY: `process_ids` is a writable array with `buffer_bytes` bytes,
        // and `needed` points to a valid writable DWORD for the returned size.
        unsafe {
            EnumProcesses(process_ids.as_mut_ptr(), buffer_bytes, &mut needed)?;
        }

        if needed < buffer_bytes {
            let process_count = needed as usize / mem::size_of::<u32>();
            process_ids.truncate(process_count);
            process_ids.retain(|pid| *pid != 0);
            process_ids.sort_unstable();
            process_ids.dedup();
            return Ok(process_ids);
        }

        if process_ids.len() >= MAX_PROCESS_ID_CAPACITY {
            return Err(WholockError::other(
                "Process ID enumeration exceeded the supported limit",
            ));
        }

        process_ids.resize(
            process_ids
                .len()
                .saturating_mul(2)
                .min(MAX_PROCESS_ID_CAPACITY),
            0,
        );
    }
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
            if let Ok(Some(path)) = module_path_for_handle(safe_handle.as_raw(), module) {
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
        let identity = get_process_identity(pid).unwrap();
        assert!(!identity.process_name.is_empty());
        assert!(std::path::Path::new(&identity.process_exe_path).exists());
        assert_ne!(identity.creation_time, 0);
        assert_eq!(
            identity.process_name,
            std::path::Path::new(&identity.process_exe_path)
                .file_name()
                .unwrap()
                .to_str()
                .unwrap()
        );
    }

    #[test]
    fn test_process_ids_include_current_process() {
        let process_ids = get_process_ids().unwrap();

        assert!(process_ids.contains(&std::process::id()));
        assert!(process_ids.windows(2).all(|pair| pair[0] < pair[1]));
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
