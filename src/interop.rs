use std::{
    ffi::{c_void, OsString},
    mem,
    os::{raw::{c_ulong, c_ushort}, windows::ffi::OsStringExt},
    ptr::{self, addr_of},
    slice,
};
use windows::Win32::Foundation::HANDLE;
use windows::core::{PCWSTR, PWSTR};
use windows::{Wdk::System::SystemInformation::{
    NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS,
}, Win32::Foundation::WIN32_ERROR};
use windows::Win32::System::Threading::{PROCESS_ACCESS_RIGHTS, OpenProcessToken};
use windows::Win32::Foundation::{DuplicateHandle, DUPLICATE_HANDLE_OPTIONS};
use windows::Win32::Storage::FileSystem::{GetFinalPathNameByHandleW, GETFINALPATHNAMEBYHANDLE_FLAGS};
use windows::Win32::Security::{GetTokenInformation, TokenUser, TOKEN_QUERY, TOKEN_USER};
use windows::Win32::Security::{LookupAccountSidW, SID_NAME_USE};
use crate::error::{WholockError, WholockResult};

pub(crate) const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS = SYSTEM_INFORMATION_CLASS(0x40);
pub(crate) const PROCESS_ACCESS_RIGHTS_DUP_HANDLE: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0040);
pub(crate) const PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION: PROCESS_ACCESS_RIGHTS = PROCESS_ACCESS_RIGHTS(0x0400);

pub(crate) struct SystemHandleInformationEx {
    number_of_handles: usize,
    _reserved: usize,
    handles: [SystemHandleTableEntryInfoEx; 1],
}

#[derive(Clone)]
pub(crate) struct SystemHandleTableEntryInfoEx {
    #[allow(dead_code)]
    object: *mut c_void,
    unique_process_id: usize,
    handle_value: *mut c_void,
    #[allow(dead_code)]
    granted_access: c_ulong,
    #[allow(dead_code)]
    creator_back_trace_index: c_ushort,
    #[allow(dead_code)]
    object_type_index: c_ushort,
    #[allow(dead_code)]
    handle_attributes: c_ulong,
    _reserved: c_ulong,
}

#[derive(Clone)]
pub(crate) struct HandleEntry(SystemHandleTableEntryInfoEx);

impl HandleEntry {
    #[allow(dead_code)]
    pub fn clone(&self) -> Self {
        HandleEntry(SystemHandleTableEntryInfoEx {
            object: self.0.object,
            unique_process_id: self.0.unique_process_id,
            handle_value: self.0.handle_value,
            granted_access: self.0.granted_access,
            creator_back_trace_index: self.0.creator_back_trace_index,
            object_type_index: self.0.object_type_index,
            handle_attributes: self.0.handle_attributes,
            _reserved: self.0._reserved,
        })
    }

    #[allow(dead_code)]
    fn object(&self) -> *mut c_void {
        self.0.object
    }
    pub fn unique_process_id(&self) -> usize {
        self.0.unique_process_id
    }
    fn handle_value(&self) -> *mut c_void {
        self.0.handle_value
    }
    #[allow(dead_code)]
    fn granted_access(&self) -> c_ulong {
        self.0.granted_access
    }
    #[allow(dead_code)]
    fn creator_back_trace_index(&self) -> c_ushort {
        self.0.creator_back_trace_index
    }
    #[allow(dead_code)]
    fn object_type_index(&self) -> c_ushort {
        self.0.object_type_index
    }
    #[allow(dead_code)]
    fn handle_attributes(&self) -> c_ulong {
        self.0.handle_attributes
    }
}

pub(crate) fn query_system_information_buffer(information_class: SYSTEM_INFORMATION_CLASS) -> WholockResult<Vec<u8>> {
    let mut buffer: Vec<u8> = vec![];
    loop {
        let mut return_length = 0;
        let result = unsafe {
            NtQuerySystemInformation(
                information_class,
                buffer.as_mut_ptr().cast(),
                buffer.len() as c_ulong,
                &mut return_length,
            )
        };
        let return_length = return_length as usize;

        if result.is_ok() {
            return Ok(buffer);
        } else if result.is_err() {
            if return_length > buffer.len() {
                buffer.clear();
                buffer.reserve_exact(return_length);
                buffer.resize(return_length, 0);
            } else {
                return Err(WholockError::SystemInfoError("Failed to query system information".to_string()));
            }
        }
    }
}

pub(crate) fn get_handle_table(buffer: &[u8]) -> &[HandleEntry] {
    let info_ptr: *const SystemHandleInformationEx = buffer.as_ptr().cast();
    let table_ptr: *const HandleEntry = unsafe { addr_of!((*info_ptr).handles).cast() };
    let len = unsafe { addr_of!((*info_ptr).number_of_handles).read_unaligned() };
    let table_offset = unsafe { table_ptr.cast::<u8>().offset_from(buffer.as_ptr()) };
    let max_len = (buffer.len() - table_offset as usize) / mem::size_of::<HandleEntry>();
    assert!(len <= max_len);
    unsafe { slice::from_raw_parts(table_ptr, len) }
}

#[allow(dead_code)]
pub(crate) fn query_system_info() {
    use log::debug;

    let buffer = query_system_information_buffer(SYSTEM_EXTENDED_HANDLE_INFORMATION).unwrap();
    let table = get_handle_table(&buffer);
    for (i, entry) in table.iter().enumerate() {
        debug!("entry {i}:");
        debug!("  Object = {:p}", entry.object());
        debug!("  UniqueProcessId = {}", entry.unique_process_id());
        debug!("  HandleValue = {:p}", entry.handle_value());
        debug!("  GrantedAccess = {:#x}", entry.granted_access());
        debug!(
            "  CreatorBackTraceIndex = {}",
            entry.creator_back_trace_index()
        );
        debug!("  ObjectTypeIndex = {}", entry.object_type_index());
        debug!("  HandleAttributes = {:#x}", entry.handle_attributes());
    }

    debug!("system info");
}

pub(crate) fn duplicate_handle(
    current_process: windows::Win32::Foundation::HANDLE,
    handle_owner_process: windows::Win32::Foundation::HANDLE,
    handle: &HandleEntry
) -> WholockResult<windows::Win32::Foundation::HANDLE> {
    let mut target_handle: windows::Win32::Foundation::HANDLE = windows::Win32::Foundation::HANDLE(ptr::null_mut());
    let result = unsafe {
        DuplicateHandle(
            handle_owner_process,
            windows::Win32::Foundation::HANDLE(handle.handle_value()),
            current_process,
            &mut target_handle,
            0,
            false,
            DUPLICATE_HANDLE_OPTIONS(0)
        )
    };

    match result {
        Ok(_) => Ok(target_handle),
        Err(_) => {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            Err(WholockError::Win32Error(err))
        },
    }
}

pub(crate) fn get_final_path_name_by_handle(h_file: &HANDLE) -> WholockResult<String> {
    let mut buf = vec![0u16; 1024];
    let mut result = unsafe {
        GetFinalPathNameByHandleW(
            *h_file,
            &mut buf,
            GETFINALPATHNAMEBYHANDLE_FLAGS(0),
        )
    };

    if result == 0 {
        return Err(WholockError::Win32Error(WIN32_ERROR(0x00000008)));
    }

    if result as usize > buf.len() {
        buf.resize(result as usize, 0);
        result = unsafe {
            GetFinalPathNameByHandleW(
                *h_file,
                &mut buf,
                GETFINALPATHNAMEBYHANDLE_FLAGS(0),
            )
        }; 
    }

    if result == 0 {
        return Err(WholockError::Win32Error(WIN32_ERROR(0x0000000D)));
    }

    let file_path = OsString::from_wide(&buf);
    let file_path = file_path.to_string_lossy().to_string();
    Ok(if file_path.starts_with(r"\\?\") {
        file_path[4..].to_string()
    } else {
        file_path
    })
}

pub(crate) fn check_if_locked_file(path: &str, target_path: &str) -> bool {
    path.to_lowercase().starts_with(&target_path.to_lowercase())
}

pub(crate) fn get_handle_owner_info(handle: HANDLE) -> WholockResult<String> {
    unsafe {
        let mut token_handle: HANDLE = HANDLE::default();
        let result = OpenProcessToken(handle, TOKEN_QUERY, &mut token_handle);
        if result.is_err() {
            return Err(std::io::Error::last_os_error().into());
        }

        let mut token_info_len = 0;
        let _ = GetTokenInformation(
            token_handle,
            TokenUser,
            None,
            0,
            &mut token_info_len
        );

        let mut token_info = vec![0u8; token_info_len as usize];
        if GetTokenInformation(
            token_handle,
            TokenUser,
            Some(token_info.as_mut_ptr() as *mut _),
            token_info_len,
            &mut token_info_len
        ).is_err() {
            return Err(std::io::Error::last_os_error().into());
        }

        let token_user = &*(token_info.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;

        let mut name_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_type = SID_NAME_USE::default();

        let _ = LookupAccountSidW(
            PCWSTR::null(),
            sid,
            PWSTR::null(),
            &mut name_size,
            PWSTR::null(),
            &mut domain_size,
            &mut sid_type
        );

        let mut name = vec![0u16; name_size as usize];
        let mut domain = vec![0u16; domain_size as usize];

        if LookupAccountSidW(
            PCWSTR::null(),
            sid,
            PWSTR::from_raw(name.as_mut_ptr()),
            &mut name_size,
            PWSTR::from_raw(domain.as_mut_ptr()),
            &mut domain_size,
            &mut sid_type
        ).is_err() {
            return Err(std::io::Error::last_os_error().into());
        }

        let name = String::from_utf16_lossy(&name[..name_size as usize]);
        let domain = String::from_utf16_lossy(&domain[..domain_size as usize]);

        Ok(format!("{}\\{}", domain, name))
    }
}

#[allow(dead_code)]
pub(crate) fn build_process_name_dict() -> WholockResult<std::collections::HashMap<usize, String>> {
    use sysinfo::System;

    let mut sys = System::new_all();
    sys.refresh_all();

    let mut process_name_dict: std::collections::HashMap<usize, String> = std::collections::HashMap::new();
    for (pid, process) in sys.processes() {
        process_name_dict.insert((*pid).into(), process.name().to_string_lossy().to_string());
    }

    Ok(process_name_dict)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::os::windows::io::AsRawHandle;
    use tempfile::tempdir;
    use windows::Win32::System::Threading::GetCurrentProcess;

    #[test]
    fn test_query_system_information_buffer() {
        let result = query_system_information_buffer(SYSTEM_EXTENDED_HANDLE_INFORMATION);
        assert!(result.is_ok());
        let buffer = result.unwrap();
        assert!(!buffer.is_empty());
    }

    #[test]
    fn test_get_handle_table() {
        let buffer = query_system_information_buffer(SYSTEM_EXTENDED_HANDLE_INFORMATION).unwrap();
        let table = get_handle_table(&buffer);
        assert!(!table.is_empty());
    }

    #[test]
    fn test_check_if_locked_file() {
        assert!(check_if_locked_file(
            r"C:\Users\test\file.txt",
            r"C:\Users\test"
        ));
        assert!(check_if_locked_file(
            r"C:\Users\test\file.txt",
            r"c:\users\test\file.txt"
        ));
        assert!(!check_if_locked_file(
            r"C:\Users\other\file.txt",
            r"C:\Users\test"
        ));
    }

    #[test]
    fn test_get_handle_owner_info() {
        let current_process = unsafe { GetCurrentProcess() };
        let result = get_handle_owner_info(current_process);
        assert!(result.is_ok());
        let owner_info = result.unwrap();
        assert!(!owner_info.is_empty());
        assert!(owner_info.contains('\\'));
    }

    #[test]
    fn test_get_final_path_name_by_handle() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("test.txt");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "test content").unwrap();

        let file = File::open(&file_path).unwrap();
        let handle = HANDLE(file.as_raw_handle() as _);
        
        let result = get_final_path_name_by_handle(&handle);
        assert!(result.is_ok());
        let path = result.unwrap();
        assert!(path.contains("test.txt"));
    }

    #[test]
    fn test_build_process_name_dict() {
        let result = build_process_name_dict();
        assert!(result.is_ok());
        let dict = result.unwrap();
        assert!(!dict.is_empty());
    }
}
