use crate::{error::get_win32_error_message, error::WholockError, WholockResult};
use std::{
    ffi::{c_void, OsString},
    mem,
    os::{
        raw::{c_ulong, c_ushort},
        windows::ffi::OsStringExt,
    },
    path::Path,
    ptr::{self, addr_of},
    slice,
    sync::mpsc::RecvTimeoutError,
    time::Duration,
};
use windows::core::{PCWSTR, PWSTR};
use windows::Wdk::Foundation::{NtQueryObject, ObjectTypeInformation};
use windows::Wdk::System::SystemInformation::{NtQuerySystemInformation, SYSTEM_INFORMATION_CLASS};
use windows::Win32::Foundation::{
    CloseHandle, DuplicateHandle, GetLastError, SetLastError, DUPLICATE_HANDLE_OPTIONS,
    ERROR_NONE_MAPPED, ERROR_NOT_ALL_ASSIGNED, HANDLE, HMODULE, MAX_PATH, UNICODE_STRING,
    WIN32_ERROR,
};
use windows::Win32::Globalization::{CompareStringOrdinal, CSTR_EQUAL};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LookupPrivilegeValueW, TokenElevation, TokenUser,
    LUID_AND_ATTRIBUTES, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, TOKEN_ADJUST_PRIVILEGES,
    TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
};
use windows::Win32::Security::{LookupAccountSidW, SID_NAME_USE};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, GetFinalPathNameByHandleW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE,
    FILE_SHARE_READ, FILE_SHARE_WRITE, GETFINALPATHNAMEBYHANDLE_FLAGS, OPEN_EXISTING,
};
use windows::Win32::System::ProcessStatus::{EnumProcessModules, GetModuleFileNameExW};
use windows::Win32::System::Threading::{
    GetCurrentProcess, OpenProcess, OpenProcessToken, QueryFullProcessImageNameW,
    PROCESS_ACCESS_RIGHTS, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_VM_READ,
};

pub(crate) const SYSTEM_EXTENDED_HANDLE_INFORMATION: SYSTEM_INFORMATION_CLASS =
    SYSTEM_INFORMATION_CLASS(0x40);
pub(crate) const PROCESS_ACCESS_RIGHTS_DUP_HANDLE: PROCESS_ACCESS_RIGHTS =
    PROCESS_ACCESS_RIGHTS(0x0040);
pub(crate) const PROCESS_ACCESS_RIGHTS_QUERY_INFORMATION: PROCESS_ACCESS_RIGHTS =
    PROCESS_ACCESS_RIGHTS(0x0400);
const DUPLICATE_HANDLE_TIMEOUT: Duration = Duration::from_secs(1);
const INITIAL_MODULE_CAPACITY: usize = 256;

#[repr(C)]
pub(crate) struct SystemHandleInformationEx {
    number_of_handles: usize,
    _reserved: usize,
    handles: [SystemHandleTableEntryInfoEx; 1],
}

#[repr(C)]
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

#[repr(transparent)]
pub(crate) struct HandleEntry(SystemHandleTableEntryInfoEx);

impl HandleEntry {
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
    pub(crate) fn handle_value_raw(&self) -> usize {
        self.0.handle_value as usize
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

#[repr(C)]
struct ObjectTypeInformationPrefix {
    name: UNICODE_STRING,
}

pub(crate) fn query_system_information_buffer(
    information_class: SYSTEM_INFORMATION_CLASS,
) -> WholockResult<Vec<u8>> {
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
                return Err(WholockError::SystemInfoError(
                    "Failed to query system information".to_string(),
                ));
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

#[cfg(test)]
pub(crate) fn duplicate_handle(
    current_process: windows::Win32::Foundation::HANDLE,
    handle_owner_process: windows::Win32::Foundation::HANDLE,
    handle: &HandleEntry,
) -> WholockResult<windows::Win32::Foundation::HANDLE> {
    duplicate_handle_value(
        current_process,
        handle_owner_process,
        handle.handle_value_raw(),
    )
}

pub(crate) fn duplicate_handle_value(
    current_process: windows::Win32::Foundation::HANDLE,
    handle_owner_process: windows::Win32::Foundation::HANDLE,
    source_handle: usize,
) -> WholockResult<windows::Win32::Foundation::HANDLE> {
    let current_process = current_process.0 as usize;
    let handle_owner_process = handle_owner_process.0 as usize;
    let (tx, rx) = std::sync::mpsc::channel();

    std::thread::spawn(move || {
        match duplicate_handle_blocking(current_process, handle_owner_process, source_handle) {
            Ok(handle) => {
                if tx.send(Ok(handle)).is_err() {
                    close_raw_handle(handle);
                }
            }
            Err(err) => {
                let _ = tx.send(Err(err));
            }
        }
    });

    match rx.recv_timeout(DUPLICATE_HANDLE_TIMEOUT) {
        Ok(result) => {
            result.map(|handle| windows::Win32::Foundation::HANDLE(handle as *mut c_void))
        }
        Err(RecvTimeoutError::Timeout) => Err(WholockError::HandleError(
            "Timed out while duplicating handle".to_string(),
        )),
        Err(RecvTimeoutError::Disconnected) => Err(WholockError::HandleError(
            "Handle duplication worker disconnected".to_string(),
        )),
    }
}

fn duplicate_handle_blocking(
    current_process: usize,
    handle_owner_process: usize,
    source_handle: usize,
) -> WholockResult<usize> {
    let mut target_handle: windows::Win32::Foundation::HANDLE =
        windows::Win32::Foundation::HANDLE(ptr::null_mut());
    let result = unsafe {
        DuplicateHandle(
            windows::Win32::Foundation::HANDLE(handle_owner_process as *mut c_void),
            windows::Win32::Foundation::HANDLE(source_handle as *mut c_void),
            windows::Win32::Foundation::HANDLE(current_process as *mut c_void),
            &mut target_handle,
            0,
            false,
            DUPLICATE_HANDLE_OPTIONS(0),
        )
    };

    match result {
        Ok(_) => Ok(target_handle.0 as usize),
        Err(_) => {
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            Err(WholockError::Win32Error(err))
        }
    }
}

fn close_raw_handle(handle: usize) {
    unsafe {
        let _ = CloseHandle(windows::Win32::Foundation::HANDLE(handle as *mut c_void));
    }
}

fn unicode_string_to_string(value: &UNICODE_STRING) -> String {
    if value.Buffer.is_null() || value.Length == 0 {
        return String::new();
    }

    let len = value.Length as usize / mem::size_of::<u16>();
    unsafe { OsString::from_wide(slice::from_raw_parts(value.Buffer.0, len)) }
        .to_string_lossy()
        .to_string()
}

pub(crate) fn get_object_type_name(handle: HANDLE) -> WholockResult<String> {
    let mut buffer = vec![0u8; 1024];

    loop {
        let mut return_length = 0;
        let status = unsafe {
            NtQueryObject(
                handle,
                ObjectTypeInformation,
                Some(buffer.as_mut_ptr().cast()),
                buffer.len() as u32,
                Some(&mut return_length),
            )
        };

        if status.is_ok() {
            let info = unsafe { &*(buffer.as_ptr() as *const ObjectTypeInformationPrefix) };
            return Ok(unicode_string_to_string(&info.name));
        }

        let return_length = return_length as usize;
        if return_length > buffer.len() {
            buffer.resize(return_length, 0);
            continue;
        }

        return Err(WholockError::Win32Error(WIN32_ERROR(status.0 as u32)));
    }
}

pub(crate) fn is_file_handle(handle: HANDLE) -> bool {
    get_object_type_name(handle).is_ok_and(|type_name| type_name == "File")
}

pub(crate) fn get_final_path_name_by_handle(h_file: &HANDLE) -> WholockResult<String> {
    let mut buf = vec![0u16; 1024];

    loop {
        let result = unsafe {
            GetFinalPathNameByHandleW(*h_file, &mut buf, GETFINALPATHNAMEBYHANDLE_FLAGS(0))
        };

        if result == 0 {
            return Err(WholockError::Win32Error(unsafe { GetLastError() }));
        }

        let result = result as usize;
        if result < buf.len() {
            let file_path = OsString::from_wide(&buf[..result])
                .to_string_lossy()
                .to_string();
            return Ok(strip_extended_path_prefix(&file_path));
        }

        buf.resize(result + 1, 0);
    }
}

fn strip_extended_path_prefix(path: &str) -> String {
    if let Some(path) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", path)
    } else if let Some(path) = path.strip_prefix(r"\\?\") {
        path.to_string()
    } else {
        path.to_string()
    }
}

fn normalize_path(path: &str) -> String {
    let mut path = strip_extended_path_prefix(path.trim_end_matches('\0')).replace('/', "\\");

    while path.len() > 3 && path.ends_with('\\') {
        path.pop();
    }

    path
}

fn windows_ignore_case_eq(left: &str, right: &str) -> bool {
    let left = left.encode_utf16().collect::<Vec<_>>();
    let right = right.encode_utf16().collect::<Vec<_>>();
    windows_ignore_case_eq_wide(&left, &right)
}

fn windows_ignore_case_eq_wide(left: &[u16], right: &[u16]) -> bool {
    unsafe { CompareStringOrdinal(left, right, true) == CSTR_EQUAL }
}

fn windows_path_starts_with_ignore_case(path: &str, prefix: &str) -> bool {
    let path = path.encode_utf16().collect::<Vec<_>>();
    let prefix = prefix.encode_utf16().collect::<Vec<_>>();

    path.len() >= prefix.len() && windows_ignore_case_eq_wide(&path[..prefix.len()], &prefix)
}

fn wide_null(path: &str) -> Vec<u16> {
    path.encode_utf16().chain(std::iter::once(0)).collect()
}

fn final_path_for_path(path: &str) -> WholockResult<String> {
    let path_wide = wide_null(path);
    let handle = unsafe {
        CreateFileW(
            PCWSTR(path_wide.as_ptr()),
            0,
            FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
            None,
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS,
            HANDLE::default(),
        )
    }?;
    let handle = SafeHandle::new(handle)?;
    let raw_handle = handle.as_raw();
    get_final_path_name_by_handle(&raw_handle)
}

fn lexical_absolute_path(path: &str) -> String {
    let path = Path::new(path);
    if path.is_absolute() {
        return path.to_string_lossy().to_string();
    }

    std::env::current_dir()
        .map(|dir| dir.join(path).to_string_lossy().to_string())
        .unwrap_or_else(|_| path.to_string_lossy().to_string())
}

pub(crate) fn target_path_is_missing(path: &str) -> bool {
    match std::fs::metadata(path).or_else(|_| std::fs::metadata(lexical_absolute_path(path))) {
        Ok(_) => false,
        Err(err) => err.kind() == std::io::ErrorKind::NotFound,
    }
}

fn directory_match_prefix(path: &str) -> String {
    if path.ends_with('\\') {
        path.to_string()
    } else {
        format!("{path}\\")
    }
}

pub(crate) struct LockedPathMatcher {
    target_path: String,
    target_directory_prefix: Option<String>,
}

impl LockedPathMatcher {
    pub(crate) fn new(target_path: &str) -> Self {
        let resolved_path =
            final_path_for_path(target_path).unwrap_or_else(|_| lexical_absolute_path(target_path));
        let is_directory = std::fs::metadata(&resolved_path)
            .or_else(|_| std::fs::metadata(target_path))
            .ok()
            .is_some_and(|metadata| metadata.is_dir());
        let target_path = normalize_path(&resolved_path);
        let target_directory_prefix = is_directory.then(|| directory_match_prefix(&target_path));

        Self {
            target_path,
            target_directory_prefix,
        }
    }

    fn matches_normalized(&self, path: &str) -> bool {
        windows_ignore_case_eq(path, &self.target_path)
            || self
                .target_directory_prefix
                .as_ref()
                .is_some_and(|prefix| windows_path_starts_with_ignore_case(path, prefix))
    }

    #[cfg(test)]
    pub(crate) fn matches(&self, path: &str) -> bool {
        self.matches_normalized(&normalize_path(path))
    }
}

pub(crate) struct LockedPathMatchers {
    matchers: Vec<LockedPathMatcher>,
}

impl LockedPathMatchers {
    pub(crate) fn new<I, P>(paths: I) -> Self
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let matchers = paths
            .into_iter()
            .filter_map(|path| {
                let path = path.as_ref();
                (!target_path_is_missing(path)).then(|| LockedPathMatcher::new(path))
            })
            .collect();

        Self { matchers }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }

    pub(crate) fn matches(&self, path: &str) -> bool {
        let path = normalize_path(path);
        self.matchers
            .iter()
            .any(|matcher| matcher.matches_normalized(&path))
    }
}

#[cfg(test)]
pub(crate) fn check_if_locked_file(path: &str, target_path: &str) -> bool {
    LockedPathMatcher::new(target_path).matches(path)
}

#[cfg(test)]
pub(crate) fn check_if_locked_files<I, P>(path: &str, target_paths: I) -> bool
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    LockedPathMatchers::new(target_paths).matches(path)
}

pub(crate) fn get_handle_owner_info(handle: HANDLE) -> WholockResult<String> {
    unsafe {
        let mut token_handle: HANDLE = HANDLE::default();
        let result = OpenProcessToken(handle, TOKEN_QUERY, &mut token_handle);
        if result.is_err() {
            return Ok(String::new());
        }
        let Ok(token_handle) = SafeHandle::new(token_handle) else {
            return Ok(String::new());
        };

        let mut token_info_len = 0;
        let _ = GetTokenInformation(
            token_handle.as_raw(),
            TokenUser,
            None,
            0,
            &mut token_info_len,
        );
        if token_info_len == 0 {
            return Ok(String::new());
        }

        let mut token_info = vec![0u8; token_info_len as usize];
        if GetTokenInformation(
            token_handle.as_raw(),
            TokenUser,
            Some(token_info.as_mut_ptr() as *mut _),
            token_info_len,
            &mut token_info_len,
        )
        .is_err()
        {
            return Ok(String::new());
        }

        let token_user = &*(token_info.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;

        let mut name_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_type = SID_NAME_USE::default();

        let lookup_probe = LookupAccountSidW(
            PCWSTR::null(),
            sid,
            PWSTR::null(),
            &mut name_size,
            PWSTR::null(),
            &mut domain_size,
            &mut sid_type,
        );
        if lookup_probe.is_err() {
            let last_error = GetLastError();
            if last_error == ERROR_NONE_MAPPED || name_size == 0 || domain_size == 0 {
                return Ok(String::new());
            }
        }

        if name_size == 0 || domain_size == 0 {
            return Ok(String::new());
        }

        let mut name = vec![0u16; name_size as usize];
        let mut domain = vec![0u16; domain_size as usize];

        if LookupAccountSidW(
            PCWSTR::null(),
            sid,
            PWSTR::from_raw(name.as_mut_ptr()),
            &mut name_size,
            PWSTR::from_raw(domain.as_mut_ptr()),
            &mut domain_size,
            &mut sid_type,
        )
        .is_err()
        {
            return Ok(String::new());
        }

        let name = String::from_utf16_lossy(&name[..name_size as usize]);
        let domain = String::from_utf16_lossy(&domain[..domain_size as usize]);

        Ok(format!("{}\\{}", domain, name))
    }
}

pub(crate) fn is_process_elevated() -> WholockResult<bool> {
    unsafe {
        let mut token_handle = HANDLE::default();
        OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token_handle)
            .map_err(WholockError::from)?;
        let token_handle = SafeHandle::new(token_handle)?;

        let mut elevation = TOKEN_ELEVATION::default();
        let mut returned_len = 0u32;
        GetTokenInformation(
            token_handle.as_raw(),
            TokenElevation,
            Some((&mut elevation as *mut TOKEN_ELEVATION).cast()),
            mem::size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned_len,
        )
        .map_err(WholockError::from)?;

        Ok(elevation.TokenIsElevated != 0)
    }
}

pub(crate) fn enable_debug_privilege() -> WholockResult<()> {
    unsafe {
        let mut token_handle = HANDLE::default();
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
            &mut token_handle,
        )
        .map_err(WholockError::from)?;
        let token_handle = SafeHandle::new(token_handle)?;

        let mut luid = Default::default();
        LookupPrivilegeValueW(PCWSTR::null(), SE_DEBUG_NAME, &mut luid)
            .map_err(WholockError::from)?;

        let privileges = TOKEN_PRIVILEGES {
            PrivilegeCount: 1,
            Privileges: [LUID_AND_ATTRIBUTES {
                Luid: luid,
                Attributes: SE_PRIVILEGE_ENABLED,
            }],
        };

        SetLastError(WIN32_ERROR(0));
        AdjustTokenPrivileges(
            token_handle.as_raw(),
            false,
            Some(&privileges),
            mem::size_of::<TOKEN_PRIVILEGES>() as u32,
            None,
            None,
        )
        .map_err(WholockError::from)?;

        let last_error = GetLastError();
        if last_error == ERROR_NOT_ALL_ASSIGNED {
            return Err(WholockError::PermissionError(
                "SeDebugPrivilege is not assigned to the current process token".to_string(),
            ));
        }

        Ok(())
    }
}

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

struct SafeHandle(HANDLE);

impl SafeHandle {
    fn new(handle: HANDLE) -> WholockResult<Self> {
        if handle.is_invalid() {
            return Err(WholockError::HandleError("Invalid handle".to_string()));
        }
        Ok(Self(handle))
    }

    fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            unsafe {
                if let Err(e) = CloseHandle(self.0) {
                    log::error!(
                        "Failed to close handle: {}",
                        get_win32_error_message(&WIN32_ERROR(e.code().0 as u32))
                    );
                }
            }
        }
    }
}

fn convert_wide_buffer(buffer: &[u16], len: usize) -> WholockResult<String> {
    let os_str = OsString::from_wide(&buffer[..len]);
    os_str
        .into_string()
        .map_err(|_| WholockError::EncodingError("Invalid UTF-16 sequence".to_string()))
}

fn extract_filename(path: &str) -> WholockResult<String> {
    std::path::Path::new(path)
        .file_name()
        .and_then(|n| n.to_str())
        .map(|s| s.to_string())
        .ok_or_else(|| WholockError::PathError("Invalid file path".to_string()))
}

pub(crate) fn get_process_info(pid: u32) -> WholockResult<(String, String)> {
    unsafe {
        let handle = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, false, pid).map_err(|e| {
            WholockError::ProcessError(format!(
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
        .map_err(|e| WholockError::Win32Error(WIN32_ERROR(e.code().0 as u32)))?;

        let path_str = convert_wide_buffer(&buffer, size as usize)?;
        let exe_name = extract_filename(&path_str)?;

        Ok((exe_name, path_str))
    }
}

fn module_count_from_needed_bytes(needed: u32) -> usize {
    let module_size = mem::size_of::<HMODULE>();
    (needed as usize + module_size - 1) / module_size
}

pub(crate) fn get_process_module_paths(pid: u32) -> WholockResult<Vec<String>> {
    unsafe {
        let handle =
            OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid).map_err(|e| {
                WholockError::ProcessError(format!(
                    "Failed to open process {} for module enumeration: {}",
                    pid,
                    get_win32_error_message(&WIN32_ERROR(e.code().0 as u32))
                ))
            })?;
        let safe_handle = SafeHandle::new(handle)?;

        let mut modules = vec![HMODULE::default(); INITIAL_MODULE_CAPACITY];

        loop {
            let mut needed = 0u32;
            let buffer_bytes = modules.len() * mem::size_of::<HMODULE>();
            let buffer_bytes = u32::try_from(buffer_bytes)
                .map_err(|_| WholockError::Other("Module buffer is too large".to_string()))?;
            EnumProcessModules(
                safe_handle.as_raw(),
                modules.as_mut_ptr(),
                buffer_bytes,
                &mut needed,
            )
            .map_err(|e| WholockError::Win32Error(WIN32_ERROR(e.code().0 as u32)))?;

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
            let len = GetModuleFileNameExW(safe_handle.as_raw(), module, &mut buffer);
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
    use std::fs::File;
    use std::io::Write;
    use std::os::windows::io::AsRawHandle;
    use std::ptr::addr_of;
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
    fn test_system_handle_struct_layout() {
        let info = SystemHandleInformationEx {
            number_of_handles: 0,
            _reserved: 0,
            handles: [SystemHandleTableEntryInfoEx {
                object: std::ptr::null_mut(),
                unique_process_id: 0,
                handle_value: std::ptr::null_mut(),
                granted_access: 0,
                creator_back_trace_index: 0,
                object_type_index: 0,
                handle_attributes: 0,
                _reserved: 0,
            }],
        };
        let info_base = addr_of!(info).cast::<u8>() as usize;
        let handles_offset = addr_of!(info.handles).cast::<u8>() as usize - info_base;

        assert_eq!(
            handles_offset,
            2 * mem::size_of::<usize>(),
            "SYSTEM_HANDLE_INFORMATION_EX handles offset must match NT ABI"
        );
        assert_eq!(
            mem::size_of::<SystemHandleTableEntryInfoEx>(),
            3 * mem::size_of::<usize>() + 4 * mem::size_of::<c_ulong>(),
            "SYSTEM_HANDLE_TABLE_ENTRY_INFO_EX size must match NT ABI"
        );
        assert_eq!(
            mem::size_of::<HandleEntry>(),
            mem::size_of::<SystemHandleTableEntryInfoEx>(),
            "HandleEntry must remain a transparent wrapper"
        );
        assert_eq!(
            mem::align_of::<HandleEntry>(),
            mem::align_of::<SystemHandleTableEntryInfoEx>(),
            "HandleEntry alignment must match the underlying NT entry"
        );
    }

    #[test]
    fn test_check_if_locked_file() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("locked.txt");
        let sibling_dir = tempdir().unwrap();
        let sibling_file_path = sibling_dir.path().join("locked.txt");
        File::create(&file_path).unwrap();
        File::create(&sibling_file_path).unwrap();

        let file_final_path = final_path_for_path(file_path.to_str().unwrap()).unwrap();
        let sibling_final_path = final_path_for_path(sibling_file_path.to_str().unwrap()).unwrap();

        assert!(check_if_locked_file(
            &file_final_path,
            file_path.to_str().unwrap()
        ));
        assert!(check_if_locked_file(
            &file_final_path.replace('\\', "/"),
            file_path.to_str().unwrap()
        ));
        assert!(check_if_locked_file(
            &file_final_path.replace("locked.txt", "LOCKED.TXT"),
            file_path.to_str().unwrap()
        ));
        assert!(check_if_locked_file(
            &file_final_path,
            dir.path().to_str().unwrap()
        ));
        assert!(!check_if_locked_file(
            &sibling_final_path,
            dir.path().to_str().unwrap()
        ));
    }

    #[test]
    fn test_check_if_locked_files() {
        let dir = tempdir().unwrap();
        let nested_file_path = dir.path().join("nested").join("locked.txt");
        std::fs::create_dir_all(nested_file_path.parent().unwrap()).unwrap();
        File::create(&nested_file_path).unwrap();

        let sibling_dir = tempdir().unwrap();
        let sibling_file_path = sibling_dir.path().join("locked.txt");
        File::create(&sibling_file_path).unwrap();

        let nested_final_path = final_path_for_path(nested_file_path.to_str().unwrap()).unwrap();
        let sibling_final_path = final_path_for_path(sibling_file_path.to_str().unwrap()).unwrap();
        let targets = [
            sibling_file_path.to_str().unwrap(),
            dir.path().to_str().unwrap(),
        ];

        assert!(check_if_locked_files(&nested_final_path, targets));
        assert!(check_if_locked_files(
            &nested_final_path.to_uppercase(),
            targets
        ));
        assert!(check_if_locked_files(&sibling_final_path, targets));
    }

    #[test]
    fn test_target_path_is_missing() {
        let dir = tempdir().unwrap();
        let missing_path = dir.path().join("missing.txt");

        assert!(target_path_is_missing(missing_path.to_str().unwrap()));
        assert!(!target_path_is_missing(dir.path().to_str().unwrap()));
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
    fn test_get_handle_owner_info_returns_empty_on_lookup_failure() {
        let owner_info = get_handle_owner_info(HANDLE::default()).unwrap();

        assert!(owner_info.is_empty());
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
        assert!(path.ends_with("test.txt"));
        assert!(!path.contains('\0'));
    }

    #[test]
    fn test_file_handle_type_detection() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("typed.txt");
        File::create(&file_path).unwrap();

        let file = File::open(&file_path).unwrap();
        let handle = HANDLE(file.as_raw_handle() as _);

        assert_eq!(get_object_type_name(handle).unwrap(), "File");
        assert!(is_file_handle(handle));
    }

    #[test]
    fn test_duplicate_handle() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("duplicate.txt");
        File::create(&file_path).unwrap();

        let file = File::open(&file_path).unwrap();
        let current_process = unsafe { GetCurrentProcess() };
        let entry = HandleEntry(SystemHandleTableEntryInfoEx {
            object: std::ptr::null_mut(),
            unique_process_id: std::process::id() as usize,
            handle_value: file.as_raw_handle() as *mut c_void,
            granted_access: 0,
            creator_back_trace_index: 0,
            object_type_index: 0,
            handle_attributes: 0,
            _reserved: 0,
        });

        let duplicated = duplicate_handle(current_process, current_process, &entry).unwrap();
        assert!(!duplicated.is_invalid());

        unsafe {
            CloseHandle(duplicated).unwrap();
        }
    }

    #[test]
    fn test_non_file_handle_type_detection() {
        let current_process = unsafe { GetCurrentProcess() };

        assert!(!is_file_handle(current_process));
    }

    #[test]
    fn test_get_final_path_name_by_exclusive_handle() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("exclusive.txt");
        File::create(&file_path).unwrap();

        let path_wide = wide_null(file_path.to_str().unwrap());
        let handle = unsafe {
            CreateFileW(
                PCWSTR(path_wide.as_ptr()),
                0,
                windows::Win32::Storage::FileSystem::FILE_SHARE_MODE(0),
                None,
                OPEN_EXISTING,
                windows::Win32::Storage::FileSystem::FILE_ATTRIBUTE_NORMAL,
                HANDLE::default(),
            )
        }
        .unwrap();
        let handle = SafeHandle::new(handle).unwrap();
        let raw_handle = handle.as_raw();

        let path = get_final_path_name_by_handle(&raw_handle).unwrap();

        assert!(path.ends_with("exclusive.txt"));
        assert!(!path.contains('\0'));
    }

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

    #[test_log::test]
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

    #[test_log::test]
    fn test_current_process_modules() {
        let modules = get_process_module_paths(std::process::id()).unwrap();

        assert!(!modules.is_empty());
        assert!(modules
            .iter()
            .any(|path| std::path::Path::new(path).exists()));
    }
}
