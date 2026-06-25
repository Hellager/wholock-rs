use crate::{WholockResult, error::WholockError, error::get_win32_error_message};
use std::mem;
use windows::Win32::Foundation::{
    ERROR_NONE_MAPPED, ERROR_NOT_ALL_ASSIGNED, GetLastError, HANDLE, SetLastError, WIN32_ERROR,
};
use windows::Win32::Security::{
    AdjustTokenPrivileges, GetTokenInformation, LUID_AND_ATTRIBUTES, LookupAccountSidW,
    LookupPrivilegeValueW, SE_DEBUG_NAME, SE_PRIVILEGE_ENABLED, SID_NAME_USE,
    TOKEN_ADJUST_PRIVILEGES, TOKEN_ELEVATION, TOKEN_PRIVILEGES, TOKEN_QUERY, TOKEN_USER,
    TokenElevation, TokenUser,
};
use windows::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};
use windows::core::{PCWSTR, PWSTR};

use super::handle::SafeHandle;

fn handle_lookup_account_sid_failure(error: WIN32_ERROR) -> WholockResult<String> {
    if error == ERROR_NONE_MAPPED {
        return Ok(String::new());
    }

    Err(WholockError::process(format!(
        "LookupAccountSidW failed: {}",
        get_win32_error_message(&error)
    )))
}

pub(crate) fn get_handle_owner_info(handle: HANDLE) -> WholockResult<String> {
    // SAFETY: All Win32 calls below receive live handles returned by Windows or
    // stack/vector buffers sized from prior API probes. Every successful HANDLE
    // is immediately wrapped in SafeHandle for cleanup before returning.
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

        // SAFETY: The TOKEN_USER buffer was filled by GetTokenInformation with
        // TokenUser and is at least `token_info_len` bytes. TOKEN_USER is the
        // documented leading layout for that buffer.
        let token_user = &*(token_info.as_ptr() as *const TOKEN_USER);
        let sid = token_user.User.Sid;

        let mut name_size = 0u32;
        let mut domain_size = 0u32;
        let mut sid_type = SID_NAME_USE::default();

        let lookup_probe = LookupAccountSidW(
            PCWSTR::null(),
            sid,
            Some(PWSTR::null()),
            &mut name_size,
            Some(PWSTR::null()),
            &mut domain_size,
            &mut sid_type,
        );
        if lookup_probe.is_err() {
            let last_error = GetLastError();
            if last_error == ERROR_NONE_MAPPED {
                return handle_lookup_account_sid_failure(last_error);
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
            Some(PWSTR::from_raw(name.as_mut_ptr())),
            &mut name_size,
            Some(PWSTR::from_raw(domain.as_mut_ptr())),
            &mut domain_size,
            &mut sid_type,
        )
        .is_err()
        {
            return handle_lookup_account_sid_failure(GetLastError());
        }

        let name = String::from_utf16_lossy(&name[..name_size as usize]);
        let domain = String::from_utf16_lossy(&domain[..domain_size as usize]);

        Ok(format!("{}\\{}", domain, name))
    }
}

pub(crate) fn is_process_elevated() -> WholockResult<bool> {
    // SAFETY: GetCurrentProcess returns a pseudo-handle used only for
    // OpenProcessToken. The token handle returned by OpenProcessToken is wrapped
    // in SafeHandle, and TOKEN_ELEVATION is passed with its exact size.
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
    // SAFETY: GetCurrentProcess returns a pseudo-handle used only for
    // OpenProcessToken. The token handle is wrapped in SafeHandle. LUID and
    // TOKEN_PRIVILEGES are initialized before being passed to the Windows APIs.
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
            return Err(WholockError::permission(
                "SeDebugPrivilege is not assigned to the current process token".to_string(),
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WholockError;
    use windows::Win32::Foundation::HANDLE;
    use windows::Win32::System::Threading::GetCurrentProcess;

    #[test]
    fn test_get_handle_owner_info() {
        // SAFETY: GetCurrentProcess returns a pseudo-handle for the current
        // process. The test passes it to get_handle_owner_info and never closes it.
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
    fn test_lookup_account_sid_failure_mapping() {
        assert!(
            handle_lookup_account_sid_failure(ERROR_NONE_MAPPED)
                .unwrap()
                .is_empty()
        );
        assert!(matches!(
            handle_lookup_account_sid_failure(WIN32_ERROR(5)),
            Err(WholockError::ProcessError(message)) if message.message().contains("LookupAccountSidW failed")
        ));
    }
}
