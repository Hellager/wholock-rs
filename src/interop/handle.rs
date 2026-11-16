use crate::{WholockResult, error::WholockError};
use std::{ffi::c_void, ptr};
use windows::Win32::Foundation::{CloseHandle, DUPLICATE_SAME_ACCESS, DuplicateHandle, HANDLE};

#[cfg(test)]
use super::nt_handles::HandleEntry;

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
    duplicate_handle_blocking(current_process, handle_owner_process, source_handle)
}

fn duplicate_handle_blocking(
    current_process: windows::Win32::Foundation::HANDLE,
    handle_owner_process: windows::Win32::Foundation::HANDLE,
    source_handle: usize,
) -> WholockResult<windows::Win32::Foundation::HANDLE> {
    let mut target_handle: windows::Win32::Foundation::HANDLE =
        windows::Win32::Foundation::HANDLE(ptr::null_mut());

    // SAFETY: `current_process` and `handle_owner_process` are live process handles
    // owned by the caller for the duration of this synchronous call. `source_handle`
    // is a handle value in `handle_owner_process`; invalid or inaccessible values are
    // reported by DuplicateHandle and converted to WholockError below.
    let result = unsafe {
        DuplicateHandle(
            handle_owner_process,
            windows::Win32::Foundation::HANDLE(source_handle as *mut c_void),
            current_process,
            &mut target_handle,
            0,
            false,
            DUPLICATE_SAME_ACCESS,
        )
    };

    match result {
        Ok(_) => Ok(target_handle),
        Err(_) => {
            // SAFETY: GetLastError has no preconditions and reads the calling
            // thread's last-error code immediately after DuplicateHandle failed.
            let err = unsafe { windows::Win32::Foundation::GetLastError() };
            Err(err.into())
        }
    }
}

pub(crate) struct SafeHandle(HANDLE);

impl SafeHandle {
    pub(crate) fn new(handle: HANDLE) -> WholockResult<Self> {
        if handle.is_invalid() {
            return Err(WholockError::handle("Invalid handle"));
        }
        Ok(Self(handle))
    }

    pub(crate) fn as_raw(&self) -> HANDLE {
        self.0
    }
}

impl Drop for SafeHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            // SAFETY: SafeHandle owns this handle and Drop is the single cleanup
            // path. Invalid handles are filtered out before CloseHandle.
            unsafe {
                let _ = CloseHandle(self.0);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::nt_handles::{HandleEntry, SystemHandleTableEntryInfoEx};
    use super::*;
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use tempfile::tempdir;
    use windows::Win32::Foundation::CloseHandle;
    use windows::Win32::System::Threading::GetCurrentProcess;

    #[test]
    fn test_duplicate_handle() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("duplicate.txt");
        File::create(&file_path).unwrap();

        let file = File::open(&file_path).unwrap();
        // SAFETY: GetCurrentProcess returns a pseudo-handle for the current
        // process. The duplicated file handle below is closed explicitly.
        let current_process = unsafe { GetCurrentProcess() };
        let entry = HandleEntry(SystemHandleTableEntryInfoEx {
            object: std::ptr::null_mut(),
            unique_process_id: std::process::id() as usize,
            handle_value: file.as_raw_handle(),
            granted_access: 0,
            creator_back_trace_index: 0,
            object_type_index: 0,
            handle_attributes: 0,
            _reserved: 0,
        });

        let duplicated = duplicate_handle(current_process, current_process, &entry).unwrap();
        assert!(!duplicated.is_invalid());

        // SAFETY: `duplicated` is an owned handle returned by DuplicateHandle in
        // this test and has not been closed yet.
        unsafe {
            CloseHandle(duplicated).unwrap();
        }
    }
}
