use crate::WholockResult;
use std::{ffi::OsString, mem, os::windows::ffi::OsStringExt, slice};
use windows::Wdk::Foundation::{NtQueryObject, OBJECT_INFORMATION_CLASS, ObjectTypeInformation};
use windows::Win32::Foundation::{HANDLE, UNICODE_STRING, WIN32_ERROR};

#[repr(C)]
struct ObjectTypeInformationPrefix {
    name: UNICODE_STRING,
}

const OBJECT_NAME_INFORMATION: OBJECT_INFORMATION_CLASS = OBJECT_INFORMATION_CLASS(1);
const MAX_OBJECT_INFORMATION_BUFFER_SIZE: usize = 1024 * 1024;

fn unicode_string_to_string(value: &UNICODE_STRING) -> String {
    if value.Buffer.is_null() || value.Length == 0 {
        return String::new();
    }

    let len = value.Length as usize / mem::size_of::<u16>();
    // SAFETY: `UNICODE_STRING` is returned by Windows for the lifetime of the
    // object information buffer. Length is in bytes and has been converted to
    // u16 code units; null and zero-length buffers were handled above.
    unsafe { OsString::from_wide(slice::from_raw_parts(value.Buffer.0, len)) }
        .to_string_lossy()
        .to_string()
}

pub(crate) fn get_object_type_name(handle: HANDLE) -> WholockResult<String> {
    let mut buffer = vec![0u8; 1024];

    loop {
        let mut return_length = 0;
        // SAFETY: `handle` is supplied by the caller as a live handle. `buffer`
        // is a writable byte buffer and `return_length` is a valid out-parameter.
        let status = unsafe {
            NtQueryObject(
                Some(handle),
                ObjectTypeInformation,
                Some(buffer.as_mut_ptr().cast()),
                buffer.len() as u32,
                Some(&mut return_length),
            )
        };

        if status.is_ok() {
            // SAFETY: On success NtQueryObject wrote an OBJECT_TYPE_INFORMATION
            // compatible prefix into `buffer`; we only read the leading
            // UNICODE_STRING field represented by ObjectTypeInformationPrefix.
            let info = unsafe { &*(buffer.as_ptr() as *const ObjectTypeInformationPrefix) };
            return Ok(unicode_string_to_string(&info.name));
        }

        let return_length = return_length as usize;
        if return_length > buffer.len() {
            buffer.resize(return_length, 0);
            continue;
        }

        return Err(WIN32_ERROR(status.0 as u32).into());
    }
}

pub(crate) fn get_object_name(handle: HANDLE) -> WholockResult<String> {
    let mut buffer = vec![0u8; 1024];

    loop {
        let mut return_length = 0;
        // SAFETY: `handle` is supplied by the caller as a live handle. `buffer`
        // is a writable byte buffer and `return_length` is a valid out-parameter.
        let status = unsafe {
            NtQueryObject(
                Some(handle),
                OBJECT_NAME_INFORMATION,
                Some(buffer.as_mut_ptr().cast()),
                buffer.len() as u32,
                Some(&mut return_length),
            )
        };

        if status.is_ok() {
            // SAFETY: On success NtQueryObject wrote an OBJECT_NAME_INFORMATION
            // compatible prefix into `buffer`; the UNICODE_STRING points into the
            // same buffer and remains valid while it is borrowed here.
            let info = unsafe { &*(buffer.as_ptr() as *const ObjectTypeInformationPrefix) };
            return Ok(unicode_string_to_string(&info.name));
        }

        let required = return_length as usize;
        if required > buffer.len() && required <= MAX_OBJECT_INFORMATION_BUFFER_SIZE {
            buffer.resize(required, 0);
            continue;
        }

        return Err(WIN32_ERROR(status.0 as u32).into());
    }
}

pub(crate) fn is_file_handle(handle: HANDLE) -> bool {
    get_object_type_name(handle).is_ok_and(|type_name| type_name == "File")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::os::windows::io::AsRawHandle;
    use tempfile::tempdir;
    use windows::Win32::System::Threading::GetCurrentProcess;

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
    fn test_file_handle_name_detection() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("named.txt");
        File::create(&file_path).unwrap();

        let file = File::open(&file_path).unwrap();
        let handle = HANDLE(file.as_raw_handle() as _);
        let name = get_object_name(handle).unwrap();

        assert!(!name.is_empty());
        assert!(name.ends_with("named.txt"));
    }

    #[test]
    fn test_non_file_handle_type_detection() {
        // SAFETY: GetCurrentProcess returns a pseudo-handle that is valid for
        // type probing and must not be closed.
        let current_process = unsafe { GetCurrentProcess() };

        assert!(!is_file_handle(current_process));
    }
}
