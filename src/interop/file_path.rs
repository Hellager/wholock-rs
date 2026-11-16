use crate::WholockResult;
use std::{ffi::OsString, os::windows::ffi::OsStringExt};
use windows::Win32::Foundation::{GetLastError, HANDLE};
use windows::Win32::Storage::FileSystem::{
    GETFINALPATHNAMEBYHANDLE_FLAGS, GetFinalPathNameByHandleW,
};

#[cfg(test)]
use super::object::get_object_name;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ResolvedFilePath {
    pub(crate) display_path: String,
    pub(crate) kernel_path: Option<String>,
    pub(crate) kernel_path_error: Option<String>,
}

pub(crate) fn get_final_path_name_by_handle(h_file: &HANDLE) -> WholockResult<String> {
    let mut buf = vec![0u16; 1024];

    loop {
        // SAFETY: `h_file` is expected to be a live file handle. `buf` is a
        // writable UTF-16 buffer whose length is passed to the Windows API.
        let result = unsafe {
            GetFinalPathNameByHandleW(*h_file, &mut buf, GETFINALPATHNAMEBYHANDLE_FLAGS(0))
        };

        if result == 0 {
            // SAFETY: GetLastError has no preconditions and is read immediately
            // after GetFinalPathNameByHandleW reports failure.
            return Err(unsafe { GetLastError() }.into());
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

#[cfg(test)]
fn get_file_paths_by_handle(h_file: &HANDLE) -> WholockResult<ResolvedFilePath> {
    let (kernel_path, kernel_path_error) = match get_object_name(*h_file) {
        Ok(path) => (Some(path), None),
        Err(err) => (None, Some(err.to_string())),
    };

    Ok(ResolvedFilePath {
        display_path: get_final_path_name_by_handle(h_file)?,
        kernel_path,
        kernel_path_error,
    })
}

pub(crate) fn strip_extended_path_prefix(path: &str) -> String {
    if let Some(path) = path.strip_prefix(r"\\?\UNC\") {
        format!(r"\\{}", path)
    } else if let Some(path) = path.strip_prefix(r"\\?\") {
        path.to_string()
    } else {
        path.to_string()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs::File;
    use std::io::Write;
    use std::os::windows::io::AsRawHandle;
    use tempfile::tempdir;

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
    fn test_get_file_paths_by_handle() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("resolved.txt");
        let mut file = File::create(&file_path).unwrap();
        writeln!(file, "test content").unwrap();

        let file = File::open(&file_path).unwrap();
        let handle = HANDLE(file.as_raw_handle() as _);
        let paths = get_file_paths_by_handle(&handle).unwrap();

        assert!(paths.display_path.ends_with("resolved.txt"));
        assert!(
            paths
                .kernel_path
                .as_deref()
                .is_some_and(|path| path.ends_with("resolved.txt"))
        );
        assert!(paths.kernel_path_error.is_none());
    }
}
