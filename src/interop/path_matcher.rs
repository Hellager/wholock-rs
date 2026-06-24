use crate::{WholockResult, error::WholockError};
use std::path::Path;
use windows::Win32::Foundation::HANDLE;
use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::core::PCWSTR;

use super::file_path::{get_final_path_name_by_handle, strip_extended_path_prefix};
use super::handle::SafeHandle;

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
    // SAFETY: Both slices are valid UTF-16 buffers for the duration of the call.
    // CompareStringOrdinal only reads from them and the final argument requests
    // documented case-insensitive ordinal comparison.
    unsafe { CompareStringOrdinal(left, right, true) == CSTR_EQUAL }
}

fn windows_path_starts_with_ignore_case(path: &str, prefix: &str) -> bool {
    let path = path.encode_utf16().collect::<Vec<_>>();
    let prefix = prefix.encode_utf16().collect::<Vec<_>>();

    path.len() >= prefix.len() && windows_ignore_case_eq_wide(&path[..prefix.len()], &prefix)
}

pub(crate) fn wide_null(path: &str) -> Vec<u16> {
    path.encode_utf16().chain(std::iter::once(0)).collect()
}

pub(crate) fn final_path_for_path(path: &str) -> WholockResult<String> {
    let path_wide = wide_null(path);
    // SAFETY: `path_wide` is a null-terminated UTF-16 path buffer that lives
    // until CreateFileW returns. The returned handle is wrapped in SafeHandle.
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

pub(crate) fn validate_target_path(path: &str) -> WholockResult<()> {
    if path.trim().is_empty() {
        return Err(WholockError::path("Target path must not be empty"));
    }

    if path.contains('\0') {
        return Err(WholockError::path(format!(
            "Target path contains an embedded NUL: {path:?}"
        )));
    }

    match std::fs::metadata(path).or_else(|_| std::fs::metadata(lexical_absolute_path(path))) {
        Ok(_) => Ok(()),
        Err(err) => Err(WholockError::path(format!(
            "Target path does not exist or cannot be accessed: {path:?}: {err}"
        ))),
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
    pub(crate) fn new<I, P>(paths: I) -> WholockResult<Self>
    where
        I: IntoIterator<Item = P>,
        P: AsRef<str>,
    {
        let mut matchers = Vec::new();
        for path in paths {
            let path = path.as_ref();
            validate_target_path(path)?;
            matchers.push(LockedPathMatcher::new(path));
        }

        Ok(Self { matchers })
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
    LockedPathMatchers::new(target_paths)
        .expect("test target paths should be valid")
        .matches(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WholockError;
    use std::fs::File;
    use tempfile::tempdir;

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
    fn test_validate_target_path() {
        let dir = tempdir().unwrap();
        let missing_path = dir.path().join("missing.txt");

        assert!(matches!(
            validate_target_path(missing_path.to_str().unwrap()),
            Err(WholockError::PathError(_))
        ));
        let missing_message = validate_target_path(missing_path.to_str().unwrap())
            .unwrap_err()
            .to_string();
        assert!(missing_message.contains(&format!("{:?}", missing_path.to_str().unwrap())));
        assert!(matches!(
            validate_target_path(""),
            Err(WholockError::PathError(_))
        ));
        assert!(matches!(
            validate_target_path("C:\\bad\0path"),
            Err(WholockError::PathError(_))
        ));
        assert!(validate_target_path(dir.path().to_str().unwrap()).is_ok());
    }
}
