use crate::{WholockResult, error::WholockError};
use std::{ffi::OsString, os::windows::ffi::OsStringExt, path::Path};
use windows::Win32::Foundation::{HANDLE, MAX_PATH};
use windows::Win32::Globalization::{CSTR_EQUAL, CompareStringOrdinal};
use windows::Win32::Storage::FileSystem::{
    CreateFileW, FILE_FLAG_BACKUP_SEMANTICS, FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE,
    OPEN_EXISTING,
};
use windows::core::PCWSTR;

use super::file_path::{
    FileIdentity, get_file_identity_by_handle, get_final_path_name_by_handle,
    strip_extended_path_prefix,
};
use super::handle::SafeHandle;
use super::object::get_object_name;

fn normalize_path(path: &str) -> String {
    let mut path = strip_extended_path_prefix(path.trim_end_matches('\0')).replace('/', "\\");

    while path.len() > 3 && path.ends_with('\\') {
        path.pop();
    }

    path
}

fn windows_ignore_case_eq_wide(left: &[u16], right: &[u16]) -> bool {
    // SAFETY: Both slices are valid UTF-16 buffers for the duration of the call.
    // CompareStringOrdinal only reads from them and the final argument requests
    // documented case-insensitive ordinal comparison.
    unsafe { CompareStringOrdinal(left, right, true) == CSTR_EQUAL }
}

fn path_for_windows_api(path: &str) -> String {
    let path = path.replace('/', "\\");
    if path.starts_with(r"\\?\") || path.starts_with(r"\\.\") {
        return path;
    }

    let path =
        if path.encode_utf16().count() >= MAX_PATH as usize && !Path::new(&path).is_absolute() {
            lexical_absolute_path(&path)
        } else {
            path
        };

    if path.encode_utf16().count() < MAX_PATH as usize {
        return path;
    }

    if let Some(unc_path) = path.strip_prefix(r"\\") {
        format!(r"\\?\UNC\{unc_path}")
    } else {
        format!(r"\\?\{path}")
    }
}

pub(crate) fn wide_null(path: &str) -> Vec<u16> {
    path_for_windows_api(path)
        .encode_utf16()
        .chain(std::iter::once(0))
        .collect()
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
            Some(HANDLE::default()),
        )
    }?;
    let handle = SafeHandle::new(handle)?;
    let raw_handle = handle.as_raw();
    get_final_path_name_by_handle(&raw_handle)
}

pub(crate) fn kernel_path_for_path(path: &str) -> WholockResult<String> {
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
            Some(HANDLE::default()),
        )
    }?;
    let handle = SafeHandle::new(handle)?;
    get_object_name(handle.as_raw())
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

struct PathIdentity {
    display_path: String,
    path: Vec<u16>,
    directory_prefix: Option<Vec<u16>>,
}

impl PathIdentity {
    fn new(path: &str, is_directory: bool) -> Self {
        let path = normalize_path(path);
        let directory_prefix = is_directory.then(|| {
            directory_match_prefix(&path)
                .encode_utf16()
                .collect::<Vec<_>>()
        });
        Self {
            path: path.encode_utf16().collect(),
            display_path: path,
            directory_prefix,
        }
    }

    fn matches_normalized(&self, path: &[u16]) -> bool {
        windows_ignore_case_eq_wide(path, &self.path)
            || self.directory_prefix.as_ref().is_some_and(|prefix| {
                path.len() >= prefix.len()
                    && windows_ignore_case_eq_wide(&path[..prefix.len()], prefix)
            })
    }

    fn matched_suffix<'a>(&self, path: &'a [u16]) -> Option<&'a [u16]> {
        if windows_ignore_case_eq_wide(path, &self.path) {
            return Some(&path[path.len()..]);
        }

        self.directory_prefix.as_ref().and_then(|prefix| {
            (path.len() >= prefix.len()
                && windows_ignore_case_eq_wide(&path[..prefix.len()], prefix))
            .then(|| &path[prefix.len()..])
        })
    }

    fn display_path_with_suffix(&self, suffix: &[u16]) -> String {
        if suffix.is_empty() {
            return self.display_path.clone();
        }

        format!(
            "{}\\{}",
            self.display_path,
            OsString::from_wide(suffix).to_string_lossy()
        )
    }
}

pub(crate) struct LockedPathMatcher {
    display: PathIdentity,
    display_aliases: Vec<PathIdentity>,
    kernel: Option<PathIdentity>,
    file_identity: Option<FileIdentity>,
}

impl LockedPathMatcher {
    pub(crate) fn new(target_path: &str) -> Self {
        let resolved_path =
            final_path_for_path(target_path).unwrap_or_else(|_| lexical_absolute_path(target_path));
        let is_directory = std::fs::metadata(&resolved_path)
            .or_else(|_| std::fs::metadata(target_path))
            .ok()
            .is_some_and(|metadata| metadata.is_dir());
        // Keep the caller's spelling as the primary display path. Windows may
        // resolve an 8.3 alias (for example, `RUNNER~1`) to a different long
        // path, so retain the resolved spelling as a matching alias as well.
        let display_path = lexical_absolute_path(target_path);
        let display = PathIdentity::new(&display_path, is_directory);
        let display_aliases = (normalize_path(&display_path) != normalize_path(&resolved_path))
            .then(|| PathIdentity::new(&resolved_path, is_directory))
            .into_iter()
            .collect();
        let kernel = kernel_path_for_path(target_path)
            .or_else(|_| kernel_path_for_path(&resolved_path))
            .ok()
            .filter(|path| !path.is_empty())
            .map(|path| PathIdentity::new(&path, is_directory));
        let file_identity = file_identity_for_path(target_path)
            .or_else(|_| file_identity_for_path(&resolved_path))
            .ok();

        Self {
            display,
            display_aliases,
            kernel,
            file_identity,
        }
    }

    fn matches_display_normalized(&self, path: &[u16]) -> bool {
        self.display.matches_normalized(path)
            || self
                .display_aliases
                .iter()
                .any(|alias| alias.matches_normalized(path))
    }

    #[cfg(test)]
    fn matches_display(&self, path: &str) -> bool {
        let path = normalize_path(path).encode_utf16().collect::<Vec<_>>();
        self.matches_display_normalized(&path)
    }

    #[cfg(test)]
    pub(crate) fn matches(&self, path: &str) -> bool {
        self.matches_display(path)
    }
}

fn file_identity_for_path(path: &str) -> WholockResult<FileIdentity> {
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
            Some(HANDLE::default()),
        )
    }?;
    let handle = SafeHandle::new(handle)?;
    get_file_identity_by_handle(handle.as_raw())
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

    pub(crate) fn kernel_paths_complete(&self) -> bool {
        self.matchers.iter().all(|matcher| matcher.kernel.is_some())
    }

    pub(crate) fn matches_kernel(&self, kernel_path: &str) -> bool {
        let kernel_path = normalize_path(kernel_path)
            .encode_utf16()
            .collect::<Vec<_>>();
        self.matchers.iter().any(|matcher| {
            matcher
                .kernel
                .as_ref()
                .is_some_and(|identity| identity.matches_normalized(&kernel_path))
        })
    }

    pub(crate) fn matching_display_path(
        &self,
        kernel_path: Option<&str>,
        file_identity: Option<FileIdentity>,
    ) -> Option<String> {
        if let Some(kernel_path) = kernel_path {
            let kernel_path = normalize_path(kernel_path)
                .encode_utf16()
                .collect::<Vec<_>>();
            if let Some(display_path) = self.matchers.iter().find_map(|matcher| {
                let suffix = matcher.kernel.as_ref()?.matched_suffix(&kernel_path)?;
                Some(matcher.display.display_path_with_suffix(suffix))
            }) {
                return Some(display_path);
            }
        }

        let file_identity = file_identity?;
        self.matchers
            .iter()
            .find(|matcher| matcher.file_identity == Some(file_identity))
            .map(|matcher| matcher.display.display_path.clone())
    }

    #[cfg(test)]
    pub(crate) fn matches(&self, path: &str) -> bool {
        self.matchers
            .iter()
            .any(|matcher| matcher.matches_display(path))
    }

    pub(crate) fn matches_resolved(&self, display_path: &str, kernel_path: Option<&str>) -> bool {
        let display_path = normalize_path(display_path)
            .encode_utf16()
            .collect::<Vec<_>>();
        if self
            .matchers
            .iter()
            .any(|matcher| matcher.matches_display_normalized(&display_path))
        {
            return true;
        }

        let Some(kernel_path) = kernel_path else {
            return false;
        };
        let kernel_path = normalize_path(kernel_path)
            .encode_utf16()
            .collect::<Vec<_>>();
        self.matchers.iter().any(|matcher| {
            matcher
                .kernel
                .as_ref()
                .is_some_and(|identity| identity.matches_normalized(&kernel_path))
        })
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
    fn test_kernel_path_matches_when_display_path_differs() {
        let dir = tempdir().unwrap();
        let file_path = dir.path().join("kernel-match.txt");
        File::create(&file_path).unwrap();

        let file_path = file_path.to_str().unwrap();
        let kernel_path = kernel_path_for_path(file_path).unwrap();
        let matchers = LockedPathMatchers::new([file_path]).unwrap();

        assert!(matchers.kernel_paths_complete());
        assert!(matchers.matches_kernel(&kernel_path));
        assert!(matchers.matches_resolved(r"Z:\alias\kernel-match.txt", Some(&kernel_path)));
    }

    #[test]
    fn test_hard_links_share_file_identity() {
        let dir = tempdir().unwrap();
        let target = dir.path().join("target.txt");
        let hard_link = dir.path().join("hard-link.txt");
        File::create(&target).unwrap();
        std::fs::hard_link(&target, &hard_link).unwrap();

        let target_identity = file_identity_for_path(target.to_str().unwrap()).unwrap();
        let link_identity = file_identity_for_path(hard_link.to_str().unwrap()).unwrap();

        assert_eq!(target_identity, link_identity);
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
