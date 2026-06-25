use std::fmt;
use thiserror::Error;
use windows::Win32::Foundation::WIN32_ERROR;
use windows::core::Error as WindowsError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum LockScanWarningKind {
    DebugPrivilege,
    OpenProcess,
    HandleEnumeration,
    ModuleEnumeration,
}

impl fmt::Display for LockScanWarningKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LockScanWarningKind::DebugPrivilege => f.write_str("debug privilege"),
            LockScanWarningKind::OpenProcess => f.write_str("open process"),
            LockScanWarningKind::HandleEnumeration => f.write_str("handle enumeration"),
            LockScanWarningKind::ModuleEnumeration => f.write_str("module enumeration"),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct LockScanWarning {
    pid: Option<u32>,
    kind: LockScanWarningKind,
    message: String,
}

impl LockScanWarning {
    pub(crate) fn new(
        pid: Option<u32>,
        kind: LockScanWarningKind,
        message: impl Into<String>,
    ) -> Self {
        Self {
            pid,
            kind,
            message: message.into(),
        }
    }

    /// Process identifier associated with the warning, if the warning is process-specific.
    #[must_use]
    pub fn pid(&self) -> Option<u32> {
        self.pid
    }

    /// Machine-readable warning category.
    #[must_use]
    pub fn kind(&self) -> LockScanWarningKind {
        self.kind
    }

    /// Human-readable warning details.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MessageError {
    message: String,
}

impl MessageError {
    pub(crate) fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }

    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for MessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl std::error::Error for MessageError {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Win32Error {
    code: WIN32_ERROR,
}

impl Win32Error {
    pub(crate) fn new(code: WIN32_ERROR) -> Self {
        Self { code }
    }

    pub fn code(&self) -> WIN32_ERROR {
        self.code
    }

    #[must_use]
    pub fn message(&self) -> String {
        get_win32_error_message(&self.code)
    }
}

impl fmt::Display for Win32Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Win32 error code {}: {}",
            self.code.0,
            get_win32_error_message(&self.code)
        )
    }
}

impl std::error::Error for Win32Error {}

#[derive(Debug, Error)]
#[non_exhaustive]
pub enum WholockError {
    #[error("Windows API error: {0}")]
    WindowsError(#[from] WindowsError),

    #[error("{0}")]
    Win32Error(#[source] Win32Error),

    #[error("IO error: {0}")]
    IoError(#[from] std::io::Error),

    #[error("System info error: {0}")]
    SystemInfoError(#[source] MessageError),

    #[error("Handle operation error: {0}")]
    HandleError(#[source] MessageError),

    #[error("Encoding error: {0}")]
    EncodingError(#[source] MessageError),

    #[error("Path error: {0}")]
    PathError(#[source] MessageError),

    #[error("Process error: {0}")]
    ProcessError(#[source] MessageError),

    #[error("Permission error: {0}")]
    PermissionError(#[source] MessageError),

    #[error("Invalid PID: {0}")]
    InvalidPID(u32),

    #[error(
        "Partial lock scan: found {} process(es), but {} scan warning(s) occurred{}",
        processes.len(),
        warnings.len(),
        first_lock_scan_warning(warnings)
    )]
    PartialLockScan {
        processes: Vec<crate::ProcessInfo>,
        warnings: Vec<LockScanWarning>,
    },

    #[error("{0}")]
    Other(#[source] MessageError),
}

impl WholockError {
    pub(crate) fn system_info(message: impl Into<String>) -> Self {
        Self::SystemInfoError(MessageError::new(message))
    }

    pub(crate) fn handle(message: impl Into<String>) -> Self {
        Self::HandleError(MessageError::new(message))
    }

    pub(crate) fn encoding(message: impl Into<String>) -> Self {
        Self::EncodingError(MessageError::new(message))
    }

    pub(crate) fn path(message: impl Into<String>) -> Self {
        Self::PathError(MessageError::new(message))
    }

    pub(crate) fn process(message: impl Into<String>) -> Self {
        Self::ProcessError(MessageError::new(message))
    }

    pub(crate) fn permission(message: impl Into<String>) -> Self {
        Self::PermissionError(MessageError::new(message))
    }

    pub(crate) fn other(message: impl Into<String>) -> Self {
        Self::Other(MessageError::new(message))
    }
}

fn first_lock_scan_warning(warnings: &[LockScanWarning]) -> String {
    let Some(warning) = warnings.first() else {
        return String::new();
    };

    let pid = warning
        .pid()
        .map_or(String::new(), |pid| format!("PID {pid} "));
    format!(
        "; first warning: {pid}{} failed: {}",
        warning.kind(),
        warning.message()
    )
}

pub(crate) fn get_win32_error_message(error: &WIN32_ERROR) -> String {
    use windows::Win32::System::Diagnostics::Debug::{FORMAT_MESSAGE_FROM_SYSTEM, FormatMessageW};
    use windows::core::PWSTR;

    let mut buffer = [0u16; 512];
    // SAFETY: `buffer` is a valid writable UTF-16 buffer and its length is
    // passed accurately. FormatMessageW writes at most that length and returns
    // the initialized character count used below.
    unsafe {
        let size = FormatMessageW(
            FORMAT_MESSAGE_FROM_SYSTEM,
            None,
            error.0,
            0,
            PWSTR::from_raw(buffer.as_mut_ptr()),
            buffer.len() as u32,
            None,
        );
        if size == 0 {
            return format!("Unknown error {}", error.0);
        }
        String::from_utf16_lossy(&buffer[..size as usize])
            .trim()
            .to_string()
    }
}

impl From<WIN32_ERROR> for WholockError {
    fn from(error: WIN32_ERROR) -> Self {
        WholockError::Win32Error(Win32Error::new(error))
    }
}

impl From<String> for WholockError {
    fn from(error: String) -> Self {
        WholockError::other(error)
    }
}
