use std::fmt;
use windows::core::Error as WindowsError;
use windows::Win32::Foundation::WIN32_ERROR;

#[derive(Debug)]
pub enum WholockError {
    WindowsError(WindowsError),
    Win32Error(WIN32_ERROR),
    IoError(std::io::Error),
    SystemInfoError(String),
    HandleError(String),
    EncodingError(String),
    PathError(String),
    ProcessError(String),
    PermissionError(String),
    Other(String),
}

impl std::error::Error for WholockError {}

impl fmt::Display for WholockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WholockError::WindowsError(e) => write!(f, "Windows API error: {}", e),
            WholockError::Win32Error(e) => write!(f, "Win32 error code {}: {}", e.0, get_win32_error_message(e)),
            WholockError::IoError(e) => write!(f, "IO error: {}", e),
            WholockError::SystemInfoError(e) => write!(f, "System info error: {}", e),
            WholockError::HandleError(e) => write!(f, "Handle operation error: {}", e),
            WholockError::EncodingError(e) => write!(f, "Encoding error: {}", e),
            WholockError::PathError(e) => write!(f, "Path error: {}", e),
            WholockError::ProcessError(e) => write!(f, "Process error: {}", e),
            WholockError::PermissionError(e) => write!(f, "Permission error: {}", e),
            WholockError::Other(e) => write!(f, "{}", e),
        }
    }
}

pub(crate) fn get_win32_error_message(error: &WIN32_ERROR) -> String {
    use windows::Win32::System::Diagnostics::Debug::{FormatMessageW, FORMAT_MESSAGE_FROM_SYSTEM};
    use windows::core::PWSTR;
    
    let mut buffer = [0u16; 512];
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
        String::from_utf16_lossy(&buffer[..size as usize]).trim().to_string()
    }
}

impl From<WindowsError> for WholockError {
    fn from(error: WindowsError) -> Self {
        WholockError::WindowsError(error)
    }
}

impl From<WIN32_ERROR> for WholockError {
    fn from(error: WIN32_ERROR) -> Self {
        WholockError::Win32Error(error)
    }
}

impl From<std::io::Error> for WholockError {
    fn from(error: std::io::Error) -> Self {
        WholockError::IoError(error)
    }
}

impl From<String> for WholockError {
    fn from(error: String) -> Self {
        WholockError::Other(error)
    }
}
