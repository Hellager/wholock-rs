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
    Other(String),
}

impl std::error::Error for WholockError {}

impl fmt::Display for WholockError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            WholockError::WindowsError(e) => write!(f, "Windows API error: {}", e),
            WholockError::Win32Error(e) => write!(f, "Win32 error: {:?}", e),
            WholockError::IoError(e) => write!(f, "IO error: {}", e),
            WholockError::SystemInfoError(e) => write!(f, "System info error: {}", e),
            WholockError::HandleError(e) => write!(f, "Handle operation error: {}", e),
            WholockError::Other(e) => write!(f, "{}", e),
        }
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

pub type WholockResult<T> = Result<T, WholockError>; 
