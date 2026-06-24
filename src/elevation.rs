use crate::WholockResult;
use crate::error::WholockError;
use crate::interop::{
    enable_debug_privilege as enable_current_process_debug_privilege,
    is_process_elevated as current_process_is_elevated,
};
use itertools::Itertools;
use std::ffi::OsStr;
use std::os::windows::ffi::OsStrExt;
use windows::Win32::Foundation::HWND;
use windows::Win32::UI::Shell::ShellExecuteW;
use windows::Win32::UI::WindowsAndMessaging::SW_SHOWNORMAL;
use windows::core::PCWSTR;

fn wide_null(value: &str) -> Vec<u16> {
    value.encode_utf16().chain(std::iter::once(0)).collect()
}

fn wide_null_os(value: &OsStr) -> Vec<u16> {
    value.encode_wide().chain(std::iter::once(0)).collect()
}

fn quote_windows_arg_from_str(arg: &str) -> String {
    let needs_quotes = arg.is_empty() || arg.chars().any(|ch| ch.is_whitespace() || ch == '"');
    if !needs_quotes {
        return arg.to_string();
    }

    let mut quoted = String::from("\"");
    let mut backslashes = 0usize;

    for ch in arg.chars() {
        if ch == '\\' {
            backslashes += 1;
            continue;
        }

        if ch == '"' {
            quoted.extend(std::iter::repeat('\\').take(backslashes * 2 + 1));
            quoted.push('"');
        } else {
            quoted.extend(std::iter::repeat('\\').take(backslashes));
            quoted.push(ch);
        }

        backslashes = 0;
    }

    quoted.extend(std::iter::repeat('\\').take(backslashes * 2));
    quoted.push('"');
    quoted
}

fn quote_windows_arg(arg: &OsStr) -> String {
    quote_windows_arg_from_str(&arg.to_string_lossy())
}

/// Returns whether the current process is running with an elevated token.
pub fn is_process_elevated() -> WholockResult<bool> {
    current_process_is_elevated()
}

/// Enables `SeDebugPrivilege` on the current process token when the token has it.
pub fn enable_debug_privilege() -> WholockResult<()> {
    enable_current_process_debug_privilege()
}

/// Starts an elevated copy of the current executable with the same arguments.
///
/// The current process is left running so callers can decide whether and when to exit.
pub fn start_as_elevated() -> WholockResult<()> {
    let exe = std::env::current_exe()?;
    let file = wide_null_os(exe.as_os_str());
    let operation = wide_null("runas");
    let parameters = std::env::args_os()
        .skip(1)
        .map(|arg| quote_windows_arg(&arg))
        .join(" ");
    let parameters = if parameters.is_empty() {
        None
    } else {
        Some(wide_null(&parameters))
    };
    let parameters = parameters
        .as_ref()
        .map_or(PCWSTR::null(), |value| PCWSTR(value.as_ptr()));

    // SAFETY: `operation`, `file`, and `parameters` are null-terminated UTF-16
    // buffers that live until ShellExecuteW returns. HWND and directory are null
    // because no owner window or working directory override is required.
    let result = unsafe {
        ShellExecuteW(
            HWND::default(),
            PCWSTR(operation.as_ptr()),
            PCWSTR(file.as_ptr()),
            parameters,
            PCWSTR::null(),
            SW_SHOWNORMAL,
        )
    };

    let code = result.0 as usize;
    if code <= 32 {
        return Err(WholockError::elevation_start(code));
    }

    Ok(())
}

/// Alias for [`start_as_elevated`].
pub fn restart_as_elevated() -> WholockResult<()> {
    start_as_elevated()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_process_elevated() {
        assert!(is_process_elevated().is_ok());
    }

    #[test]
    fn test_quote_windows_arg() {
        assert_eq!(quote_windows_arg_from_str("plain"), "plain");
        assert_eq!(quote_windows_arg_from_str("two words"), "\"two words\"");
        assert_eq!(quote_windows_arg_from_str(""), "\"\"");
        assert_eq!(
            quote_windows_arg_from_str(r#"say "hello""#),
            r#""say \"hello\"""#
        );
        assert_eq!(
            quote_windows_arg_from_str(r#"C:\path with space\"#),
            r#""C:\path with space\\""#
        );
    }

    #[test]
    fn test_elevation_start_error_uses_shell_execute_code() {
        let error = WholockError::elevation_start(5);

        assert!(matches!(
            error,
            WholockError::ElevationStartError(shell_error)
                if shell_error.code() == 5
                    && shell_error.description().contains("Access was denied")
        ));
    }
}
