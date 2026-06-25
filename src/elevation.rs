use crate::WholockResult;
use crate::interop::{
    enable_debug_privilege as enable_current_process_debug_privilege,
    is_process_elevated as current_process_is_elevated,
};

/// Returns whether the current process is running with an elevated token.
///
/// # Returns
///
/// Returns `WholockResult<bool>` where `true` means the current process token is elevated.
///
/// # Errors
///
/// Returns a [`WholockError`](crate::error::WholockError) if the current process token
/// cannot be opened or queried.
///
/// # Examples
///
/// ```no_run
/// use wholock::is_process_elevated;
///
/// match is_process_elevated() {
///     Ok(true) => println!("running elevated"),
///     Ok(false) => println!("not elevated"),
///     Err(error) => eprintln!("failed to query elevation: {error}"),
/// }
/// ```
pub fn is_process_elevated() -> WholockResult<bool> {
    current_process_is_elevated()
}

/// Enables `SeDebugPrivilege` on the current process token when the token has it.
///
/// # Returns
///
/// Returns `WholockResult<()>` when the privilege was enabled successfully.
///
/// # Errors
///
/// Returns a [`WholockError`](crate::error::WholockError) if the process token cannot be
/// opened, if the privilege cannot be looked up, or if the token does not include
/// `SeDebugPrivilege`.
///
/// # Examples
///
/// ```no_run
/// use wholock::enable_debug_privilege;
///
/// if let Err(error) = enable_debug_privilege() {
///     eprintln!("lock scans may be incomplete: {error}");
/// }
/// ```
pub fn enable_debug_privilege() -> WholockResult<()> {
    enable_current_process_debug_privilege()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_is_process_elevated() {
        assert!(is_process_elevated().is_ok());
    }
}
