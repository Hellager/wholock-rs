use crate::scan::find_processes_recursive;
use crate::{WholockResult, types::WaitForUnlockResult};
use std::time::{Duration, Instant};

const WAIT_FOR_UNLOCK_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Waits until a single file or directory no longer has matching locks.
///
/// This is a convenience wrapper around [`wait_for_unlock_files`].
///
/// # Arguments
///
/// * `path` - The file or directory path to wait on
/// * `timeout` - Maximum duration to wait, or `None` to wait indefinitely
///
/// # Returns
///
/// Returns `WholockResult<WaitForUnlockResult>` describing whether the path unlocked,
/// how long polling took, and any remaining locks on timeout.
///
/// # Errors
///
/// Returns a [`WholockError`](crate::error::WholockError) if the path is invalid or if
/// a lock scan fails.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use wholock::wait_for_unlock;
///
/// let result = wait_for_unlock("C:\\path\\to\\file.txt", Some(Duration::from_secs(5)))?;
/// if result.timed_out() {
///     println!("still locked by {} process(es)", result.remaining_locks.len());
/// }
/// # Ok::<(), wholock::error::WholockError>(())
/// ```
pub fn wait_for_unlock(
    path: &str,
    timeout: Option<Duration>,
) -> WholockResult<WaitForUnlockResult> {
    wait_for_unlock_files(std::iter::once(path), timeout)
}

/// Waits until all files or directories no longer have matching locks.
///
/// The query is retried every 200ms. If `timeout` is `None`, this waits
/// indefinitely.
///
/// # Arguments
///
/// * `paths` - The file and directory paths to wait on
/// * `timeout` - Maximum duration to wait, or `None` to wait indefinitely
///
/// # Returns
///
/// Returns `WholockResult<WaitForUnlockResult>` with `unlocked` set to `true` when no
/// matching locks remain.
///
/// # Errors
///
/// Returns a [`WholockError`](crate::error::WholockError) if any path is invalid or if
/// a lock scan fails while polling.
///
/// # Examples
///
/// ```no_run
/// use std::time::Duration;
/// use wholock::wait_for_unlock_files;
///
/// let result = wait_for_unlock_files(
///     ["C:\\path\\to\\file.txt", "C:\\path\\to\\directory"],
///     Some(Duration::from_secs(10)),
/// )?;
///
/// assert!(result.unlocked || result.timed_out());
/// # Ok::<(), wholock::error::WholockError>(())
/// ```
pub fn wait_for_unlock_files<I, P>(
    paths: I,
    timeout: Option<Duration>,
) -> WholockResult<WaitForUnlockResult>
where
    I: IntoIterator<Item = P>,
    P: AsRef<str>,
{
    let paths = paths
        .into_iter()
        .map(|path| path.as_ref().to_string())
        .collect::<Vec<_>>();
    let start = Instant::now();
    let mut warnings = Vec::new();

    loop {
        let scan = find_processes_recursive(paths.iter().map(String::as_str))?;
        warnings.extend(scan.warnings);
        let remaining_locks = scan.processes;
        let elapsed = start.elapsed();

        if remaining_locks.is_empty() {
            return Ok(WaitForUnlockResult {
                unlocked: true,
                elapsed,
                remaining_locks,
                warnings,
            });
        }

        if timeout.is_some_and(|timeout| elapsed > timeout) {
            return Ok(WaitForUnlockResult {
                unlocked: false,
                elapsed,
                remaining_locks,
                warnings,
            });
        }

        let sleep_for = timeout
            .map(|timeout| {
                timeout
                    .saturating_sub(elapsed)
                    .min(WAIT_FOR_UNLOCK_POLL_INTERVAL)
            })
            .unwrap_or(WAIT_FOR_UNLOCK_POLL_INTERVAL);
        std::thread::sleep(sleep_for);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::error::WholockError;
    use tempfile::tempdir;

    #[test]
    fn test_wait_for_unlock_missing_path_returns_error() {
        let dir = tempdir().unwrap();
        let missing_path = dir.path().join("missing.txt");

        let result = wait_for_unlock(missing_path.to_str().unwrap(), Some(Duration::from_secs(1)));

        assert!(matches!(result, Err(WholockError::PathError(_))));
    }
}
