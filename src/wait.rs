use crate::scan::find_processes_recursive;
use crate::{WholockResult, types::WaitForUnlockResult};
use std::time::{Duration, Instant};

const WAIT_FOR_UNLOCK_POLL_INTERVAL: Duration = Duration::from_millis(200);

/// Waits until a single file or directory no longer has matching locks.
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

    loop {
        let remaining_locks = find_processes_recursive(paths.iter().map(String::as_str))?;
        let elapsed = start.elapsed();

        if remaining_locks.is_empty() {
            return Ok(WaitForUnlockResult {
                unlocked: true,
                elapsed,
                remaining_locks,
            });
        }

        if timeout.is_some_and(|timeout| elapsed > timeout) {
            return Ok(WaitForUnlockResult {
                unlocked: false,
                elapsed,
                remaining_locks,
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
