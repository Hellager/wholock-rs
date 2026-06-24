use crate::{WholockResult, error::WholockError, types::ProcessInfo};
use serde::Serialize;

#[derive(Serialize)]
struct JsonProcess<'a> {
    pid: u32,
    name: &'a str,
    exe_path: &'a str,
    user: &'a str,
    files: &'a [String],
}

#[derive(Serialize)]
struct JsonProcessList<'a> {
    processes: Vec<JsonProcess<'a>>,
}

fn json_process_list(processes: &[ProcessInfo]) -> JsonProcessList<'_> {
    JsonProcessList {
        processes: processes
            .iter()
            .map(|process| JsonProcess {
                pid: process.pid,
                name: &process.process_name,
                exe_path: &process.process_exe_path,
                user: &process.domain_username,
                files: &process.locked_file,
            })
            .collect(),
    }
}

/// Serializes process lock results as PowerToys-compatible JSON.
///
/// The output shape is `{ "processes": [{ "pid", "name", "exe_path", "user", "files" }] }`.
///
/// # Arguments
///
/// * `processes` - Process lock results to serialize
///
/// # Returns
///
/// Returns `WholockResult<String>` containing the JSON representation.
///
/// # Errors
///
/// Returns a [`WholockError`](crate::error::WholockError) if serialization fails.
///
/// # Examples
///
/// ```
/// use wholock::{ProcessInfo, processes_to_json};
///
/// let processes = vec![ProcessInfo {
///     pid: 42,
///     process_name: "locker.exe".to_string(),
///     process_exe_path: "C:\\tools\\locker.exe".to_string(),
///     domain_username: "DOMAIN\\user".to_string(),
///     locked_file: vec!["C:\\data\\locked.txt".to_string()],
/// }];
///
/// let json = processes_to_json(&processes)?;
/// assert!(json.contains("locker.exe"));
/// # Ok::<(), wholock::error::WholockError>(())
/// ```
pub fn processes_to_json(processes: &[ProcessInfo]) -> WholockResult<String> {
    serde_json::to_string(&json_process_list(processes))
        .map_err(|err| WholockError::other(format!("Failed to serialize JSON output: {err}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_processes_to_json() {
        let processes = vec![ProcessInfo {
            pid: 42,
            process_name: "locker.exe".to_string(),
            process_exe_path: r"C:\tools\locker.exe".to_string(),
            domain_username: r"DOMAIN\user".to_string(),
            locked_file: vec![r"C:\data\locked.txt".to_string()],
        }];

        let json = processes_to_json(&processes).unwrap();
        let value: serde_json::Value = serde_json::from_str(&json).unwrap();

        assert_eq!(value["processes"][0]["pid"], 42);
        assert_eq!(value["processes"][0]["name"], "locker.exe");
        assert_eq!(value["processes"][0]["exe_path"], r"C:\tools\locker.exe");
        assert_eq!(value["processes"][0]["user"], r"DOMAIN\user");
        assert_eq!(value["processes"][0]["files"][0], r"C:\data\locked.txt");
        assert!(value["processes"][0].get("process_name").is_none());
    }
}
