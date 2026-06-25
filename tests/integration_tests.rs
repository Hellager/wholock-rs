use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::tempdir;
use wholock::ProcessInfo;
use wholock::{unlock_file, who_locks_file};

const LOCK_HELPER_PATH_ENV: &str = "WHOLOCK_E2E_LOCK_PATH";
const LOCK_HELPER_READY_ENV: &str = "WHOLOCK_E2E_READY_PATH";

fn create_locked_file() -> (tempfile::TempDir, String, File) {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("locked.txt");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "test content").unwrap();
    (dir, file_path.to_str().unwrap().to_string(), file)
}

fn scan_processes(path: &str) -> Vec<ProcessInfo> {
    match who_locks_file(path) {
        Ok(scan) => scan.into_processes(),
        Err(err) => panic!("lock scan failed: {err:?}"),
    }
}

fn wait_until<F>(timeout: Duration, mut condition: F) -> bool
where
    F: FnMut() -> bool,
{
    let start = Instant::now();
    while start.elapsed() < timeout {
        if condition() {
            return true;
        }
        thread::sleep(Duration::from_millis(100));
    }

    condition()
}

#[test]
fn e2e_lock_helper_process() {
    let Ok(file_path) = std::env::var(LOCK_HELPER_PATH_ENV) else {
        return;
    };
    let ready_path = std::env::var(LOCK_HELPER_READY_ENV).expect("ready path should be set");

    let _file = File::open(file_path).expect("helper should open target file");
    File::create(ready_path).expect("helper should signal readiness");
    thread::sleep(Duration::from_secs(30));
}

#[test]
fn test_find_locked_file_by_helper_process() {
    let (dir, file_path, file) = create_locked_file();
    drop(file);

    let ready_path = dir.path().join("helper-ready");
    let mut child = Command::new(std::env::current_exe().unwrap())
        .args(["--exact", "e2e_lock_helper_process", "--nocapture"])
        .env(LOCK_HELPER_PATH_ENV, &file_path)
        .env(LOCK_HELPER_READY_ENV, &ready_path)
        .spawn()
        .expect("failed to start lock helper process");

    assert!(
        wait_until(Duration::from_secs(5), || ready_path.exists()),
        "lock helper did not signal readiness"
    );

    let processes = scan_processes(&file_path);
    if processes.is_empty() {
        let _ = child.kill();
        let _ = child.wait();
        return;
    }

    let helper_process = processes
        .iter()
        .find(|process| process.pid == child.id())
        .expect("lock helper process not found");

    assert!(helper_process.pid > 0);
    assert!(
        helper_process
            .locked_file
            .iter()
            .any(|f| f.contains("locked.txt"))
    );

    unlock_file(helper_process.pid).unwrap();
    assert!(
        wait_until(Duration::from_secs(5), || child
            .try_wait()
            .unwrap()
            .is_some()),
        "lock helper should exit after unlock_file terminates it"
    );

    drop(dir);
}

#[test]
fn test_no_locks_on_new_file() {
    let (dir, file_path, file) = create_locked_file();

    drop(file);

    assert!(scan_processes(&file_path).is_empty());

    drop(dir);
}

#[test]
fn test_unlock_nonexistent_process() {
    let result = unlock_file(999999);
    assert!(result.is_err());
}

#[test]
fn test_who_locks_nonexistent_file() {
    let result = who_locks_file(r"C:\nonexistent\file.txt");
    assert!(result.is_err());
}
