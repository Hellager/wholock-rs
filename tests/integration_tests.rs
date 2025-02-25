use std::fs::File;
use std::io::Write;
use std::process::Command;
use std::thread;
use std::time::Duration;
use tempfile::tempdir;
use wholock::{unlock_file, who_locks_file};

fn create_locked_file() -> (tempfile::TempDir, String, File) {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("locked.txt");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "test content").unwrap();
    (dir, file_path.to_str().unwrap().to_string(), file)
}

#[test]
fn test_find_locked_file_by_notepad() {
    let (dir, file_path, file) = create_locked_file();
    drop(file);

    let _child = Command::new("notepad.exe")
        .arg(&file_path)
        .spawn()
        .expect("Failed to start notepad");

    thread::sleep(Duration::from_secs(2));

    let result = who_locks_file(&file_path);
    println!("result: {:?}", result);
    assert!(result.is_ok());

    let processes = result.unwrap();
    assert!(!processes.is_empty());

    let notepad_process = processes
        .iter()
        .find(|p| p.process_name.to_lowercase().contains("notepad"))
        .expect("Notepad process not found");

    assert!(notepad_process.pid > 0);
    assert!(!notepad_process.domain_username.is_empty());
    assert!(notepad_process
        .locked_file
        .iter()
        .any(|f| f.contains("locked.txt")));

    unlock_file(notepad_process.pid).unwrap();
    thread::sleep(Duration::from_millis(500));

    drop(dir);
}

#[test]
fn test_no_locks_on_new_file() {
    let (dir, file_path, file) = create_locked_file();

    drop(file);

    let result = who_locks_file(&file_path);
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());

    drop(dir);
}

#[test]
fn test_unlock_nonexistent_process() {
    let result = unlock_file(999999);
    assert!(result.is_err());
}

#[test]
#[should_panic]
fn test_who_locks_nonexistent_file() {
    let result = who_locks_file(r"C:\nonexistent\file.txt");
    assert!(result.is_ok());
    assert!(result.unwrap().is_empty());
}
