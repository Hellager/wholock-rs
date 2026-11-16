use std::fs::{File, OpenOptions};
use std::io::Write;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, Command};
use std::thread;
use std::time::{Duration, Instant};
use tempfile::{TempDir, tempdir};
use wholock::{
    LockMatchSource, LockScanOptions, ProcessInfo, ProcessTerminationFailureKind, scan_locks,
    unlock_process, unlock_processes, who_locks_file,
};
use windows::Win32::Foundation::FreeLibrary;
use windows::Win32::Storage::FileSystem::{FILE_SHARE_DELETE, FILE_SHARE_READ, FILE_SHARE_WRITE};
use windows::Win32::System::LibraryLoader::LoadLibraryW;
use windows::core::PCWSTR;

const HELPER_MODE_ENV: &str = "WHOLOCK_E2E_MODE";
const HELPER_PATH_ENV: &str = "WHOLOCK_E2E_PATH";
const HELPER_READY_ENV: &str = "WHOLOCK_E2E_READY_PATH";
const HELPER_RELEASE_ENV: &str = "WHOLOCK_E2E_RELEASE_PATH";
const HELPER_MODE_FILE: &str = "file";
const HELPER_MODE_DELETE_PENDING: &str = "delete-pending";
const HELPER_MODE_MODULE: &str = "module";

struct HelperProcess {
    child: Child,
    release_path: PathBuf,
}

impl HelperProcess {
    fn spawn(mode: &str, target: &Path, dir: &Path) -> Self {
        let ready_path = dir.join(format!("helper-ready-{mode}"));
        let release_path = dir.join(format!("helper-release-{mode}"));
        let child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "e2e_lock_helper_process", "--nocapture"])
            .env(HELPER_MODE_ENV, mode)
            .env(HELPER_PATH_ENV, target)
            .env(HELPER_READY_ENV, &ready_path)
            .env(HELPER_RELEASE_ENV, &release_path)
            .spawn()
            .expect("failed to start lock helper process");
        let mut helper = Self {
            child,
            release_path,
        };

        if !wait_until(Duration::from_secs(5), || ready_path.exists()) {
            let _ = helper.child.kill();
            let _ = helper.child.wait();
            panic!("lock helper did not signal readiness for mode {mode}");
        }

        helper
    }

    fn id(&self) -> u32 {
        self.child.id()
    }

    fn release_and_wait(&mut self) {
        File::create(&self.release_path).expect("failed to release helper process");
        assert!(
            wait_until(Duration::from_secs(5), || self
                .child
                .try_wait()
                .expect("failed to query helper process")
                .is_some()),
            "lock helper should exit after release"
        );
    }
}

impl Drop for HelperProcess {
    fn drop(&mut self) {
        if self.child.try_wait().ok().flatten().is_none() {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
}

struct SubstDrive {
    drive: String,
}

impl SubstDrive {
    fn create(target: &Path) -> Option<Self> {
        for letter in (b'Q'..=b'Z').rev() {
            let drive = format!("{}:", char::from(letter));
            if Path::new(&format!(r"{drive}\")).exists() {
                continue;
            }

            let status = Command::new("subst")
                .arg(&drive)
                .arg(target)
                .status()
                .ok()?;
            if status.success() {
                return Some(Self { drive });
            }
        }

        None
    }

    fn path(&self, name: &str) -> PathBuf {
        PathBuf::from(format!(r"{}\{name}", self.drive))
    }
}

impl Drop for SubstDrive {
    fn drop(&mut self) {
        let _ = Command::new("subst").args([&self.drive, "/D"]).status();
    }
}

fn create_locked_file() -> (TempDir, PathBuf, File) {
    let dir = tempdir().unwrap();
    let file_path = dir.path().join("locked.txt");
    let mut file = File::create(&file_path).unwrap();
    writeln!(file, "test content").unwrap();
    (dir, file_path, file)
}

fn scan_processes(path: &Path) -> Vec<ProcessInfo> {
    match who_locks_file(path.to_str().unwrap()) {
        Ok(scan) => scan.into_processes(),
        Err(err) => panic!("lock scan failed: {err:?}"),
    }
}

fn scan_helper(path: &Path, pid: u32, include_modules: bool) -> ProcessInfo {
    let options = LockScanOptions::new().with_module_scan(include_modules);
    let scan = scan_locks([path.to_str().unwrap()], options)
        .unwrap_or_else(|err| panic!("lock scan failed for {}: {err:?}", path.display()));

    scan.processes()
        .iter()
        .find(|process| process.pid == pid)
        .cloned()
        .unwrap_or_else(|| {
            panic!(
                "helper PID {pid} was not found while scanning {}; warnings: {:?}",
                path.display(),
                scan.warnings()
            )
        })
}

fn assert_file_handle_match(path: &Path, pid: u32) {
    let process = scan_helper(path, pid, false);
    assert!(
        process
            .matches
            .iter()
            .any(|lock_match| lock_match.source == LockMatchSource::FileHandle)
    );
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
        thread::sleep(Duration::from_millis(50));
    }

    condition()
}

fn wait_for_release(path: &Path) {
    assert!(
        wait_until(Duration::from_secs(30), || path.exists()),
        "helper release marker was not created"
    );
}

fn loopback_unc_path(path: &Path) -> Option<PathBuf> {
    let path = path.canonicalize().ok()?;
    let path = path.to_str()?;
    let bytes = path.as_bytes();
    if bytes.len() < 3 || bytes[1] != b':' || bytes[2] != b'\\' {
        return None;
    }

    Some(PathBuf::from(format!(
        r"\\localhost\{}$\{}",
        char::from(bytes[0]),
        &path[3..]
    )))
}

fn create_junction(link: &Path, target: &Path) -> bool {
    Command::new("cmd")
        .args(["/C", "mklink", "/J"])
        .arg(link)
        .arg(target)
        .output()
        .is_ok_and(|output| output.status.success())
}

#[test]
fn e2e_lock_helper_process() {
    let Ok(mode) = std::env::var(HELPER_MODE_ENV) else {
        return;
    };
    let target = PathBuf::from(std::env::var_os(HELPER_PATH_ENV).expect("target path missing"));
    let ready = PathBuf::from(std::env::var_os(HELPER_READY_ENV).expect("ready path missing"));
    let release =
        PathBuf::from(std::env::var_os(HELPER_RELEASE_ENV).expect("release path missing"));

    match mode.as_str() {
        HELPER_MODE_FILE => {
            let _file = File::open(target).expect("helper should open target file");
            File::create(ready).expect("helper should signal readiness");
            wait_for_release(&release);
        }
        HELPER_MODE_DELETE_PENDING => {
            let _file = OpenOptions::new()
                .read(true)
                .share_mode((FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE).0)
                .open(target)
                .expect("helper should open delete-shared target file");
            File::create(ready).expect("helper should signal readiness");
            wait_for_release(&release);
        }
        HELPER_MODE_MODULE => {
            let target = target
                .as_os_str()
                .encode_wide()
                .chain(std::iter::once(0))
                .collect::<Vec<_>>();
            // SAFETY: `target` is a null-terminated UTF-16 path that remains alive
            // for the duration of the call. The returned module is freed below.
            let module = unsafe { LoadLibraryW(PCWSTR(target.as_ptr())) }
                .expect("helper should load target module");
            File::create(ready).expect("helper should signal readiness");
            wait_for_release(&release);
            // SAFETY: `module` is the live HMODULE returned by LoadLibraryW above
            // and is released exactly once before the helper exits.
            unsafe { FreeLibrary(module) }.expect("helper should free target module");
        }
        _ => panic!("unsupported helper mode: {mode}"),
    }
}

#[test]
fn test_find_locked_file_by_helper_process() {
    let (dir, file_path, file) = create_locked_file();
    drop(file);
    let mut helper = HelperProcess::spawn(HELPER_MODE_FILE, &file_path, dir.path());

    let helper_process = scan_helper(&file_path, helper.id(), false);
    assert!(helper_process.pid > 0);
    assert!(
        helper_process
            .locked_file
            .iter()
            .any(|path| path.contains("locked.txt"))
    );
    assert!(helper_process.matches.iter().any(|lock_match| {
        lock_match.path.contains("locked.txt") && lock_match.source == LockMatchSource::FileHandle
    }));

    let unlock_results = unlock_processes(std::slice::from_ref(&helper_process));
    assert_eq!(unlock_results.len(), 1);
    assert!(
        unlock_results[0].is_success(),
        "checked unlock failed: {:?}",
        unlock_results[0].failure
    );
    assert!(
        wait_until(Duration::from_secs(5), || helper
            .child
            .try_wait()
            .unwrap()
            .is_some()),
        "lock helper should exit after checked termination"
    );
}

#[test]
fn test_real_long_file_and_directory_paths() {
    let dir = tempdir().unwrap();
    let component = "nested-segment-".to_string() + &"x".repeat(75);
    let long_dir = dir
        .path()
        .join(format!("{component}-a"))
        .join(format!("{component}-b"))
        .join(format!("{component}-c"));
    std::fs::create_dir_all(&long_dir).expect("failed to create long directory path");
    let long_file = long_dir.join(format!("locked-{}.txt", "y".repeat(80)));
    File::create(&long_file).expect("failed to create long file path");
    assert!(long_dir.as_os_str().encode_wide().count() > 260);
    assert!(long_file.as_os_str().encode_wide().count() > 260);

    let helper = HelperProcess::spawn(HELPER_MODE_FILE, &long_file, dir.path());
    assert_file_handle_match(&long_file, helper.id());
    assert_file_handle_match(&long_dir, helper.id());
}

#[test]
fn test_path_aliases_find_same_lock_holder() {
    let (dir, file_path, file) = create_locked_file();
    drop(file);
    let helper = HelperProcess::spawn(HELPER_MODE_FILE, &file_path, dir.path());

    let hard_link = dir.path().join("hard-link.txt");
    std::fs::hard_link(&file_path, &hard_link).expect("failed to create hard link");
    assert_file_handle_match(&hard_link, helper.id());

    let junction = dir.path().join("junction");
    let junction_target = dir.path().join("junction-target");
    std::fs::create_dir(&junction_target).unwrap();
    let junction_file = junction_target.join("locked.txt");
    std::fs::hard_link(&file_path, &junction_file).unwrap();
    if create_junction(&junction, &junction_target) {
        assert_file_handle_match(&junction.join("locked.txt"), helper.id());
    } else {
        eprintln!("skipping junction assertion: mklink /J is unavailable");
    }

    let symbolic_link = dir.path().join("symbolic-link.txt");
    match std::os::windows::fs::symlink_file(&file_path, &symbolic_link) {
        Ok(()) => assert_file_handle_match(&symbolic_link, helper.id()),
        Err(err) => eprintln!("skipping symbolic-link assertion: {err}"),
    }

    if let Some(mapped_drive) = SubstDrive::create(dir.path()) {
        assert_file_handle_match(&mapped_drive.path("locked.txt"), helper.id());
    } else {
        eprintln!("skipping mapped-drive assertion: no subst drive was available");
    }

    if let Some(unc_path) = loopback_unc_path(&file_path) {
        if unc_path.exists() {
            assert_file_handle_match(&unc_path, helper.id());
        } else {
            eprintln!("skipping UNC assertion: loopback administrative share is unavailable");
        }
    }
}

#[test]
fn test_delete_pending_file_does_not_stall_parent_scan() {
    let (dir, file_path, file) = create_locked_file();
    drop(file);
    let helper = HelperProcess::spawn(HELPER_MODE_DELETE_PENDING, &file_path, dir.path());
    assert_file_handle_match(&file_path, helper.id());

    std::fs::remove_file(&file_path).expect("failed to mark locked file for deletion");
    assert!(!file_path.exists());

    let start = Instant::now();
    let scan = scan_locks(
        [dir.path().to_str().unwrap()],
        LockScanOptions::new()
            .disable_module_scan()
            .with_handle_probe_timeout(Duration::from_millis(200)),
    )
    .expect("delete-pending scan should return diagnostics");

    assert!(start.elapsed() < Duration::from_secs(5));
    assert!(
        !scan
            .processes()
            .iter()
            .any(|process| process.pid == helper.id())
    );
}

#[test]
fn test_loaded_module_without_file_handle_is_reported() {
    let dir = tempdir().unwrap();
    let system_root = std::env::var_os("SystemRoot").expect("SystemRoot should be defined");
    let source = PathBuf::from(system_root)
        .join("System32")
        .join("version.dll");
    let module_path = dir.path().join("module-only.dll");
    std::fs::copy(source, &module_path).expect("failed to copy test DLL");
    let helper = HelperProcess::spawn(HELPER_MODE_MODULE, &module_path, dir.path());

    let process = scan_helper(&module_path, helper.id(), true);
    assert!(
        process
            .matches
            .iter()
            .any(|lock_match| lock_match.source == LockMatchSource::ProcessModule)
    );
    assert!(
        !process
            .matches
            .iter()
            .any(|lock_match| lock_match.source == LockMatchSource::FileHandle)
    );
}

#[test]
fn test_stale_scan_is_rejected_after_process_exit() {
    let (dir, file_path, file) = create_locked_file();
    drop(file);
    let mut helper = HelperProcess::spawn(HELPER_MODE_FILE, &file_path, dir.path());
    let snapshot = scan_helper(&file_path, helper.id(), false);

    helper.release_and_wait();
    let results = unlock_processes(&[snapshot]);

    assert_eq!(results.len(), 1);
    assert_eq!(
        results[0].failure.as_ref().map(|failure| failure.kind),
        Some(ProcessTerminationFailureKind::InvalidPid)
    );
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
    let result = unlock_process(999_999);
    assert!(result.is_err());
}

#[test]
fn test_who_locks_nonexistent_file() {
    let result = who_locks_file(r"C:\nonexistent\file.txt");
    assert!(result.is_err());
}
