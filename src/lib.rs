//! # wholock
//!
//! `wholock` is a Windows file lock diagnostics library for finding processes
//! that keep files or directories open, reporting partial scan warnings, and
//! safely terminating verified lock holders when requested.
//!
//! ## Key Features
//!
//! ### Core Operations
//! - Scan one or more files for locking processes
//! - Match directory inputs recursively
//! - Return process identity, owner, executable path, and matching locked paths
//! - Wait until matching locks disappear
//!
//! ### Advanced Management
//! - Best-effort scans with structured warnings
//! - Optional strict debug privilege requirements through [`LockScanOptions`]
//! - Checked process termination through [`unlock_processes`]
//!
//! ### System Integration
//! - Windows handle table and process module inspection
//! - Elevation and debug privilege helpers
//! - RAII cleanup for native Windows handles used internally
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use wholock::{LockScanOptions, WholockResult, scan_locks};
//!
//! fn main() -> WholockResult<()> {
//!     let scan = scan_locks(["C:\\path\\to\\file.txt"], LockScanOptions::new())?;
//!
//!     for process in scan.processes() {
//!         println!("PID {}: {}", process.pid, process.process_name);
//!         for path in &process.locked_file {
//!             println!("  - {}", path);
//!         }
//!     }
//!
//!     if !scan.is_complete_success() {
//!         eprintln!("scan completed with {} warning(s)", scan.warnings().len());
//!     }
//!
//!     Ok(())
//! }
//! ```
//!
//! ## Implementation Details
//!
//! - Uses Windows NT handle enumeration and process module inspection
//! - Protects potentially blocking handle probes with caller-configurable timeouts
//! - Preserves recoverable scan failures as [`error::LockScanWarning`] values
//!
//! ## Safety and Reliability
//!
//! - Validates input paths before scanning
//! - Closes native handles through internal RAII guards
//! - Revalidates process identity and lock state before checked termination
//!
//! ## Best Practices
//!
//! - Inspect [`LockScanResult::warnings`] before treating empty results as authoritative
//! - Use [`LockScanOptions::require_debug_privilege`] only when partial results are unacceptable
//! - Prefer [`unlock_processes`] with scan results over terminating arbitrary PIDs
//!
mod elevation;
pub mod error;
mod interop;
mod scan;
mod types;
mod unlock;
mod wait;

use crate::error::WholockError;

/// Result type returned by wholock APIs.
///
/// This is a crate-wide alias for `Result<T, WholockError>`.
pub type WholockResult<T> = Result<T, WholockError>;

pub use elevation::{
    enable_debug_privilege, is_process_elevated, restart_as_elevated, start_as_elevated,
};
pub use scan::{find_processes_recursive, scan_locks, who_locks_file, who_locks_files};
pub use types::{
    LockScanOptions, LockScanResult, ProcessInfo, ProcessTerminationFailure,
    ProcessTerminationFailureKind, UnlockProcessResult, WaitForUnlockResult,
};
pub use unlock::{unlock_file, unlock_processes};
pub use wait::{wait_for_unlock, wait_for_unlock_files};
