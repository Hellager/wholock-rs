//! # wholock
//!
//! `wholock` is a Windows file lock diagnostics library for finding processes that keep files or
//! directories open, reporting partial scan warnings, and safely terminating verified lock holders
//! when requested.
//!
//! ## Key Features
//!
//! ### Core Operations
//! - Identify processes locking one file with [`who_locks_file`]
//! - Scan one or more files or directories with [`scan_locks`]
//! - Return process identity, owner, executable path, and matching locked paths
//! - Wait until matching locks disappear
//!
//! ### Advanced Management
//! - Best-effort scans with structured warnings
//! - Optional strict debug privilege requirements with [`LockScanOptions`]
//! - Checked process termination through [`unlock_process`] and [`unlock_processes`]
//!
//! ### System Integration
//! - Windows handle table and process module inspection
//! - Elevation and debug privilege helpers
//! - RAII cleanup for native Windows handles used internally
//!
//! ## Quick Start
//!
//! ```rust,no_run
//! use wholock::{WholockResult, unlock_processes, who_locks_file};
//!
//! fn main() -> WholockResult<()> {
//!     let scan = who_locks_file("C:\\path\\to\\file.txt")?;
//!
//!     for process in scan.processes() {
//!         println!("PID {}: {}", process.pid, process.process_name);
//!         for path in &process.locked_file {
//!             println!("  - {}", path);
//!         }
//!     }
//!
//!     for result in unlock_processes(scan.processes()) {
//!         if result.is_success() {
//!             println!("terminated PID {}", result.pid);
//!         } else if let Some(reason) = result.failure_reason() {
//!             eprintln!("failed to terminate PID {}: {}", result.pid, reason);
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
//! ## Advanced Usage
//!
//! Use [`scan_locks`] when you need to scan multiple paths or tune scan behavior.
//!
//! ```rust,no_run
//! use std::time::Duration;
//! use wholock::{LockScanOptions, WholockResult, scan_locks, unlock_processes};
//!
//! fn main() -> WholockResult<()> {
//!     let options = LockScanOptions::new()
//!         .with_handle_probe_timeout(Duration::from_millis(500))
//!         .require_debug_privilege();
//!
//!     let scan = scan_locks(["C:\\work", "C:\\data\\database.lock"], options)?;
//!
//!     for warning in scan.warnings() {
//!         eprintln!("{} warning: {}", warning.kind(), warning.message());
//!     }
//!
//!     for result in unlock_processes(scan.processes()) {
//!         if !result.is_success() {
//!             eprintln!(
//!                 "failed to terminate PID {}: {}",
//!                 result.pid,
//!                 result.failure_reason().unwrap_or("unknown failure")
//!             );
//!         }
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
//! - Start with [`who_locks_file`] for simple single-path queries
//! - Use [`scan_locks`] when scanning multiple paths or customizing [`LockScanOptions`]
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

pub use elevation::{enable_debug_privilege, is_process_elevated};
pub use scan::{scan_locks, who_locks_file};
pub use types::{
    LockScanOptions, LockScanResult, ProcessInfo, ProcessTerminationFailure,
    ProcessTerminationFailureKind, UnlockProcessResult, WaitForUnlockResult,
};
pub use unlock::{unlock_process, unlock_processes};
pub use wait::{wait_for_unlock, wait_for_unlock_files};
