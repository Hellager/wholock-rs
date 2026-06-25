# Changelog

All notable changes to this project will be documented in this file.

## [0.1.1] - 2026-06-25

### Added

- Added structured lock scan results with recoverable scan warnings.
- Added configurable lock scanning through `LockScanOptions`.
- Added crate-level documentation and updated README usage examples.
- Added release workflow support for manual dispatch and draft source releases.

### Changed

- Consolidated the public API around `who_locks_file`, `scan_locks`, `wait_for_unlock`,
  `wait_for_unlock_files`, `unlock_process`, `unlock_processes`, `is_process_elevated`, and
  `enable_debug_privilege`.
- Changed default scanning to best-effort behavior when debug privilege is unavailable.
- Renamed the PID-based unlock API from `unlock_file` to `unlock_process`.
- Updated README examples to show querying locks before unlocking with `unlock_processes`.
- Simplified dependencies and removed JSON output support from the public API.
- Aligned release workflows with the wincent-rs workflow structure.

### Fixed

- Prevented timed-out handle probes from using process handles after ownership is released.
- Strengthened process termination checks to reduce PID reuse and protected-process risks.
- Preserved partial scan context through warnings instead of silently returning incomplete results.
- Replaced FFI buffer assertions with structured errors.
- Validated invalid, empty, and missing path inputs instead of hiding user errors.
- Added `SAFETY` comments for unsafe FFI blocks.

### Removed

- Removed `who_locks_files` and `find_processes_recursive` in favor of `scan_locks`.
- Removed `start_as_elevated` and `restart_as_elevated` from the public API.
- Removed JSON serialization helpers and the related `serde` dependencies.
