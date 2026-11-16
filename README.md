# Wholock-rs

[![](https://img.shields.io/crates/v/wholock.svg)](https://crates.io/crates/wholock)
[![][img_doc]][doc]
![Crates.io Total Downloads](https://img.shields.io/crates/d/wholock)
![GitHub Actions Workflow Status](https://img.shields.io/github/actions/workflow/status/Hellager/wholock-rs/publish.yml)
![Crates.io License](https://img.shields.io/crates/l/wholock)

Read this in other languages: [English](README.md) | [中文](README.cn.md)

## Overview

Windows file locking diagnostics toolkit with surgical precision. Identify processes locking files
and terminate verified lock holders when requested.

Inspired by PowerToys [File Locksmith](https://github.com/microsoft/PowerToys?tab=readme-ov-file),
`wholock` provides a focused Rust library API for lock discovery and controlled unlocking.

## Features ✨

- 🔍 **Deep Handle Inspection** - Enumerate system handles with NTAPI
- 🎯 **Precise PID Targeting** - Map handles to exact process IDs
- 🔓 **Controlled Unlocking** - Checked termination with safety checks
- 📂 **Path Normalization** - Handle Win32 device path conversions
- 🛡️ **Safe FFI Wrapping** - RAII guards for Windows handles

## Installation ⚙️

Add to `Cargo.toml`:

```toml
[dependencies]
wholock = "0.1.1"
```

*Requires Windows 10+ and Rust 1.85+*

## Usage Guide 🚀

### Basic Lock Detection and Unlocking

Use `who_locks_file` for the common case: one path, default best-effort scanning. Pass the scan
result to `unlock_processes` when you want wholock to revalidate the lock holders before
termination.

```rust
use wholock::{unlock_processes, who_locks_file, WholockResult};

fn main() -> WholockResult<()> {
    let target = r"C:\critical\database.lock";
  
    let scan = who_locks_file(target)?;
  
    scan.processes().iter().for_each(|p| {
        println!("🔒 Process {} (PID: {}) locks:", p.process_name, p.pid);
        p.locked_file.iter().for_each(|f| println!("   - {}", f));
    });

    for result in unlock_processes(scan.processes()) {
        if result.is_success() {
            println!("✅ Successfully terminated PID {}", result.pid);
        } else if let Some(reason) = result.failure_reason() {
            eprintln!("❌ Failed to terminate PID {}: {}", result.pid, reason);
        }
    }
  
    Ok(())
}
```

### Advanced Usage

Use `scan_locks` when you need to scan multiple paths or customize scan behavior.

```rust
use std::time::Duration;
use wholock::{scan_locks, unlock_processes, LockScanOptions, WholockResult};

fn main() -> WholockResult<()> {
    let options = LockScanOptions::new()
        .with_handle_probe_timeout(Duration::from_millis(500))
        .require_debug_privilege();

    let scan = scan_locks([r"C:\work", r"C:\data\database.lock"], options)?;

    for process in scan.processes() {
        println!("Process {} (PID: {}) locks:", process.process_name, process.pid);
        for file in &process.locked_file {
            println!("   - {}", file);
        }
    }

    for warning in scan.warnings() {
        eprintln!("{warning}");
    }

    for result in unlock_processes(scan.processes()) {
        if result.is_success() {
            println!("✅ Successfully terminated PID {}", result.pid);
        } else if let Some(reason) = result.failure_reason() {
            eprintln!("❌ Failed to terminate PID {}: {}", result.pid, reason);
        }
    }

    Ok(())
}
```

## Security Notes 🔐

### Critical Requirements
- 🛑 **Elevation Optional** - Administrator/debug privilege improves scan completeness
- ⚠️ **Handle Validation** - Handle type checks before path probing
- 🔄 **Cleanup Guarantees** - RAII pattern for system handles

### System Compatibility
| Component       | Requirement              |
|-----------------|--------------------------|
| OS Version      | Windows 10+             |
| Rust Toolchain  | 1.85+ (MSRV)            |
| Security Policy | SeDebugPrivilege optional for fuller visibility |

## Contribution 👥

### Development Workflow

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/Hellager/wholock-rs.git

# Build
cargo build

# Run tests
cargo test
```

### Code Standards
- Branch naming: `feat/[feature-name]` / `fix/[issue-number]`
- Commit messages: Follow Conventional Commits
- Documentation: 100% API coverage required

## Support & Troubleshooting

For urgent issues, create a GitHub Issue with:
1. Exact error message
2. Windows build number (`winver`)
3. Reproduction steps
4. Security context details

## Thanks

- [@PolarGoose](https://github.com/PolarGoose/ShowWhatProcessLocksFile)
- [@PowerToys](https://github.com/microsoft/PowerToys)

## License 📜

Distributed under the [LICENSE-MIT](LICENSE-MIT) License. See LICENSE for more information.

## Author

Developed with 🦀 by @Hellager

[img_doc]: https://img.shields.io/badge/doc-latest-orange
[doc]: https://docs.rs/wholock/latest/wholock/
