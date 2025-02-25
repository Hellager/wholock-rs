# Wholock-rs

Read this in other languages: [English](README.md) | [中文](README.zh-CN.md)

## Overview

Windows file locking diagnostics toolkit with surgical precision. Identify processes locking files and safely release resources. 

This is basically a Rust implementation of [File Locksmith](https://github.com/microsoft/PowerToys?tab=readme-ov-file) and for now its in a very early version. 

## Features ✨

- 🔍 **Deep Handle Inspection** - Enumerate system handles with NTAPI
- 🎯 **Precise PID Targeting** - Map handles to exact process IDs
- 🔓 **Controlled Unlocking** - Graceful termination with safety checks
- 📂 **Path Normalization** - Handle Win32 device path conversions
- 🛡️ **Safe FFI Wrapping** - RAII guards for Windows handles

## Installation ⚙️

Add to `Cargo.toml`:

```toml
[dependencies]
wholock = "0.0.1"
```

*Requires Windows 10+ and Rust 1.70+*

## Usage Guide 🚀

### Basic Lock Detection

```rust
use wholock::{who_locks_file, WholockError};

fn main() -> Result<(), WholockError> {
    let target = r"C:\critical\database.lock";
  
    let processes = who_locks_file(target)?;
  
    processes.iter().for_each(|p| {
        println!("🔒 Process {} (PID: {}) locks:", p.process_name, p.pid);
        p.locked_file.iter().for_each(|f| println!("   - {}", f));
    });
  
    Ok(())
}
```

### Safe Process Termination

```rust
use wholock::{unlock_file, WholockError};

fn release_lock(pid: u32) -> Result<(), WholockError> {
    match unlock_file(pid) {
        Ok(_) => println!("✅ Successfully terminated PID {}", pid),
        Err(e) => eprintln!("❌ Error terminating process: {}", e),
    }
    Ok(())
}
```

### Advanced Monitoring

```rust
use wholock::ProcessInfo;
use tokio::time::{interval, Duration};

async fn monitor_locks(path: &str) -> wholock::WholockResult<()> {
    let mut interval = interval(Duration::from_secs(30));
  
    loop {
        interval.tick().await;
        let locks = who_locks_file(path)?;
      
        if !locks.is_empty() {
            send_alert(&locks).await?;
        }
    }
}

async fn send_alert(processes: &[ProcessInfo]) -> wholock::WholockResult<()> {
    // Implement custom notification logic
    Ok(())
}
```

## Security Notes 🔐

### Critical Requirements
- 🛑 **Admin Privileges** Required for handle duplication
- ⚠️ **Handle Validation** - Anti-DLL injection protections
- 🔄 **Cleanup Guarantees** - RAII pattern for system handles

### System Compatibility
| Component       | Requirement              |
|-----------------|--------------------------|
| OS Version      | Windows 10+             |
| Rust Toolchain  | 1.70+ (MSRV)            |
| Security Policy | SeDebugPrivilege enabled|

## Contribution 👥

### Development Workflow

```bash
# Clone with submodules
git clone --recurse-submodules https://github.com/Hellager/wholock-rs.git

# Build with Windows SDK
cargo build --features=win32

# Run tests (admin required)
cargo test -- --test-threads=1
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