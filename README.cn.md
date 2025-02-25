# Wholock-rs

其他语言版本: [English](README.md) | [中文](README.cn.md)

## 概述

Windows 文件锁定诊断工具包，精准识别锁定文件的进程并安全释放资源。

本项目是 [File Locksmith](https://github.com/microsoft/PowerToys?tab=readme-ov-file) 的 Rust 实现，当前处于早期开发阶段。

## 功能特性 ✨

- 🔍 **深度句柄探查** - 通过 NTAPI 枚举系统句柄
- 🎯 **精准 PID 定位** - 将句柄映射到具体进程 ID
- 🔓 **安全解锁控制** - 带安全检查的优雅终止
- 📂 **路径标准化** - 处理 Win32 设备路径转换
- 🛡️ **安全 FFI 封装** - Windows 句柄的 RAII 守卫

## 安装指南 ⚙️

在 `Cargo.toml` 中添加：

```toml
[dependencies]
wholock = "0.0.1"
```

*要求 Windows 10+ 和 Rust 1.70+*

## 使用指南 🚀

### 基础锁检测

```rust
use wholock::{who_locks_file, WholockError};

fn main() -> Result<(), WholockError> {
    let target = r"C:\critical\database.lock";

    let processes = who_locks_file(target)?;

    processes.iter().for_each(|p| {
        println!("🔒 进程 {} (PID: {}) 锁定文件:", p.process_name, p.pid);
        p.locked_file.iter().for_each(|f| println!("   - {}", f));
    });

    Ok(())
}
```

### 安全进程终止

```rust
use wholock::{unlock_file, WholockError};

fn release_lock(pid: u32) -> Result<(), WholockError> {
    match unlock_file(pid) {
        Ok(_) => println!("✅ 成功终止进程 PID {}", pid),
        Err(e) => eprintln!("❌ 进程终止错误: {}", e),
    }
    Ok(())
}
```

### 高级监控

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
    // 实现自定义通知逻辑
    Ok(())
}
```

## 安全说明 🔐

### 关键要求
- 🛑 **需要管理员权限** 用于句柄复制
- ⚠️ **句柄验证** - 反DLL注入保护
- 🔄 **资源清理保证** - 系统句柄的RAII模式

### 系统兼容性
| 组件           | 要求                  |
|-----------------|-----------------------|
| 操作系统版本    | Windows 10+          |
| Rust 工具链     | 1.70+ (最低支持版本) |
| 安全策略        | 启用 SeDebugPrivilege|

## 贡献指南 👥

### 开发流程

```bash
# 克隆仓库（含子模块）
git clone --recurse-submodules https://github.com/Hellager/wholock-rs.git

# 使用 Windows SDK 构建
cargo build --features=win32

# 运行测试（需管理员权限）
cargo test -- --test-threads=1
```

### 代码规范
- 分支命名: `feat/[功能名称]` / `fix/[问题编号]`
- 提交信息: 遵循约定式提交规范
- 文档要求: 100% API 覆盖率

## 支持与排障

提交 GitHub Issue 时请包含：
1. 完整错误信息
2. Windows 构建版本 (`winver`)
3. 问题复现步骤
4. 安全上下文详情

## 特别感谢

- [@PolarGoose](https://github.com/PolarGoose/ShowWhatProcessLocksFile)
- [@PowerToys](https://github.com/microsoft/PowerToys)

## 许可证 📜

根据 [LICENSE-MIT](LICENSE-MIT) 许可证分发。有关更多信息，请参见 LICENSE。

## 作者

由 @Hellager 使用 🦀 Rust 精心打造
