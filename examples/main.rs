use std::env;
use std::time::Duration;
use wholock::{unlock_processes, wait_for_unlock, who_locks_file};

fn main() {
    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "wholock".to_string());
    let mut file_path = None;
    let mut should_unlock = false;
    let mut wait = false;
    let mut wait_timeout = None;
    let mut args = args.peekable();

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--unlock" => should_unlock = true,
            "--wait" => {
                wait = true;
                if let Some(next) = args.peek() {
                    if !next.starts_with("--") {
                        let timeout = args.next().unwrap();
                        match timeout.parse::<u64>() {
                            Ok(seconds) => wait_timeout = Some(Duration::from_secs(seconds)),
                            Err(_) => {
                                eprintln!("Invalid --wait timeout: {timeout}");
                                return;
                            }
                        }
                    }
                }
            }
            "--timeout" => {
                let Some(timeout) = args.next() else {
                    eprintln!("Missing value for --timeout");
                    return;
                };
                match timeout.parse::<u64>() {
                    Ok(seconds) => wait_timeout = Some(Duration::from_secs(seconds)),
                    Err(_) => {
                        eprintln!("Invalid --timeout value: {timeout}");
                        return;
                    }
                }
            }
            _ if file_path.is_none() => file_path = Some(arg),
            _ => {
                eprintln!("Unexpected argument: {arg}");
                eprintln!("Usage: {program} <file_path> [--unlock] [--wait [seconds]]");
                return;
            }
        }
    }

    let Some(file_path) = file_path else {
        println!("Usage: {program} <file_path> [--unlock] [--wait [seconds]]");
        return;
    };

    if wait {
        println!("Waiting for files to be unlocked...");
        match wait_for_unlock(&file_path, wait_timeout) {
            Ok(result) if result.unlocked => {
                println!("Files unlocked after {:.2}s", result.elapsed.as_secs_f64());
            }
            Ok(result) => {
                if result.is_inconclusive() {
                    eprintln!(
                        "Timed out after {:.2}s; scan warnings prevented unlock confirmation",
                        result.elapsed.as_secs_f64()
                    );
                } else {
                    eprintln!(
                        "Timed out after {:.2}s; {} process(es) still locking the file",
                        result.elapsed.as_secs_f64(),
                        result.remaining_locks.len()
                    );
                }
                std::process::exit(1);
            }
            Err(e) => {
                eprintln!("Error: {}", e);
                std::process::exit(1);
            }
        }
        return;
    }

    match who_locks_file(&file_path) {
        Ok(scan) => {
            if scan.processes().is_empty() {
                println!("No process is locking the file: {}", file_path);
            } else {
                println!("\nProcesses locking the file {}:", file_path);
                println!("{:-<50}", "");

                for process in scan.processes() {
                    println!("PID: {}", process.pid);
                    println!("Process Name: {}", process.process_name);
                    println!("Executable Path: {}", process.process_exe_path);
                    println!("Owner: {}", process.domain_username);
                    println!("Matches:");
                    for lock_match in &process.matches {
                        println!("  - {} ({})", lock_match.path, lock_match.source);
                    }
                    println!("{:-<50}", "");
                }
            }

            for warning in scan.warnings() {
                eprintln!("Warning: {warning}");
            }

            if should_unlock {
                for unlock in unlock_processes(scan.processes()) {
                    let status = format!(
                        "Attempting to unlock by terminating process {}...",
                        unlock.pid
                    );
                    println!("{status}");

                    match unlock.result {
                        Ok(_) => println!("Successfully terminated process {}", unlock.pid),
                        Err(e) => {
                            if let Some(failure) = &unlock.failure {
                                eprintln!(
                                    "Failed to terminate process {} ({:?}): {}",
                                    unlock.pid, failure.kind, failure.reason
                                );
                            } else {
                                eprintln!("Failed to terminate process {}: {}", unlock.pid, e);
                            }
                        }
                    }
                }
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}
