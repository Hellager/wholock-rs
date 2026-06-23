use std::env;
use wholock::{processes_to_json, unlock_processes, who_locks_file};

fn main() {
    env_logger::init();

    let mut args = env::args();
    let program = args.next().unwrap_or_else(|| "wholock".to_string());
    let mut file_path = None;
    let mut should_unlock = false;
    let mut json_output = false;

    for arg in args {
        match arg.as_str() {
            "--unlock" => should_unlock = true,
            "--json" => json_output = true,
            _ if file_path.is_none() => file_path = Some(arg),
            _ => {
                eprintln!("Unexpected argument: {arg}");
                eprintln!("Usage: {program} <file_path> [--unlock] [--json]");
                return;
            }
        }
    }

    let Some(file_path) = file_path else {
        println!("Usage: {program} <file_path> [--unlock] [--json]");
        return;
    };

    match who_locks_file(&file_path) {
        Ok(processes) => {
            if json_output {
                match processes_to_json(&processes) {
                    Ok(json) => println!("{json}"),
                    Err(e) => eprintln!("Error: {}", e),
                }
            } else if processes.is_empty() {
                println!("No process is locking the file: {}", file_path);
            } else {
                println!("\nProcesses locking the file {}:", file_path);
                println!("{:-<50}", "");

                for process in &processes {
                    println!("PID: {}", process.pid);
                    println!("Process Name: {}", process.process_name);
                    println!("Executable Path: {}", process.process_exe_path);
                    println!("Owner: {}", process.domain_username);
                    println!("Locked Files:");
                    for file in &process.locked_file {
                        println!("  - {}", file);
                    }
                    println!("{:-<50}", "");
                }
            }

            if should_unlock {
                for unlock in unlock_processes(&processes) {
                    let status = format!(
                        "Attempting to unlock by terminating process {}...",
                        unlock.pid
                    );
                    if json_output {
                        eprintln!("{status}");
                    } else {
                        println!("{status}");
                    }

                    match unlock.result {
                        Ok(_) if json_output => {
                            eprintln!("Successfully terminated process {}", unlock.pid)
                        }
                        Ok(_) => println!("Successfully terminated process {}", unlock.pid),
                        Err(e) => eprintln!("Failed to terminate process {}: {}", unlock.pid, e),
                    }
                }
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}
