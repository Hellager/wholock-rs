use std::env;
use wholock::{unlock_file, who_locks_file};

fn main() {
    env_logger::init();

    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        println!("Usage: {} <file_path> [--unlock]", args[0]);
        return;
    }

    let file_path = &args[1];
    let should_unlock = args.get(2).map_or(false, |arg| arg == "--unlock");

    match who_locks_file(file_path) {
        Ok(processes) => {
            if processes.is_empty() {
                println!("No process is locking the file: {}", file_path);
                return;
            }

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

                if should_unlock {
                    println!(
                        "Attempting to unlock by terminating process {}...",
                        process.pid
                    );
                    match unlock_file(process.pid) {
                        Ok(_) => println!("Successfully terminated process {}", process.pid),
                        Err(e) => eprintln!("Failed to terminate process {}: {}", process.pid, e),
                    }
                }
            }
        }
        Err(e) => eprintln!("Error: {}", e),
    }
}
