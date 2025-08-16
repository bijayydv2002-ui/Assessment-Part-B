use std::io::{self, Write};

use safe_backup::{backup_file, delete_file, restore_file};

fn read_line(prompt: &str) -> io::Result<String> {
    print!("{}", prompt);
    io::stdout().flush()?;
    let mut buf = String::new();
    io::stdin().read_line(&mut buf)?;
    Ok(buf.trim().to_string())
}

fn main() {
    println!("== SafeBackup (Rust) ==");
    println!("Supported commands: backup, restore, delete");
    println!("Only text-like files are allowed: .txt, .log, .md");
    println!();

    let filename = match read_line("Please enter your file name: ") {
        Ok(s) => s,
        Err(e) => {
            eprintln!("Failed to read filename: {}", e);
            return;
        }
    };
    let command = match read_line("Please enter your command (backup, restore, delete): ") {
        Ok(s) => s.to_lowercase(),
        Err(e) => {
            eprintln!("Failed to read command: {}", e);
            return;
        }
    };

    let result = match command.as_str() {
        "backup" => {
            match backup_file(&filename) {
                Ok(path) => {
                    println!("Your backup created: {}", path.display());
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        "restore" => {
            match restore_file(&filename) {
                Ok(path) => {
                    println!("Your file restored from backup to: {}", path.display());
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        "delete" => {
            match delete_file(&filename) {
                Ok(()) => {
                    println!("File securely deleted.");
                    Ok(())
                }
                Err(e) => Err(e),
            }
        }
        _ => {
            eprintln!("Unknown command");
            return;
        }
    };

    if let Err(err) = result {
        eprintln!("Operation failed: {}", err);
    }
}
