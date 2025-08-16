//! Library for secure file backup, restore, and delete operations.
//! Follows secure coding practices: strong input validation, clear Result-based errors,
//! safe file operations with atomic writes, and append-only logging.

use anyhow::{Context, Result};
use chrono::Utc;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};

/// Allowed filename pattern: ASCII letters, digits, underscore, hyphen, and dot.
/// No path separators, no traversal tokens, length <= 255, not empty.
pub fn sanitize_filename(input: &str) -> Result<String> {
    if input.is_empty() {
        anyhow::bail!("filename is empty")
    }
    if input.len() > 255 {
        anyhow::bail!("filename too long")
    }
    if input.contains('/') || input.contains('\\') {
        anyhow::bail!("path separators are not allowed")
    }
    if input.contains("..") {
        anyhow::bail!("traversal tokens are not allowed")
    }
    if !input
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'_' || b == b'-')
    {
        anyhow::bail!("filename contains invalid characters")
    }
    // Optional: allow only .txt or .log and .md for safety. Adjust if needed.
    let allowed_exts = ["txt", "log", "md"];
    if let Some(ext) = Path::new(input).extension().and_then(|s| s.to_str()) {
        if !allowed_exts.contains(&ext) {
            anyhow::bail!("only .txt, .log, or .md files are allowed in this tool")
        }
    } else {
        anyhow::bail!("file must have an extension")
    }
    Ok(input.to_string())
}

fn cwd() -> Result<PathBuf> {
    std::env::current_dir().context("cannot read current directory")
}

fn within_cwd(p: &Path) -> Result<()> {
    let base = cwd()?.canonicalize().context("canonicalize base dir failed")?;
    let parent = p.parent().unwrap_or_else(|| Path::new("."));
    let parent = base.join(parent);
    let candidate = parent.join(
        p.file_name()
            .ok_or_else(|| anyhow::anyhow!("invalid filename"))?,
    );
    // We avoided separators already, so this should be inside base.
    if !candidate.starts_with(&base) {
        anyhow::bail!("path escapes working directory")
    }
    Ok(())
}

fn logfile_path() -> Result<PathBuf> {
    Ok(cwd()?.join("logfile.txt"))
}

fn log_event(level: &str, msg: &str) -> Result<()> {
    let ts = Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();
    let line = format!("[{}] {}: {}\n", ts, level, msg);
    let path = logfile_path()?;
    let mut f = OpenOptions::new()
        .append(true)
        .create(true)
        .open(&path)
        .with_context(|| format!("open logfile at {}", path.display()))?;
    f.write_all(line.as_bytes())?;
    Ok(())
}

/// Create `<filename>.bak` without overwriting. Copies bytes safely.
pub fn backup_file(filename: &str) -> Result<PathBuf> {
    let filename = sanitize_filename(filename)?;
    let src = Path::new(&filename);
    within_cwd(src)?;
    if !src.exists() {
        anyhow::bail!("source file does not exist")
    }
    if !src.is_file() {
        anyhow::bail!("source is not a regular file")
    }
    let bak = Path::new(&(filename.to_string() + ".bak"));
    if bak.exists() {
        anyhow::bail!("backup already exists, refusing to overwrite")
    }

    // Open source for read
    let mut reader = File::open(src)
        .with_context(|| format!("open source {}", src.display()))?;

    // Create dest with create_new to avoid race
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&bak)
        .with_context(|| format!("create backup {}", bak.display()))?;

    io::copy(&mut reader, &mut writer).context("copy to backup failed")?;
    writer.flush()?;

    log_event("INFO", &format!("Backup created for {}", filename)).ok();
    Ok(bak.to_path_buf())
}

/// Restore from `<filename>.bak` to `<filename>` atomically by writing to a temp file.
pub fn restore_file(filename: &str) -> Result<PathBuf> {
    let filename = sanitize_filename(filename)?;
    let src_bak = Path::new(&(filename.to_string() + ".bak"));
    within_cwd(src_bak)?;

    if !src_bak.exists() || !src_bak.is_file() {
        anyhow::bail!("backup file does not exist")
    }

    let tmp = Path::new(&(filename.to_string() + ".tmp"));

    // Open bak for read
    let mut reader = File::open(src_bak)
        .with_context(|| format!("open backup {}", src_bak.display()))?;

    // Create temp new file
    let mut writer = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(&tmp)
        .with_context(|| format!("create temp {}", tmp.display()))?;

    io::copy(&mut reader, &mut writer).context("copy from backup failed")?;
    writer.flush()?;

    // Atomic replace
    fs::rename(&tmp, &filename).with_context(|| {
        // Clean temp on failure best effort
        let _ = fs::remove_file(&tmp);
        format!("rename {} to {}", tmp.display(), filename)
    })?;

    log_event("INFO", &format!("Restore completed for {}", filename)).ok();
    Ok(PathBuf::from(filename))
}

/// Securely delete a file by overwriting with zeros and then removing.
pub fn delete_file(filename: &str) -> Result<()> {
    let filename = sanitize_filename(filename)?;
    let path = Path::new(&filename);
    within_cwd(path)?;

    if !path.exists() || !path.is_file() {
        anyhow::bail!("file does not exist")
    }

    // Overwrite with zeros
    let metadata = fs::metadata(path).with_context(|| format!("metadata {}", path.display()))?;
    let len = metadata.len();
    {
        let mut f = OpenOptions::new()
            .write(true)
            .open(path)
            .with_context(|| format!("open {} for overwrite", path.display()))?;
        // Write in chunks
        let chunk = vec![0u8; 8192];
        let mut written: u64 = 0;
        while written < len {
            let to_write = std::cmp::min(8192u64, len - written) as usize;
            f.write_all(&chunk[..to_write])?;
            written += to_write as u64;
        }
        f.flush()?;
    }

    fs::remove_file(path).with_context(|| format!("remove {}", path.display()))?;
    log_event("INFO", &format!("Secure delete completed for {}", filename)).ok();
    Ok(())
}
