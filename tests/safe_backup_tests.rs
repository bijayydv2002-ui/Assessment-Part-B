use std::fs;
use std::io::Write;
use std::path::Path;

use safe_backup::{backup_file, delete_file, restore_file};
use tempfile::tempdir;

#[test]
fn test_backup_valid() {
    let dir = tempdir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    // create sample.txt
    let mut f = fs::File::create("sample.txt").unwrap();
    writeln!(f, "hello").unwrap();

    let bak = backup_file("sample.txt").expect("backup should succeed");
    assert!(bak.exists());

    let content_src = fs::read_to_string("sample.txt").unwrap();
    let content_bak = fs::read_to_string("sample.txt.bak").unwrap();
    assert_eq!(content_src, content_bak);
}

#[test]
fn test_backup_traversal_blocked() {
    let dir = tempdir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    // malicious path must be rejected
    let err = backup_file("../../etc/passwd").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("path separators") || msg.contains("traversal"));
}

#[test]
fn test_restore_valid() {
    let dir = tempdir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    // create sample.txt and a backup
    {
        let mut f = fs::File::create("data.txt").unwrap();
        write!(f, "original").unwrap();
    }
    // backup
    backup_file("data.txt").unwrap();

    // modify the original
    {
        let mut f = fs::File::create("data.txt").unwrap();
        write!(f, "modified").unwrap();
    }

    // restore
    restore_file("data.txt").unwrap();
    let content = fs::read_to_string("data.txt").unwrap();
    assert_eq!(content, "original\n");
}

#[test]
fn test_delete_valid() {
    let dir = tempdir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    {
        let mut f = fs::File::create("remove_me.txt").unwrap();
        write!(f, "secret").unwrap();
    }

    delete_file("remove_me.txt").unwrap();
    assert!(!Path::new("remove_me.txt").exists());
}

#[test]
fn test_restore_traversal_blocked() {
    let dir = tempdir().unwrap();
    std::env::set_current_dir(dir.path()).unwrap();

    let err = restore_file("../foo.txt").unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("path separators") || msg.contains("traversal"));
}
