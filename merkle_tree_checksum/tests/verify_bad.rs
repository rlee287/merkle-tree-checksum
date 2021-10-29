use std::env::{current_dir, set_current_dir};

use assert_cmd::Command;
use predicates::prelude::*;

use serial_test::serial;

#[test]
#[serial]
fn verify_files_short_badhash() {
    set_current_dir("tests/reference_files").unwrap();
    let _guard = scopeguard::guard((), |_| {
        if current_dir().unwrap().ends_with("tests/reference_files") {
            set_current_dir("../..").unwrap();
        }
    });
    let mut cmd_check = Command::cargo_bin("merkle_tree_checksum").unwrap();
    let assert_check = cmd_check
        .args(["verify-hash", "hash_out_short_badhash"])
        .assert();
    assert_check
        .failure()
        .code(2)
        // TODO: check for "hash mismatch", and that others are fine
        .stderr(predicate::str::contains("Error"));
}

#[test]
#[serial]
fn verify_files_short_malformed() {
    set_current_dir("tests/reference_files").unwrap();
    let _guard = scopeguard::guard((), |_| {
        if current_dir().unwrap().ends_with("tests/reference_files") {
            set_current_dir("../..").unwrap();
        }
    });
    let mut cmd_check = Command::cargo_bin("merkle_tree_checksum").unwrap();
    let assert_check = cmd_check
        .args(["verify-hash", "hash_out_short_badhash"])
        .assert();
    assert_check
        .failure()
        .code(2)
        .stderr(predicate::str::contains("Error"));
    // TODO: check for "malformed entry", and that others are fine
}