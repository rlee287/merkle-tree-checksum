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
        .code(3)
        // TODO: check that the correct file is bad, and that others are fine
        .stderr(
            predicate::str::contains("Error").and(
                predicate::str::contains("hash mismatch")
            ));
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
        .args(["verify-hash", "hash_out_short_malformed"])
        .assert();
    assert_check
        .failure()
        .code(3)
        .stderr(predicate::str::contains("Error").and(
            predicate::str::contains("malformed entry")
        ));
    // TODO: check which entry is malformed, and that others are fine
}

#[test]
#[serial]
fn verify_files_long_badlen() {
    set_current_dir("tests/reference_files").unwrap();
    let _guard = scopeguard::guard((), |_| {
        if current_dir().unwrap().ends_with("tests/reference_files") {
            set_current_dir("../..").unwrap();
        }
    });
    let mut cmd_check = Command::cargo_bin("merkle_tree_checksum").unwrap();
    let assert_check = cmd_check
        .args(["verify-hash", "hash_out_badlen"])
        .assert();
    assert_check
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Error").and(
            predicate::str::contains("mismatched file length")
        ));
    // TODO: check which entry is malformed, and that others are fine

    cmd_check = Command::cargo_bin("merkle_tree_checksum").unwrap();
    let assert_check = cmd_check
        .args(["verify-hash", "hash_out_badlen_last"])
        .assert();
    assert_check
        .failure()
        .code(1)
        .stderr(predicate::str::contains("Error").and(
            predicate::str::contains("mismatched file length")
        ));
    // TODO: check which entry is malformed, and that others are fine
}
