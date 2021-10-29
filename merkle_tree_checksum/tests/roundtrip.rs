mod utils;
use utils::gen_random_name;

use std::env::{current_dir, set_current_dir};
use std::fs::remove_file;

use assert_cmd::Command;
use predicates::prelude::*;

use serial_test::serial;

#[test]
#[serial]
fn roundtrip_reference_files_long() {
    let output_path = gen_random_name("temp_hash_out");
    let mut cmd_gen = Command::cargo_bin("merkle_tree_checksum").unwrap();
    let assert_gen = cmd_gen
        .args(["generate-hash", "-l", "4",
            "-o", output_path.to_str().unwrap(),
            "--",
            "tests/reference_files/16_byte_file",
            "tests/reference_files/20_byte_file",
            "tests/reference_files/empty_file"])
        .assert();
    assert_gen
        .success()
        .code(0);
    let _guard = scopeguard::guard(output_path.clone(), |output_path| {
        if output_path.is_file() {
            remove_file(output_path).unwrap();
        }
    });
    assert!(output_path.is_file());
    let mut cmd_check = Command::cargo_bin("merkle_tree_checksum").unwrap();
    let assert_check = cmd_check
        .args(["verify-hash", output_path.to_str().unwrap()])
        .assert();
    assert_check
        .success()
        .code(0);
}
#[test]
#[serial]
fn roundtrip_reference_files_short() {
    let output_path = gen_random_name("temp_hash_out_short");
    let mut cmd_gen = Command::cargo_bin("merkle_tree_checksum").unwrap();
    let assert_gen = cmd_gen
        .args(["generate-hash", "-l", "4", "-s",
            "-o", output_path.to_str().unwrap(),
            "--",
            "tests/reference_files/16_byte_file",
            "tests/reference_files/20_byte_file",
            "tests/reference_files/empty_file"])
        .assert();
    assert_gen
        .success()
        .code(0)
        .stderr(predicate::str::contains("Error").count(0));
    let _guard = scopeguard::guard(output_path.clone(), |output_path| {
        if output_path.is_file() {
            remove_file(output_path).unwrap();
        }
    });
    assert!(output_path.is_file());

    let mut cmd_check = Command::cargo_bin("merkle_tree_checksum").unwrap();
    let assert_check = cmd_check
        .args(["verify-hash", output_path.to_str().unwrap()])
        .assert();
    assert_check
        .success()
        .code(0)
        .stderr(predicate::str::contains("Error").count(0));
}
