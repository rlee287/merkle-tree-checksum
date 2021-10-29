mod utils;
use utils::{gen_random_name, file_contents_equal};

use std::env::{current_dir, set_current_dir};
use std::fs::{remove_file, File};

use assert_cmd::Command;
use predicates::prelude::*;

use serial_test::serial;

#[test]
#[serial]
fn gen_compare_files_long() {
    let output_path = gen_random_name("temp_hash_out");
    set_current_dir("tests/reference_files").unwrap();
    let _guard = scopeguard::guard(output_path.clone(), |output_path| {
        if output_path.is_file() {
            remove_file(output_path).unwrap();
        }
        if current_dir().unwrap().ends_with("tests/reference_files") {
            set_current_dir("../..").unwrap();
        }
    });
    let mut cmd_gen = Command::cargo_bin("merkle_tree_checksum").unwrap();
    let assert_gen = cmd_gen
        .args(["generate-hash", "-l", "4",
            "-o", output_path.to_str().unwrap(),
            "--",
            "16_byte_file",
            "20_byte_file",
            "empty_file"])
        .assert();
    assert_gen
        .success()
        .code(0)
        .stderr(predicate::str::contains("Error").count(0));
    assert!(output_path.is_file());

    let output_file_obj = File::open(output_path.clone()).unwrap();
    let ref_file_obj = File::open("hash_out").unwrap();

    assert!(file_contents_equal(output_file_obj, ref_file_obj));
}
#[test]
#[serial]
fn gen_compare_files_short() {
    let output_path = gen_random_name("temp_hash_out_short");
    set_current_dir("tests/reference_files").unwrap();
    let _guard = scopeguard::guard(output_path.clone(), |output_path| {
        if output_path.is_file() {
            remove_file(output_path).unwrap();
        }
        if current_dir().unwrap().ends_with("tests/reference_files") {
            set_current_dir("../..").unwrap();
        }
    });
    let mut cmd_gen = Command::cargo_bin("merkle_tree_checksum").unwrap();
    let assert_gen = cmd_gen
        .args(["generate-hash", "-l", "4", "-s",
            "-o", output_path.to_str().unwrap(),
            "--",
            "16_byte_file",
            "20_byte_file",
            "empty_file"])
        .assert();
    assert_gen
        .success()
        .code(0)
        .stderr(predicate::str::contains("Error").count(0));
    assert!(output_path.is_file());

    let output_file_obj = File::open(output_path.clone()).unwrap();
    let ref_file_obj = File::open("hash_out_short").unwrap();

    assert!(file_contents_equal(output_file_obj, ref_file_obj));
}