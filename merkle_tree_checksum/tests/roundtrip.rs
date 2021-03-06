#[macro_use]
mod utils;
use utils::*;

use std::env::{current_dir, set_current_dir};
use std::fs::{File, remove_file};
use std::path::PathBuf;

use assert_cmd::Command;
use predicates::prelude::*;

use rand::{thread_rng, Rng};
use rand::distributions::Alphanumeric;

use serial_test::serial;

#[test]
#[serial]
fn roundtrip_reference_files_long() {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let output_name = "temp_hash_out".to_owned() + &rand_string;
    let output_path = PathBuf::from(output_name.clone());

    cleanup_after_func!({
        let mut cmd_gen = Command::cargo_bin("merkle_tree_checksum").unwrap();
        let assert_gen = cmd_gen
            .args(["generate-hash", "-l", "4", "-o", &output_name,
                "--",
                "tests/reference_files/16_byte_file",
                "tests/reference_files/20_byte_file",
                "tests/reference_files/empty_file"])
            .assert();
        assert_gen
            .success()
            .code(0);
        assert!(output_path.is_file());
    
        let mut cmd_check = Command::cargo_bin("merkle_tree_checksum").unwrap();
        let assert_check = cmd_check
            .args(["verify-hash", &output_name])
            .assert();
        assert_check
            .success()
            .code(0);
    }, {
        if output_path.is_file() {
            remove_file(output_path).unwrap();
        }
    });
}
#[test]
#[serial]
fn roundtrip_reference_files_short() {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let output_name = "temp_hash_out_short".to_owned() + &rand_string;
    let output_path = PathBuf::from(output_name.clone());

    cleanup_after_func!({
        let mut cmd_gen = Command::cargo_bin("merkle_tree_checksum").unwrap();
        let assert_gen = cmd_gen
            .args(["generate-hash", "-l", "4", "-s", "-o", &output_name,
                "--",
                "tests/reference_files/16_byte_file",
                "tests/reference_files/20_byte_file",
                "tests/reference_files/empty_file"])
            .assert();
        assert_gen
            .success()
            .code(0)
            .stderr(predicate::str::contains("Error").count(0));
        assert!(output_path.is_file());
    
        let mut cmd_check = Command::cargo_bin("merkle_tree_checksum").unwrap();
        let assert_check = cmd_check
            .args(["verify-hash", &output_name])
            .assert();
        assert_check
            .success()
            .code(0)
            .stderr(predicate::str::contains("Error").count(0));
    }, {
        if output_path.is_file() {
            remove_file(output_path).unwrap();
        }
    });
}

#[test]
#[serial]
fn gen_compare_files_long() {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let output_name = "temp_hash_out".to_owned() + &rand_string;
    let output_path = PathBuf::from(output_name.clone());

    cleanup_after_func!({
        set_current_dir("tests/reference_files").unwrap();
        let mut cmd_gen = Command::cargo_bin("merkle_tree_checksum").unwrap();
        let assert_gen = cmd_gen
            .args(["generate-hash", "-l", "4", "-o", &output_name,
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
    }, {
        if output_path.is_file() {
            remove_file(output_path).unwrap();
        }
        if current_dir().unwrap().ends_with("tests/reference_files") {
            set_current_dir("../..").unwrap();
        }
    });
}
#[test]
#[serial]
fn gen_compare_files_short() {
    let rand_string: String = thread_rng()
        .sample_iter(&Alphanumeric)
        .take(8)
        .map(char::from)
        .collect();
    let output_name = "temp_hash_out_short".to_owned() + &rand_string;
    let output_path = PathBuf::from(output_name.clone());

    cleanup_after_func!({
        set_current_dir("tests/reference_files").unwrap();
        let mut cmd_gen = Command::cargo_bin("merkle_tree_checksum").unwrap();
        let assert_gen = cmd_gen
            .args(["generate-hash", "-l", "4", "-s", "-o", &output_name,
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
    }, {
        if output_path.is_file() {
            remove_file(output_path).unwrap();
        }
        if current_dir().unwrap().ends_with("tests/reference_files") {
            set_current_dir("../..").unwrap();
        }
    });
}

#[test]
#[serial]
fn verify_files_short_bad() {
    cleanup_after_func!({
        set_current_dir("tests/reference_files").unwrap();
        let mut cmd_check = Command::cargo_bin("merkle_tree_checksum").unwrap();
        let assert_check = cmd_check
            .args(["verify-hash", "hash_out_short_bad"])
            .assert();
        assert_check
            .failure()
            .code(2)
            .stderr(predicate::str::contains("Error"));
    }, {
        if current_dir().unwrap().ends_with("tests/reference_files") {
            set_current_dir("../..").unwrap();
        }
    });
}