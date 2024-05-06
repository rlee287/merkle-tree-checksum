use snapbox::cmd::{Command, cargo_bin};

use std::path::PathBuf;
use tempfile::tempdir;

const INPUT_FILE_LIST: &[&str] =
    &["16_byte_file", "20_byte_file", "empty_file"];

#[test]
fn gen_and_verify_roundtrip() {
    let ref_cwd = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/reference_files");
    let test_cwd = tempdir().unwrap();

    for input_file in INPUT_FILE_LIST {
        let input_path = ref_cwd.join(input_file);
        let output_path = test_cwd.path().join(input_file);
        std::fs::copy(input_path, output_path).unwrap();
    }

    Command::new(cargo_bin!("merkle_tree_checksum"))
        .current_dir(&test_cwd)
        .args(&["generate-hash", "-o", "hash_out", "-l", "4", "--", "16_byte_file", "20_byte_file", "empty_file"])
        .assert()
        .success();

    Command::new(cargo_bin!("merkle_tree_checksum"))
        .current_dir(&test_cwd)
        .args(&["verify-hash", "--", "hash_out"])
        .assert()
        .success();
}