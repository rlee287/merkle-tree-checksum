use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

use scopeguard::defer;

const HASH_FUNCTION_LIST: &[&'static str] = &["crc32",
    "sha224", "sha256", "sha384", "sha512" ,"sha512_224", "sha512_256",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    "blake2b512", "blake2s256",
    "blake3"];

const INPUT_FILE_LIST: &[&'static str] =
    &["16_byte_file", "20_byte_file", "empty_file"];

const GEN_REF_TEMPLATE: &str =
r#"bin.name = "merkle_tree_checksum"
args = "generate-hash -o hash_out -l 4 -f HASH_FUNC -- 16_byte_file 20_byte_file empty_file"
fs.sandbox = true"#;
const VERIFY_TOML: &str =
r#"bin.name = "merkle_tree_checksum"
args = "verify-hash -- hash_out"
fs.sandbox = true"#;

// Set to true to debug generated temp files
const SKIP_CLEANUP: bool = false;

#[test]
fn gen_ref_cmd_tests() {
    for hash_func in HASH_FUNCTION_LIST {
        let mut toml_file = File::create(format!("tests/gen_ref_cmd/{}_gen_ref.toml",hash_func)).unwrap();
        write!(toml_file, "{}", GEN_REF_TEMPLATE.replace("HASH_FUNC", hash_func)).unwrap();
    }
    let in_directories: Vec<PathBuf> = HASH_FUNCTION_LIST.iter()
        .map(|func| {
            PathBuf::from(format!("tests/gen_ref_cmd/{}_gen_ref.in", func))
        })
        .collect();
    for in_dir in in_directories.iter() {
        fs::create_dir(in_dir).unwrap();
        for input_file in INPUT_FILE_LIST {
            let mut dest_path = in_dir.clone();
            dest_path.extend(&[input_file]);

            fs::copy(format!("tests/reference_files/{}", input_file),
            dest_path).unwrap();
        }
    }
    defer! {
        if !SKIP_CLEANUP {
            for in_dir in in_directories {
                fs::remove_dir_all(in_dir).unwrap();
            }
            for hash_func in HASH_FUNCTION_LIST {
                fs::remove_file(format!("tests/gen_ref_cmd/{}_gen_ref.toml",hash_func)).unwrap();
            }
        }
    }

    trycmd::TestCases::new()
        .case("tests/gen_ref_cmd/*_gen_ref.toml");

}
#[test]
//#[ignore]
fn verify_tests() {
    for hash_func in HASH_FUNCTION_LIST {
        let mut toml_file = File::create(format!("tests/verify_cmd/{}_verify.toml",hash_func)).unwrap();
        write!(toml_file, "{}", VERIFY_TOML).unwrap();
    }
    let in_directories: Vec<PathBuf> = HASH_FUNCTION_LIST.iter()
        .map(|func| {
            PathBuf::from(format!("tests/verify_cmd/{}_verify.in", func))
        })
        .collect();
    // Do not create and remove directories because we preserve hash_out
    for in_dir in in_directories.iter() {
        for input_file in INPUT_FILE_LIST {
            let mut dest_path = in_dir.clone();
            dest_path.extend(&[input_file]);

            fs::copy(format!("tests/reference_files/{}", input_file),
            dest_path).unwrap();
        }
    }
    defer!{
        if !SKIP_CLEANUP {
            for in_dir in in_directories {
                for input_file in INPUT_FILE_LIST {
                    let mut dest_path = in_dir.clone();
                    dest_path.extend(&[input_file]);
                    fs::remove_file(dest_path).unwrap();
                }
            }
            for hash_func in HASH_FUNCTION_LIST {
                fs::remove_file(format!("tests/verify_cmd/{}_verify.toml",hash_func)).unwrap();
            }
        }
    }

    trycmd::TestCases::new()
        .case("tests/verify_cmd/*_verify.toml");
}

#[test]
fn help_test() {
    trycmd::TestCases::new()
        .case("tests/help_cmd/help_out_*.toml");
}
