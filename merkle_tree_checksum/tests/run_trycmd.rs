use std::fs::{self, File};
use std::io::Write;
use std::path::{Path, PathBuf};

use scopeguard::defer;

const HASH_FUNCTION_LIST: &[&str] = &["crc32",
    "sha224", "sha256", "sha384", "sha512" ,"sha512_224", "sha512_256",
    "sha3_224", "sha3_256", "sha3_384", "sha3_512",
    "blake2b512", "blake2s256",
    "blake3"];

// Hash functions with name aliases
const HASH_FUNCTION_ALTNAME_LIST: &[&str] = &["sha512trunc224",
    "sha512trunc256", "blake2b", "blake2s"];

const INPUT_FILE_LIST: &[&str] =
    &["16_byte_file", "20_byte_file", "empty_file"];

const GEN_REF_TEMPLATE: &str =
r#"bin.name = "merkle_tree_checksum"
args = "generate-hash -o hash_out -l 4 -f HASH_FUNC -- 16_byte_file 20_byte_file empty_file"
fs.sandbox = true"#;
const VERIFY_TOML: &str =
r#"bin.name = "merkle_tree_checksum"
args = "verify-hash -- hash_out"
fs.sandbox = true"#;
const VERIFY_ALTNAME_TOML: &str =
r#"bin.name = "merkle_tree_checksum"
args = "verify-hash -- hash_out_altname"
fs.sandbox = true"#;
const VERIFY_BAD_TEMPLATE: &str =
r#"bin.name = "merkle_tree_checksum"
args = "verify-hash -- FILENAME"
fs.sandbox = true
status.code = STATUS_CODE"#;

// Set to true to debug generated temp files
const SKIP_CLEANUP: bool = false;

// Helper that runs all *.toml tests in dir_path and that copies and removes shared auxiliary files used by those *.toml tests
fn cmd_test_helper<'a>(dir_path: &Path, prefix_names: impl IntoIterator<Item = &'a str>,
        mkdir_rmdir: bool) {
    let prefix_vec: Vec<_> = prefix_names.into_iter().collect();
    for prefix in prefix_vec.iter() {
        let mut in_dir_path = PathBuf::from(dir_path);
        in_dir_path.push(format!("{}.in", prefix));
        if mkdir_rmdir && !in_dir_path.is_dir() {
            fs::create_dir(&in_dir_path).expect(format!("Could not create {}", in_dir_path.display()).as_ref());
        }
        for input_file in INPUT_FILE_LIST {
            let mut dest_path = in_dir_path.clone();
            dest_path.push(input_file);
            let src_path = format!("tests/reference_files/{}", input_file);
    
            fs::copy(&src_path, dest_path)
                .expect(format!("Error copying from {}", src_path).as_str());
        }
    }

    defer! {
        if !SKIP_CLEANUP {
            for prefix in prefix_vec {
                let mut in_dir_path = PathBuf::from(dir_path);
                in_dir_path.push(format!("{}.in", prefix));
                if mkdir_rmdir {
                    fs::remove_dir_all(&in_dir_path)
                        .expect(format!("Error removing dir {}", in_dir_path.display()).as_str());
                } else {
                    for input_file in INPUT_FILE_LIST {
                        let mut dest_path = in_dir_path.clone();
                        dest_path.push(input_file);
                
                        fs::remove_file(&dest_path)
                            .expect(format!("Error removing file {}", dest_path.display()).as_str());
                    }
                }
            }
        }
    }
    let mut toml_path = PathBuf::from(dir_path);
    toml_path.push("*.toml");
    trycmd::TestCases::new().case(toml_path);
}

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
        if !in_dir.is_dir() {
            fs::create_dir(in_dir).expect(format!("Could not create {}", in_dir.display()).as_ref());
        }
        for input_file in INPUT_FILE_LIST {
            let mut dest_path = in_dir.clone();
            dest_path.push(input_file);

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
fn gen_ref_short_cmd_tests() {
    // We're only doing sha256 for now; update if doing parametric generation
    let test_dir = PathBuf::from("tests/gen_ref_short_cmd");
    cmd_test_helper(&test_dir, ["sha256_gen_ref_short"], true);
}

#[test]
fn verify_cmd_tests() {
    for hash_func in HASH_FUNCTION_LIST {
        let mut toml_file = File::create(format!("tests/verify_cmd/{}_verify.toml",hash_func)).unwrap();
        write!(toml_file, "{}", VERIFY_TOML).unwrap();
    }
    for hash_func in HASH_FUNCTION_ALTNAME_LIST {
        let mut toml_file = File::create(format!("tests/verify_cmd/{}_verify.toml",hash_func)).unwrap();
        write!(toml_file, "{}", VERIFY_ALTNAME_TOML).unwrap();
    }
    let in_directories: Vec<PathBuf> = HASH_FUNCTION_LIST.iter()
        .chain(HASH_FUNCTION_ALTNAME_LIST.iter())
        .map(|func| {
            PathBuf::from(format!("tests/verify_cmd/{}_verify.in", func))
        })
        .collect();
    // Do not create and remove directories because we preserve hash_out
    for in_dir in in_directories.iter() {
        for input_file in INPUT_FILE_LIST {
            let mut dest_path = in_dir.clone();
            dest_path.push(input_file);

            fs::copy(format!("tests/reference_files/{}", input_file),
                &dest_path)
                .expect(format!("Error copying to {}", dest_path.display()).as_str());
        }
    }
    defer!{
        if !SKIP_CLEANUP {
            for in_dir in in_directories {
                for input_file in INPUT_FILE_LIST {
                    let mut dest_path = in_dir.clone();
                    dest_path.push(input_file);
                    fs::remove_file(dest_path).unwrap();
                }
            }
            for hash_func in HASH_FUNCTION_LIST {
                fs::remove_file(format!("tests/verify_cmd/{}_verify.toml",hash_func)).unwrap();
            }
            for hash_func in HASH_FUNCTION_ALTNAME_LIST {
                fs::remove_file(format!("tests/verify_cmd/{}_verify.toml",hash_func)).unwrap();
            }
        }
    }

    trycmd::TestCases::new()
        .case("tests/verify_cmd/*_verify.toml");
}
#[test]
fn verify_short_cmd_tests() {
    // We're only doing sha256 for now; update if doing parametric generation
    let test_dir = PathBuf::from("tests/verify_short_cmd");
    cmd_test_helper(&test_dir, ["sha256_verify_short"], false);
}

#[test]
fn verify_bad_cmd_tests() {
    // We're only doing sha256 for now; update if doing parametric generation
    let suffix_list = ["badhash", "badlen", "badlen_last", "malformed", "short_badhash", "short_malformed"];
    let input_testcase_tuples = suffix_list
        .map(|s| (format!("hash_out_{}", s), format!("sha256_verify_{}", s)));
    for (input_name, testcase) in input_testcase_tuples.iter() {
        let mut in_dir = PathBuf::from("tests/verify_bad_cmd");
        let mut toml_path = in_dir.clone();
        in_dir.push(testcase.clone() + ".in");
        toml_path.push(testcase.clone() + ".toml");

        let mut toml_content = VERIFY_BAD_TEMPLATE.replace("FILENAME", input_name);
        let expected_status = match input_name.find("badlen") {
            Some(_) => 1,
            None => 3
        };
        toml_content = toml_content.replace("STATUS_CODE", &expected_status.to_string());
        let mut toml_file = File::create(toml_path).unwrap();
        write!(toml_file, "{}", toml_content).unwrap();
        drop(toml_file);

        if !in_dir.is_dir() {
            fs::create_dir(&in_dir).expect(format!("Could not create {}", in_dir.display()).as_ref());
        }

        let mut inputfile_path = in_dir.clone();
        inputfile_path.push(input_name);
        fs::copy(format!("tests/reference_files/{}", input_name),
            &inputfile_path)
            .expect(format!("Error copying to {}", inputfile_path.display()).as_str());
        for data_file in INPUT_FILE_LIST {
            let mut data_file_path = in_dir.clone();
            data_file_path.push(data_file);
            fs::copy(format!("tests/reference_files/{}", data_file),
                &data_file_path)
                .expect(format!("Error copying to {}", data_file_path.display()).as_str());
        }
    }

    defer! {
        if !SKIP_CLEANUP {
            for (_, testcase) in input_testcase_tuples.iter() {
                let mut in_dir = PathBuf::from("tests/verify_bad_cmd");
                let mut toml_path = in_dir.clone();
                in_dir.push(testcase.clone() + ".in");
                toml_path.push(testcase.clone() + ".toml");

                fs::remove_file(&toml_path)
                    .expect(format!("Error removing file {}", toml_path.display()).as_str());
                fs::remove_dir_all(&in_dir)
                    .expect(format!("Error removing dir {}", in_dir.display()).as_str());
            }
        }
    }

    trycmd::TestCases::new()
        .case("tests/verify_bad_cmd/*.toml");
}

#[test]
fn help_test() {
    trycmd::TestCases::new()
        .case("tests/help_cmd/help_out_*.toml");
}
