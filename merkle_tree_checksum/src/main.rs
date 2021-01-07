#![forbid(unsafe_code)]
extern crate merkle_tree;
#[macro_use]
extern crate clap;

use std::fs::File;
use std::path::Path;
use walkdir::WalkDir;

use sha2::Sha256;
use clap::{App, Arg};

const HASH_LIST: &[&str] = &["sha224", "sha256", "sha384", "sha512"];

fn main() {
    let status_code = run();
    std::process::exit(status_code);
}

fn run() -> i32 {
    /*for entry in WalkDir::new("target").min_depth(1) {
        let entry_unwrap = entry.unwrap();
        let entry_path = entry_unwrap.path();
        if entry_path.is_file() {
            println!("{}", entry_path.display());
        }
    }*/
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::with_name("hash").long("hash-function").short("f")
            .takes_value(true)
            .default_value("sha256").possible_values(HASH_LIST)
            .help("Hash function to use"))
        .arg(Arg::with_name("branch").long("branch-factor").short("b")
            .takes_value(true).default_value("4")
            .validator(|input_str| -> Result<(), String> {
                match input_str.parse::<u16>() {
                    Ok(_) => Ok(()),
                    Err(err) => Err(err.to_string())
                }
            })
            .help("Branch factor for tree"))
        .arg(Arg::with_name("blocksize").long("block-size").short("s")
            .takes_value(true).default_value("4096")
            .validator(|input_str| -> Result<(), String> {
                match input_str.parse::<u32>() {
                    Ok(_) => Ok(()),
                    Err(err) => Err(err.to_string())
                }
            })
            .help("Block size for hash"))
        .arg(Arg::with_name("verbose").long("verbose").short("v")
            .multiple(true)
            .help("Be verbose"))
        .arg(Arg::with_name("FILES").required(true)
            .multiple(true).last(true))
        .get_matches();

    // Unwraps succeeds because validators should already have caught errors
    let block_size: u32 = matches.value_of("blocksize").unwrap().parse().unwrap();
    let branch_factor: u16 = matches.value_of("branch").unwrap().parse().unwrap();
    let verbosity = matches.occurrences_of("verbose");
    let mut file_list = Vec::<String>::new();
    for file_str in matches.values_of("FILES").unwrap() {
        let file_path = Path::new(file_str);
        if file_path.is_file() {
            println!("{}", file_path.display());
            file_list.push(file_str.to_owned());
        } else if file_path.is_dir() {
            for entry in WalkDir::new(file_path).min_depth(1) {
                let entry_unwrap = entry.unwrap();
                let entry_path = entry_unwrap.path();
                if entry_path.is_file() {
                    println!("{}", entry_path.display());
                    file_list.push(entry_path.to_str().unwrap().to_owned());
                }
            }
        } else {
            eprintln!("Error: file {} does not exist", file_str);
            return 1;
        }
    }
    println!("File list is {:?}", file_list);
    for file_name in file_list {
        let file_obj = match File::open(file_name.to_owned()) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Error opening file {}: {}", file_name, err);
                return 1
            }
        };
        let hash_result = merkle_tree::merkle_hash_file::<Sha256>(file_obj, block_size, branch_factor);
        println!("Final hash is {:x}", hash_result);
    }
    return 0;
}