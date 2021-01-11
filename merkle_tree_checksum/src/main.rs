#![forbid(unsafe_code)]
extern crate merkle_tree;
#[macro_use]
extern crate clap;

use std::convert::AsMut;
use std::env::args;

use chrono::Local;

use std::fs::File;
use std::io::{self, Write, BufWriter};
use std::path::Path;
use walkdir::WalkDir;

use sha2::Sha256;

use clap::{App, Arg};
use indicatif::{ProgressBar, ProgressStyle};

const HASH_LIST: &[&str] = &["sha224", "sha256", "sha384", "sha512"];

struct ProgressBarAsIncrementable {
    pb: ProgressBar
}
impl merkle_tree::Incrementable for ProgressBarAsIncrementable {
    fn incr(&mut self) {
        self.pb.inc(1);
    }
}

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
        .arg(Arg::with_name("blocksize").long("block-length").short("l")
            .takes_value(true).default_value("4096")
            .validator(|input_str| -> Result<(), String> {
                match input_str.parse::<u32>() {
                    Ok(_) => Ok(()),
                    Err(err) => Err(err.to_string())
                }
            })
            .help("Block size for hash"))
        .arg(Arg::with_name("output").long("output").short("o")
            .takes_value(true)
            .help("Output file (default stdout)"))
        .arg(Arg::with_name("short").long("short").short("s")
            .help("Output only the summary hash")
            .long_help("Write only the summary hash to the output. This will make identifying corrupted locations impossible."))
        .arg(Arg::with_name("FILES").required(true)
            .multiple(true).last(true))
        .get_matches();

    // Unwraps succeeds because validators should already have caught errors
    let block_size: u32 = matches.value_of("blocksize").unwrap().parse().unwrap();
    let branch_factor: u16 = matches.value_of("branch").unwrap().parse().unwrap();
    let short_output = matches.is_present("short");
    let mut file_list = Vec::<String>::new();
    for file_str in matches.values_of("FILES").unwrap() {
        let file_path = Path::new(file_str);
        if file_path.is_file() {
            println!("{}", file_path.display());
            file_list.push(file_str.to_owned());
        } else if file_path.is_dir() {
            // Walk directory to find all the files in it
            for entry in WalkDir::new(file_path).min_depth(1) {
                let entry_unwrap = entry.unwrap();
                let entry_path = entry_unwrap.path();
                if entry_path.is_file() {
                    file_list.push(entry_path.to_str().unwrap().to_owned());
                }
            }
        } else {
            eprintln!("Error: file {} does not exist", file_str);
            return 1;
        }
    }
    let mut arg_vec: Vec<String> = Vec::new();
    // Scope the argument iteration variables
    {
        let mut arg_iter = args();
        // Skip the first element (binary name)
        arg_iter.next();
        for arg in arg_iter {
            if arg == "--" {
                break;
            }
            arg_vec.push(arg);
        }
    }
    let mut out_file: Box<dyn Write> = match matches.value_of("output") {
        None => Box::new(io::stdout()),
        Some(name) => match File::create(name) {
            Ok(file) => Box::new(BufWriter::new(file)),
            Err(err) => {
                eprintln!("Error opening file {} for writing: {}",
                    name, err);
                return 1
            }
        }
    };
    let write_handle: &mut dyn Write = out_file.as_mut();
    writeln!(write_handle, "{} v{}", crate_name!(), crate_version!()).unwrap();
    writeln!(write_handle, "Arguments: {}", arg_vec.join(" ")).unwrap();
    writeln!(write_handle, "Started {}", Local::now().to_rfc2822()).unwrap();
    write_handle.flush().unwrap();

    for file_name in file_list {
        let file_obj = match File::open(file_name.to_owned()) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Error opening file {} for reading: {}",
                    file_name, err);
                return 1
            }
        };
        let pb = ProgressBar::new(
            merkle_tree::node_count(file_obj.metadata().unwrap().len(), block_size, branch_factor)
        );
        let pb_style = ProgressStyle::default_bar()
            .template("[{elapsed_precise}] {pos}/{len} (hash rate {per_sec}) ETA [{eta_precise}] {wide_msg}");
        pb.set_style(pb_style);
        pb.set_message(Path::new(&file_name).file_name().unwrap().to_str().unwrap());
        pb.tick();
        // Clone is fine as ProgressBar is an Arc around internal state
        let mut pb_incr = ProgressBarAsIncrementable {pb: pb.clone()};
        if short_output {
            let hash_result = merkle_tree::merkle_hash_file::<Sha256>(file_obj, block_size, branch_factor, &mut io::sink(), &mut pb_incr);
            writeln!(write_handle, "{:x}  {}", hash_result, file_name).unwrap();
        } else {
            writeln!(write_handle, "File {}", file_name).unwrap();
            // Final entry is the final hash
            merkle_tree::merkle_hash_file::<Sha256>(file_obj, block_size, branch_factor, write_handle, &mut pb_incr);
        }
        assert_eq!(pb.position(), pb.length());
        pb.finish_at_current_pos();
        write_handle.flush().unwrap();
    }
    return 0;
}