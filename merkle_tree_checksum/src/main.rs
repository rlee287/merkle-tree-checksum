#![forbid(unsafe_code)]
extern crate merkle_tree;
#[macro_use]
extern crate clap;

mod utils;

use std::convert::AsMut;
use std::iter::FromIterator;
use std::cmp::min;
use std::env::args;
use std::fmt::Write as FmtWrite;
use std::thread;
use std::sync::mpsc::channel;

use chrono::Local;

use std::fs::File;
use std::io::{self, Write, BufWriter};
use std::path::{Path,PathBuf};
use walkdir::WalkDir;

use utils::Crc32;
use sha2::{Sha224, Sha256, Sha384, Sha512};

use clap::{App, Arg};
use indicatif::{ProgressBar, ProgressStyle};

arg_enum!{
    #[derive(PartialEq, Eq, Debug)]
    #[allow(non_camel_case_types)]
    enum HashFunctions {
        crc32,
        sha224,
        sha256,
        sha384,
        sha512
    }
}

fn abbreviate_filename(name: &str, len_threshold: usize) -> String {
    let name_chars = Vec::from_iter(name.chars());
    if name.len() <= len_threshold {
        // TODO: is copy avoidable?
        return name.to_owned();
    } else if len_threshold <= 3 {
        // Return the first 3 chars (*not* bytes)
        return name_chars[..3].iter().collect::<String>();
    } else {
        // Join the beginning and end part of the name with ellipses
        let filechar_count = len_threshold - 3;
        // Use subtraction to ensure consistent sum
        let end_half_len = filechar_count / 2;
        let begin_half_len = filechar_count - end_half_len;
        return [&name[..begin_half_len],
                "...",
                &name[name.len()-end_half_len..]].join("");
    }
}


pub fn arr_to_hex_str(arr: &[u8]) -> String {
    let mut return_str: String = "".to_string();
    for byte_val in arr {
        write!(return_str, "{:02x}", byte_val).unwrap();
    }
    return return_str;
}

fn main() {
    let status_code = run();
    std::process::exit(status_code);
}

fn run() -> i32 {
    let matches = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .arg(Arg::with_name("hash").long("hash-function").short("f")
            .takes_value(true)
            .default_value("sha256").possible_values(&HashFunctions::variants())
            .case_insensitive(true)
            .help("Hash function to use"))
        .arg(Arg::with_name("branch").long("branch-factor").short("b")
            .takes_value(true).default_value("4")
            .validator(|input_str| -> Result<(), String> {
                match input_str.parse::<u16>() {
                    Ok(0) | Ok(1) => Err("branch must be >= 2".to_string()),
                    Ok(_) => Ok(()),
                    Err(err) => Err(err.to_string())
                }
            })
            .help("Branch factor for tree"))
        .arg(Arg::with_name("blocksize").long("block-length").short("l")
            .takes_value(true).default_value("4096")
            .validator(|input_str| -> Result<(), String> {
                match input_str.parse::<u32>() {
                    Ok(0) => Err("blocksize must be positive".to_string()),
                    Ok(_) => Ok(()),
                    Err(err) => Err(err.to_string())
                }
            })
            .help("Block size to hash over, in bytes"))
        .arg(Arg::with_name("quiet").long("quiet").short("q")
            //.required_unless("output")
            .help("Hide the progress bar"))
        .arg(Arg::with_name("output").long("output").short("o")
            .takes_value(true)
            .help("Output file (default stdout)"))
        .arg(Arg::with_name("short").long("short").short("s")
            .help("Write only the summary hash")
            .long_help("Write only the summary hash to the output. This will make identifying corrupted locations impossible."))
        .arg(Arg::with_name("FILES").required(true)
            .multiple(true).last(true))
        .get_matches();

    // Unwraps succeeds because validators should already have caught errors
    let block_size = value_t!(matches, "blocksize", u32).unwrap();
    let branch_factor = value_t!(matches, "branch", u16).unwrap();
    let short_output = matches.is_present("short");
    let hash_enum = value_t!(matches, "hash", HashFunctions).unwrap();
    let mut file_list = Vec::<PathBuf>::new();
    for file_str in matches.values_of("FILES").unwrap() {
        let file_path = Path::new(file_str);
        if file_path.is_file() {
            file_list.push(file_path.to_path_buf());
        } else if file_path.is_dir() {
            // Walk directory to find all the files in it
            for entry in WalkDir::new(file_path).min_depth(1) {
                let entry_unwrap = entry.unwrap();
                let entry_path = entry_unwrap.path();
                if entry_path.is_file() {
                    file_list.push(entry_path.to_path_buf());
                }
            }
        } else {
            eprintln!("Error: file {} does not exist", file_str);
            return 1;
        }
    }

    let mut out_file: Box<dyn Write + Send> = match matches.value_of("output") {
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
    let write_handle = out_file.as_mut();
    writeln!(write_handle, "{} v{}", crate_name!(), crate_version!()).unwrap();
    write!(write_handle, "Arguments: ").unwrap();
    // Scope the argument iteration variables
    {
        let mut arg_iter = args();
        {
            let argv_0 = arg_iter.next().unwrap();
            let binary_name = Path::new(argv_0.as_str())
                    .file_name().unwrap().to_str().unwrap();
            // Write the binary name (skipping directory parts)
            write!(write_handle, "{}", binary_name).unwrap();
        }
        for arg in arg_iter.take_while(|arg_val| {arg_val != "--"}) {
            write!(write_handle, " ").unwrap();
            write!(write_handle, "{}", arg).unwrap();
        }
        write!(write_handle, "\n").unwrap();
    }
    writeln!(write_handle, "Started {}", Local::now().to_rfc2822()).unwrap();
    write_handle.flush().unwrap();

    if !short_output {
        writeln!(write_handle, "Files:").unwrap();
        for (index, file_name) in file_list.iter().enumerate() {
            writeln!(write_handle, "{} {}",
                    index, file_name.to_str().unwrap()).unwrap();
        }
    }
    writeln!(write_handle, "Hashes:").unwrap();
    write_handle.flush().unwrap();

    let merkle_tree_thunk = match hash_enum {
        HashFunctions::crc32 => merkle_tree::merkle_hash_file::<Crc32>,
        HashFunctions::sha224 => merkle_tree::merkle_hash_file::<Sha224>,
        HashFunctions::sha256 => merkle_tree::merkle_hash_file::<Sha256>,
        HashFunctions::sha384 => merkle_tree::merkle_hash_file::<Sha384>,
        HashFunctions::sha512 => merkle_tree::merkle_hash_file::<Sha512>,
    };
    if hash_enum == HashFunctions::crc32 {
        eprintln!("Warning: CRC32 is not cryptographically secure and will only prevent accidental corruption");
    }
    for (file_index, file_name) in file_list.iter().enumerate() {
        let file_obj = match File::open(file_name.to_owned()) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Error opening file {} for reading: {}",
                    file_name.to_str().unwrap(), err);
                return 1
            }
        };
        let pb_len = merkle_tree::node_count(file_obj.metadata().unwrap().len(), block_size, branch_factor);
        let pb = match matches.is_present("quiet") {
            false => ProgressBar::new(pb_len),
            true => ProgressBar::hidden()
        };
        let pb_style = ProgressStyle::default_bar()
            .template("{msg:25!} {pos:>8}/{len:8} | {per_sec:>8} [{elapsed_precise}] ETA [{eta_precise}]");
        // Scope ProgressBar setup
        {
            pb.set_style(pb_style);
            let file_part = Path::new(&file_name).file_name().unwrap()
                    .to_str().unwrap();
            let abbreviated_msg = abbreviate_filename(file_part, 25);
            assert!(abbreviated_msg.len() <= 25);
            pb.set_message(&abbreviated_msg);
            pb.set_draw_delta(min(pb_len/100, 512));
            pb.tick();
        }

        let (tx, rx) = channel::<merkle_tree::HashRange>();
        let thread_handle = thread::Builder::new()
            .name(String::from(file_name.to_str().unwrap()))
            .spawn(move || {
                merkle_tree_thunk(file_obj, block_size, branch_factor, tx)
            })
            .unwrap();
        for block_hash in rx.into_iter() {
            pb.inc(1);
            if !short_output {
                // {file_index} [{tree_block_start}-{tree_block_end}] [{file_block_start}-{file_block_end}] {hash}
                writeln!(write_handle,"{:3} {} {} {}",
                    file_index,
                    block_hash.block_range,
                    block_hash.byte_range,
                    arr_to_hex_str(&block_hash.hash_result)).unwrap();
            }
            thread::yield_now();
        }
        let final_hash = thread_handle.join().unwrap();
        if short_output {
            writeln!(write_handle, "{}  {}",
                arr_to_hex_str(final_hash.as_ref()),
                file_name.to_str().unwrap()).unwrap();
        }
        write_handle.flush().unwrap();
        if !matches.is_present("quiet") {
            assert_eq!(pb.position(), pb.length());
        }
        pb.finish_at_current_pos();

    }
    return 0;
}
