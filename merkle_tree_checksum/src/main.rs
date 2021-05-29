#![forbid(unsafe_code)]
extern crate merkle_tree;
#[macro_use]
extern crate clap;

extern crate enquote;

mod crc32_utils;
mod utils;

use std::convert::AsMut;
use std::iter::FromIterator;
use std::cmp::min;
use std::thread;
use std::sync::mpsc;

use chrono::Local;

use std::fs::File;
use std::io::{self, Write, BufWriter};
use std::path::{Path,PathBuf};

use crc32_utils::Crc32;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};
use merkle_tree::merkle_hash_file;
use utils::MpscConsumer;

use clap::{App, AppSettings, Arg, SubCommand, ArgMatches};
use indicatif::{ProgressBar, ProgressStyle};

arg_enum!{
    #[derive(PartialEq, Eq, Debug, Clone, Copy)]
    #[allow(non_camel_case_types)]
    enum HashFunctions {
        crc32,
        sha224,
        sha256,
        sha384,
        sha512,
        sha512trunc224,
        sha512trunc256
    }
}

const GENERATE_HASH_CMD_NAME: &str = "generate-hash";
const VERIFY_HASH_CMD_NAME: &str = "verify-hash";

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum HashCommand {
    GenerateHash,
    VerifyHash
}

fn main() {
    let status_code = run(&mut std::env::args_os());
    std::process::exit(status_code);
}

pub(crate) fn run(argv: &mut dyn Iterator<Item = std::ffi::OsString>) -> i32 {
    let gen_hash_command = SubCommand::with_name(GENERATE_HASH_CMD_NAME)
        .about("Generates Merkle tree hashes")
        .setting(AppSettings::UnifiedHelpMessage)
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
        .arg(Arg::with_name("output").long("output").short("o")
            .takes_value(true)
            .help("Output file (default stdout)"))
        .arg(Arg::with_name("short").long("short").short("s")
            .help("Write only the summary hash")
            .long_help("Write only the summary hash to the output. This will make identifying corrupted locations impossible."))
        .arg(Arg::with_name("FILES").required(true)
            .multiple(true).last(true));
    let check_hash_command = SubCommand::with_name(VERIFY_HASH_CMD_NAME)
        .about("Verify Merkle tree hashes")
        .setting(AppSettings::UnifiedHelpMessage)
        .arg(Arg::with_name("output").long("output").short("o")
            .takes_value(true)
            .help("Output file (default stdout)"))
        .arg(Arg::with_name("FILE").required(true)
            .help("File containing the hashes to check"));

    let clap_app = App::new(crate_name!())
        .version(crate_version!())
        .author(crate_authors!())
        .about(crate_description!())
        .setting(AppSettings::SubcommandRequired)
        .setting(AppSettings::VersionlessSubcommands)
        .setting(AppSettings::UnifiedHelpMessage)
        .arg(Arg::with_name("quiet").long("quiet").short("q")
            .help("Hide the progress bar"))
        .subcommand(gen_hash_command)
        .subcommand(check_hash_command);

    let matches = clap_app.get_matches_from(argv);

    let (cmd_chosen, cmd_matches): (HashCommand, ArgMatches)
            = match matches.subcommand() {
        (GENERATE_HASH_CMD_NAME, Some(gencmd_matches)) => 
                (HashCommand::GenerateHash, gencmd_matches.clone()),
        (VERIFY_HASH_CMD_NAME, Some(verify_matches)) =>
                (HashCommand::VerifyHash, verify_matches.clone()),
        (_, _) => panic!("Invalid subcommand detected")
    };

    let (file_list_result, block_size, branch_factor, short_output, hash_enum):
            (Result<Vec<PathBuf>, String>, u32, u16, bool, HashFunctions)
            = match cmd_chosen {
        HashCommand::GenerateHash => {
            let file_vec = cmd_matches.values_of("FILES").unwrap().collect();
            // Validators should already have caught errors
            (
                utils::get_file_list(file_vec),
                value_t!(cmd_matches, "blocksize", u32)
                    .unwrap_or_else(|e| e.exit()),
                value_t!(cmd_matches, "branch", u16)
                    .unwrap_or_else(|e| e.exit()),
                cmd_matches.is_present("short"),
                value_t!(cmd_matches, "hash", HashFunctions)
                    .unwrap_or_else(|e| e.exit())
            )
        },
        HashCommand::VerifyHash => {
            // TODO: parse input file to get options
            (
                todo!(),
                todo!(),
                todo!(),
                todo!(),
                todo!()
            )
        }
    };
    if file_list_result.is_err() {
        eprintln!("Error: file {} does not exist",
                file_list_result.unwrap_err());
        return 1;
    }
    let file_list = file_list_result.unwrap();

    // Further changes needed here, depends on verify command stuff
    let mut out_file: Box<dyn Write + Send + Sync> = match cmd_matches.value_of("output") {
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

    if cmd_chosen == HashCommand::GenerateHash {
        let write_handle = out_file.as_mut();
        writeln!(write_handle, "{} v{}", crate_name!(), crate_version!()).unwrap();
        writeln!(write_handle, "# Started {}", Local::now().to_rfc2822()).unwrap();
        writeln!(write_handle, "Hash function: {}", hash_enum).unwrap();
        writeln!(write_handle, "Block size: {}", block_size).unwrap();
        writeln!(write_handle, "Branching factor: {}", branch_factor).unwrap();
        write_handle.flush().unwrap();

        if !short_output {
            writeln!(write_handle, "Files:").unwrap();
            let list_str: Vec<String> = file_list.iter()
                .map(|path| path.to_str().unwrap())
                .map(|string| enquote::enquote('"', string))
                .collect();
            writeln!(write_handle, "{}", list_str.join(",\n")).unwrap();
        }
        writeln!(write_handle, "Hashes:").unwrap();
        write_handle.flush().unwrap();
    }

    type HashConsumer = MpscConsumer<merkle_tree::HashRange>;
    let merkle_tree_thunk = match hash_enum {
        HashFunctions::crc32 => merkle_hash_file::<Crc32,HashConsumer>,
        HashFunctions::sha224 => merkle_hash_file::<Sha224,HashConsumer>,
        HashFunctions::sha256 => merkle_hash_file::<Sha256,HashConsumer>,
        HashFunctions::sha384 => merkle_hash_file::<Sha384,HashConsumer>,
        HashFunctions::sha512 => merkle_hash_file::<Sha512,HashConsumer>,
        HashFunctions::sha512trunc224 => merkle_hash_file::<Sha512Trunc224,HashConsumer>,
        HashFunctions::sha512trunc256 => merkle_hash_file::<Sha512Trunc256,HashConsumer>,
    };

    if hash_enum == HashFunctions::crc32
            && cmd_chosen == HashCommand::GenerateHash {
        eprintln!("Warning: CRC32 is not cryptographically secure and will only prevent accidental corruption");
    }

    // TODO: Different actions when verifying a hash file
    let write_handle = out_file.as_mut();
    for (file_index, file_name) in file_list.iter().enumerate() {
        let filename_str = file_name.to_str().unwrap();
        let file_obj = match File::open(file_name.to_owned()) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Error opening file {} for reading: {}",
                    filename_str, err);
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
            let abbreviated_msg = utils::abbreviate_filename(file_part, 25);
            assert!(abbreviated_msg.len() <= 25);
            pb.set_message(&abbreviated_msg);
            pb.set_draw_delta(min(pb_len/100, 512));
            pb.tick();
        }

        let (tx, rx) = mpsc::channel::<merkle_tree::HashRange>();
        let tx_wrap = utils::MpscConsumer::new_async(tx);
        let thread_handle = thread::Builder::new()
            .name(String::from(filename_str))
            .spawn(move || {
                merkle_tree_thunk(file_obj, block_size, branch_factor, tx_wrap)
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
                    utils::arr_to_hex_str(&block_hash.hash_result)).unwrap();
            }
            thread::yield_now();
        }
        let final_hash = thread_handle.join().unwrap();
        if short_output {
            writeln!(write_handle, "{}  {}",
                utils::arr_to_hex_str(final_hash.as_ref()),
                enquote::enquote('"',filename_str)).unwrap();
        }
        write_handle.flush().unwrap();
        if !matches.is_present("quiet") {
            assert_eq!(pb.position(), pb.length());
        }
        pb.finish_at_current_pos();

    }
    return 0;
}
