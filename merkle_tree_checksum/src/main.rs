#![forbid(unsafe_code)]
extern crate merkle_tree;
#[macro_use]
extern crate clap;

extern crate enquote;

mod crc32_utils;
mod utils;
mod error_types;
mod format_functions;
mod parse_functions;

use std::thread;
use crossbeam_channel::bounded as bounded_channel;

use std::fs::{File, OpenOptions};
use std::io::{Write, Seek, SeekFrom, BufRead, BufReader, LineWriter};

use semver::VersionReq;
use parse_functions::{extract_long_hash_parts, extract_short_hash_parts, size_str_to_num};
use std::path::{Path,PathBuf};
use format_functions::{escape_chars, title_center, abbreviate_filename};

use crc32_utils::Crc32;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512_224, Sha512_256};
use sha3::{Sha3_224, Sha3_256, Sha3_384, Sha3_512};
use blake2::{Blake2b512, Blake2s256};
use blake3::Hasher as Blake3;

use merkle_tree::{merkle_hash_file, merkle_block_generator};
use merkle_tree::HashRange;
use merkle_tree::{branch_t, block_t};
use merkle_tree::reorder_hashrange_iter;

use utils::HashFunctions;
use utils::StoredAndComputed;
use utils::TreeParams;
use utils::ChannelOrPb;
use error_types::{PreHashError, HeaderParsingErr, VerificationError};

use std::convert::TryFrom;

use const_format::formatcp;

use clap::{Command, Arg, ArgAction, ArgMatches};
use clap::builder::EnumValueParser;

use indicatif::{ProgressBar, ProgressStyle, ProgressDrawTarget, MultiProgress};
use git_version::git_version;

const GENERATE_HASH_CMD_NAME: &str = "generate-hash";
const VERIFY_HASH_CMD_NAME: &str = "verify-hash";

const EMPTY_STRING: String = String::new();

const HELP_STR_HASH_LIST: &str = concat!("Supported hash functions are ",
    "the SHA2 family, the SHA3 family, Blake2b/Blake2s, Blake3, ",
    "and CRC32.");

const CMDLINE_ERR: i32 = 1;
const DATA_READ_ERR: i32 = 2;
const GEN_WRITE_ERR: i32 = 101; // Same exitcode as panic
const VERIF_READ_ERR: i32 = 101; // Same exitcode as panic
const VERIF_BAD_HEADER_ERR: i32 = 1;
const VERIF_BAD_ENTRY_ERR: i32 = 3;

const VERSION_STR: &str = formatcp!("{} ({}, rustc {})", crate_version!(),
            git_version!(prefix = "git:", fallback = "unknown"),
            env!("RUSTC_VERSION_STR"));

// Use Options for inside because we know variant before we have the inside
#[derive(Debug)]
enum HashCommand<W, R>
where
    W: Write+Send+std::fmt::Debug,
    R: BufRead+Seek+Send+std::fmt::Debug
{
    GenerateHash(Option<W>),
    VerifyHash(Option<R>)
}

fn main() {
    let status_code = run();
    std::process::exit(status_code);
}

fn parse_cli() -> Result<ArgMatches, clap::Error> {
    let gen_hash_after_help = HELP_STR_HASH_LIST.to_owned()
        +concat!(" sha512-based hashes ",
        "(sha384, sha512, sha512_224, and sha512_256) ",
        "can be significantly faster than sha256-based hashes ",
        "(sha224 and sha256) ",
        "on 64-bit systems that lack SHA hardware acceleration.");

    let gen_hash_command = Command::new(GENERATE_HASH_CMD_NAME)
        .about("Generates Merkle tree hashes")
        .after_help(gen_hash_after_help)
        .arg(Arg::new("hash").long("hash-function").short('f')
            .action(ArgAction::Set)
            .value_parser(EnumValueParser::<HashFunctions>::new())
            .default_value("sha256")
            .ignore_case(true)
            .help("Hash function to use"))
        .arg(Arg::new("branch").long("branch-factor").short('b')
            .action(ArgAction::Set)
            .default_value("4")
            .value_parser(clap::value_parser!(branch_t).range(2..))
            .help("Branch factor for tree"))
        .arg(Arg::new("blocksize").long("block-length").short('l')
            .action(ArgAction::Set)
            .default_value("4096")
            .value_parser(size_str_to_num)
            .help("Block size to hash over, in bytes")
            .long_help(concat!("Block size to hash over, in bytes ",
                "(SI prefixes K,M,G and IEC prefixes Ki,Mi,Gi accepted")))
        .arg(Arg::new("output").long("output").short('o')
            .action(ArgAction::Set)
            .required(true)
            .help("Output file"))
        .arg(Arg::new("overwrite").long("overwrite")
            .action(ArgAction::SetTrue)
            .help("Overwrite output file if it already exists"))
        .arg(Arg::new("short").long("short").short('s')
            .action(ArgAction::SetTrue)
            .help("Write only the summary hash")
            .long_help(concat!("Write only the summary hash to the output. ",
                "This will make identifying corrupted locations impossible.")))
        .arg(Arg::new("FILES").required(true)
            .action(ArgAction::Append)
            .last(true)
            .num_args(1..=u16::MAX.into())
            .help("Files to hash"));
    let check_hash_command = Command::new(VERIFY_HASH_CMD_NAME)
        .about("Verify Merkle tree hashes")
        .arg(Arg::new("failfast").long("fail-fast")
            .action(ArgAction::SetTrue)
            .help("Bail immediately on hash mismatch")
            .long_help(concat!("Skip checking the rest of the files ",
                "when a hash mismatch is detected.")))
        .arg(Arg::new("FILE").required(true)
            .action(ArgAction::Set)
            .help("File containing the hashes to check"));

    let clap_app = Command::new(crate_name!())
        .version(VERSION_STR)
        .author(crate_authors!())
        .about(crate_description!())
        .after_help(HELP_STR_HASH_LIST)
        .subcommand_required(true)
        .arg(Arg::new("quiet").long("quiet").short('q')
            .action(ArgAction::Count)
            .help("Print less text")
            .long_help(concat!("Specify once to hide progress bars. ",
                "Specify twice to suppress all output besides errors.")))
        .arg(Arg::new("jobs").long("jobs").short('j')
            .action(ArgAction::Set)
            .default_value("4")
            .value_parser(clap::value_parser!(usize))
            .help("Specify size of thread pool for hashing (set to 0 to disable)")
            .long_help(concat!(
                "Specify size of thread pool for hashing. ",
                "It is recommended to leave at least one CPU free ",
                "for the main thread to read/write hashes. ",
                "Adding more than 2 threads does not improve performance ",
                "when I/O is the program bottleneck."
            )))
        .subcommand(gen_hash_command)
        .subcommand(check_hash_command);
    clap_app.try_get_matches()
}

fn run() -> i32 {
    let matches_result = parse_cli();
    if let Err(e) = matches_result {
        // Mirror e.exit, but use scoping to call destructors
        e.print().expect("Failed to print CMD parse error");
        return CMDLINE_ERR;
    }
    let matches = matches_result.unwrap();

    let (mut cmd_chosen, cmd_matches): (HashCommand<_,_>, ArgMatches)
            = match matches.subcommand() {
        Some((GENERATE_HASH_CMD_NAME, gencmd_matches)) => 
                (HashCommand::GenerateHash(None), gencmd_matches.clone()),
        Some((VERIFY_HASH_CMD_NAME, verify_matches)) =>
                (HashCommand::VerifyHash(None), verify_matches.clone()),
        _ => panic!("Invalid or missing subcommand detected")
    };

    let mut hashing_final_status = 0;

    let (file_list_result, tree_params, short_output, verify_start_pos):
            (Vec<(String, Option<PreHashError>)>, TreeParams, bool, Option<u64>)
            = match cmd_chosen {
        HashCommand::GenerateHash(None) => {
            let file_vec: Vec<_> = cmd_matches.get_many::<String>("FILES").unwrap().collect();
            // Validators should already have caught errors
            (
                {
                    let mut collect_vec: Vec<_> = Vec::with_capacity(
                        file_vec.len());
                    for file_path in file_vec {
                        match utils::str_to_files(file_path) {
                            Some(paths) => {
                                for path in paths {
                                    match File::open(&path) {
                                        Ok(_) => collect_vec.push((path.to_string_lossy().into_owned(), None)),
                                        Err(_) => collect_vec.push((path.to_string_lossy().into_owned(), Some(PreHashError::ReadPermissionError)))
                                    }
                                }
                            },
                            None => collect_vec.push((file_path.to_owned(), Some(PreHashError::FileNotFound)))
                        }
                    };
                    collect_vec
                },
                // unwraps will always succeed due to default values
                TreeParams {
                    // block_size has a special parser invoked in parse_cli
                    block_size: *cmd_matches.get_one("blocksize").unwrap(),
                    branch_factor: *cmd_matches.get_one("branch").unwrap(),
                    hash_function: *cmd_matches.get_one("hash").unwrap()
                },
                cmd_matches.get_flag("short"),
                None
            )
        },
        HashCommand::VerifyHash(None) => {
            let hash_file_str = cmd_matches.get_one::<String>("FILE").unwrap();
            let hash_file = match File::open(hash_file_str) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Error opening hash file {}: {}",
                            hash_file_str, e);
                    return VERIF_READ_ERR;
                }
            };
            let mut hash_file_reader = BufReader::new(hash_file);

            let mut file_vec: Vec<(String, Option<PreHashError>)> = Vec::new();
            // Parse version number
            let mut version_line = String::new();
            let version_read_result = hash_file_reader.read_line(&mut version_line);
            if version_read_result.is_err() {
                eprintln!("Error: unable to read in version line");
                return VERIF_READ_ERR;
            }
            match parse_functions::parse_version_line(&version_line) {
                Ok(version) => {
                    // TODO: Do more precise version checking later
                    let range_str = ">=0.5, <0.7";
                    let recognized_range = VersionReq::parse(range_str).unwrap();
                    if !recognized_range.matches(&version) {
                        eprintln!("Error: hash file has unsupported version {}", version);
                        return VERIF_BAD_HEADER_ERR;
                    }
                },
                Err(e) => match e {
                    HeaderParsingErr::MalformedFile => {
                        eprintln!("Error: hash file is malformed: unable to parse version line");
                        return VERIF_BAD_HEADER_ERR;
                    },
                    HeaderParsingErr::MalformedVersion(s) => {
                        eprintln!("Error: hash file has malformed version {}",s);
                        return VERIF_BAD_HEADER_ERR;
                    }
                    _ => unreachable!()
                }
            }
            // Read in the next three lines
            let mut hash_param_arr = [EMPTY_STRING; 3];
            for param_str in hash_param_arr.iter_mut() {
                let mut line = String::new();
                let line_result = hash_file_reader.read_line(&mut line);
                if line_result.is_ok() {
                    assert!(line.ends_with('\n'));
                    if &line[line.len()-2..line.len()-1] == "\r" {
                        // \r\n ending
                        *param_str = line[..line.len()-2].to_string();
                    } else {
                        // \n ending
                        *param_str = line[..line.len()-1].to_string();
                    }
                } else {
                    eprintln!("Error: unable to read in parameter line");
                    return VERIF_READ_ERR;
                }
            }
            let tree_param_result = TreeParams::from_lines(&hash_param_arr);
            if let Err(other_errors) = tree_param_result {
                for error in other_errors {
                    eprintln!("Error: {}", error);
                }
                return VERIF_BAD_HEADER_ERR;
            }

            let mut format_line = String::new();
            let format_line_result = hash_file_reader.read_line(&mut format_line);
            if format_line_result.is_err() {
                eprintln!("Error: hash file is malformed: unable to read hashes or file list");
                return VERIF_READ_ERR;
            }
            let is_short_hash = match format_line.as_str() {
                "Hashes:\n" | "Hashes:\r\n" => true,
                "Files:\n" | "Files:\r\n" => false,
                _ => {
                    eprintln!("Error: hash file is malformed: file should have file list or hash list");
                    return VERIF_BAD_HEADER_ERR;
                }
            };
            let list_begin_pos: Option<u64> = match is_short_hash {
                true => Some(
                    hash_file_reader.stream_position().unwrap()
                ),
                false => None
            };
            loop {
                let mut next_line = String::new();
                let next_line_result = hash_file_reader.read_line(&mut next_line);
                if let Err(read_err) = next_line_result {
                    if read_err.kind() == std::io::ErrorKind::UnexpectedEof {
                        if !is_short_hash {
                            eprintln!("Error: unexpected EOF reading hashes");
                            return VERIF_BAD_HEADER_ERR;
                        }
                    } else {
                        eprintln!("Error: Error in reading file: {}", read_err);
                        return VERIF_READ_ERR;
                    }
                }
                if let Ok((quoted_name, len_option)) = parse_functions::extract_quoted_filename(&next_line) {
                    assert_eq!(len_option.is_none(), is_short_hash);
                    let unquoted_name = match enquote::unquote(quoted_name) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("Error: unable to unquote file name {}: {}",
                                quoted_name, e);
                            if is_short_hash {
                                return VERIF_BAD_ENTRY_ERR;
                            } else {
                                return VERIF_BAD_HEADER_ERR;
                            }
                        }
                    };
                    let path = PathBuf::from(unquoted_name);
                    if path.is_file() {
                        if File::open(&path).is_err() {
                            // We already checked file existence
                            file_vec.push((path.to_string_lossy().into_owned(),
                                Some(PreHashError::ReadPermissionError)))
                        } else if let Some(expected_len) = len_option {
                            let actual_len = path.metadata().unwrap().len();
                            if actual_len == expected_len {
                                file_vec.push((path.to_string_lossy().into_owned(), None));
                            } else {
                                let mismatch_len_obj = StoredAndComputed::new
                                    (expected_len, actual_len);
                                file_vec.push((
                                    path.to_string_lossy().into_owned(),
                                    Some(PreHashError::MismatchedLength(
                                        mismatch_len_obj
                                    )))
                                )
                            }
                        } else {
                            file_vec.push((path.to_string_lossy().into_owned(), None))
                        }
                    } else {
                        file_vec.push(
                            (
                                path.to_string_lossy().into_owned(),
                                Some(PreHashError::FileNotFound))
                            )
                    }
                } else if next_line == "Hashes:\n" || next_line == "Hashes:\r\n" {
                    assert!(!is_short_hash);
                    break;
                } else if next_line.is_empty() {
                    assert!(is_short_hash);
                    break;
                } else {
                    eprintln!("Error: encountered malformed file entry {:?}",
                        next_line);
                    return VERIF_BAD_HEADER_ERR;
                }
            }
            assert!(is_short_hash == list_begin_pos.is_some());
            if let Some(seek_pos) = list_begin_pos {
                hash_file_reader.seek(SeekFrom::Start(seek_pos)).unwrap();
            }

            (
                file_vec,
                tree_param_result.unwrap(),
                is_short_hash,
                // We want to ensure that the seek call succeeded
                Some(hash_file_reader.stream_position().unwrap())
            )
        },
        _ => unreachable!()
    };
    let mut abort: Result<(), i32> = Ok(());
    // Bool is whether to process this file or not
    let file_list: Vec<(PathBuf, bool)> = file_list_result.into_iter().map(|(path_str, err_opt)| {
        if let Some(err) = err_opt {
            eprintln!("Error with file {}: {}",
                    path_str, err);
            hashing_final_status = 1;
            match err {
                PreHashError::MismatchedLength(_) => {
                    assert!(matches!(cmd_chosen, HashCommand::VerifyHash(_)));
                    if cmd_matches.get_flag("failfast") {
                        abort = Err(VERIF_BAD_ENTRY_ERR);
                    }
                },
                PreHashError::FileNotFound => {
                    if !matches!(cmd_chosen, HashCommand::VerifyHash(_)) {
                        abort = Err(DATA_READ_ERR);
                    }
                },
                PreHashError::ReadPermissionError => {
                    abort = Err(DATA_READ_ERR);
                }
            };
            (PathBuf::from(path_str), false)
        } else {
            (PathBuf::from(path_str), true)
        }
    }).collect();
    if let Err(exit_code) = abort {
        return exit_code;
    }

    let quiet_count = matches.get_count("quiet");

    // unwrap always succeeds because "jobs" has a default value
    let thread_count = *matches.get_one::<usize>("jobs")
        .unwrap();

    let hash_enum: HashFunctions = tree_params.hash_function;
    let block_size: block_t = tree_params.block_size;
    let branch_factor: branch_t = tree_params.branch_factor;
    // TODO: use the duplicate crate for macro-ing this?
    let merkle_tree_thunk = match hash_enum {
        HashFunctions::crc32 =>
            merkle_hash_file::<_,Crc32,_>,
        HashFunctions::sha224 =>
            merkle_hash_file::<_,Sha224,_>,
        HashFunctions::sha256 =>
            merkle_hash_file::<_,Sha256,_>,
        HashFunctions::sha384 =>
            merkle_hash_file::<_,Sha384,_>,
        HashFunctions::sha512 =>
            merkle_hash_file::<_,Sha512,_>,
        HashFunctions::sha512_224 =>
            merkle_hash_file::<_,Sha512_224,_>,
        HashFunctions::sha512_256 =>
            merkle_hash_file::<_,Sha512_256,_>,
        HashFunctions::sha3_224 => merkle_hash_file::<_,Sha3_224,_>,
        HashFunctions::sha3_256 => merkle_hash_file::<_,Sha3_256,_>,
        HashFunctions::sha3_384 => merkle_hash_file::<_,Sha3_384,_>,
        HashFunctions::sha3_512 => merkle_hash_file::<_,Sha3_512,_>,
        HashFunctions::blake2b_512 => merkle_hash_file::<_,Blake2b512,_>,
        HashFunctions::blake2s_256 => merkle_hash_file::<_,Blake2s256,_>,
        HashFunctions::blake3 => merkle_hash_file::<_,Blake3,_>
    };
    let expected_hash_len = hash_enum.hash_len();

    if quiet_count < 2 && hash_enum == HashFunctions::crc32
            && matches!(cmd_chosen, HashCommand::GenerateHash(_)) {
        eprintln!("Warning: CRC32 is not cryptographically secure and will only prevent accidental corruption");
    }
    if quiet_count < 2 && matches!(cmd_chosen, HashCommand::VerifyHash(_))
            && !short_output && !cmd_matches.get_flag("failfast") {
        eprintln!(
            concat!("Warning: Verification of long hashes may fail early ",
                "if the hash file is malformed, ",
                "even when --fail-fast is not specified")
        );
    }

    match cmd_chosen {
        HashCommand::GenerateHash(None) => {
            let write_file_name = cmd_matches.get_one::<String>("output").unwrap();
            let overwrite = cmd_matches.get_flag("overwrite");
            let open_result = match overwrite {
                true => OpenOptions::new().write(true).create(true)
                    .truncate(true).open(write_file_name),
                false => OpenOptions::new().write(true)
                    .create_new(true).open(write_file_name)
            };
            let mut file_handle = match open_result {
                Ok(file) => LineWriter::new(file),
                Err(err) => {
                    eprintln!("Error opening file {} for writing: {}",
                        write_file_name, err);
                    return GEN_WRITE_ERR;
                }
            };
            // Write file prelude
            writeln!(file_handle, "{} v{}", crate_name!(), crate_version!()).unwrap();
            // tree_params Display impl includes ending newline
            write!(file_handle, "{}", tree_params).unwrap();

            if !short_output {
                writeln!(file_handle, "Files:").unwrap();
                let list_str: Vec<String> = file_list.iter()
                    .filter_map(|(pathbuf, keep)| {
                        if *keep {
                            Some(pathbuf)
                        } else {
                            None
                        }
                    })
                    .map(|path| {
                        let path_metadata = path.metadata().unwrap();
                        (path.to_str().unwrap(), path_metadata.len())
                    })
                    .map(|(string, len)| {
                        let escaped_str = escape_chars(string);
                        let quoted_str = enquote::enquote('"', &escaped_str);
                        format!("{} {:#x} bytes", quoted_str, len)
                    })
                    .collect();
                writeln!(file_handle, "{}", list_str.join("\n")).unwrap();
            }
            writeln!(file_handle, "Hashes:").unwrap();
            file_handle.flush().unwrap();

            debug_assert!(verify_start_pos.is_none());
            cmd_chosen = HashCommand::GenerateHash(Some(file_handle));
        },
        HashCommand::VerifyHash(None) => {
            let read_file_name = cmd_matches.get_one::<String>("FILE").unwrap();
            let mut hash_file = match File::open(read_file_name) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Error opening hash file {}: {}",
                            read_file_name, e);
                    return VERIF_READ_ERR;
                }
            };
            hash_file.seek(SeekFrom::Start(verify_start_pos.unwrap())).unwrap();
            cmd_chosen = HashCommand::VerifyHash(Some(BufReader::new(hash_file)))
        },
        _ => unreachable!()
    };

    for (file_index, (file_name, process)) in file_list.iter().enumerate() {
        let filename_str = file_name.to_str().unwrap();
        if !process {
            if quiet_count <= 1 {
                if quiet_count == 0 {
                    eprintln!("{}", title_center(filename_str));
                    eprintln!("Warning: skipped");
                } else { // quiet_count == 1
                    // Extra newline to add space
                    eprintln!("Warning: skipping file {}", filename_str);
                }
            }
            if let HashCommand::VerifyHash(Some(ref mut r)) = cmd_chosen {
                if short_output {
                    let mut hash_line = String::new();
                    r.read_line(&mut hash_line).unwrap();
                    // Still check line format, and warn if entry is malformed
                    let hash_parts = extract_short_hash_parts(&hash_line,
                        2*expected_hash_len);
                    if let Ok((_, quoted_name)) = hash_parts {
                        assert_eq!(filename_str,
                            enquote::unquote(quoted_name).unwrap());
                    } else {
                        eprintln!("Warning skipping file {}: {}", filename_str,
                            VerificationError::MalformedEntry(hash_line));
                        if cmd_matches.get_flag("failfast") {
                            return VERIF_BAD_ENTRY_ERR;
                        }
                    }
                } else {
                    loop {
                        let mut hash_line = String::new();
                        let chars_read = r.read_line(&mut hash_line).unwrap();
                        let hash_parts = extract_long_hash_parts(&hash_line,
                            2*expected_hash_len);
                        if let Ok((read_index, _)) = hash_parts {
                            if read_index == file_index + 1 {
                                r.seek_relative(-i64::try_from(chars_read).unwrap()).unwrap();
                                break;
                            } else if read_index != file_index {
                                eprintln!("Error skipping file {}: {}",
                                    filename_str,
                                    VerificationError::MismatchedFileID);
                                return VERIF_BAD_ENTRY_ERR;
                            }
                        } else  if chars_read > 0 {
                            eprintln!("Error skipping file {}: {}",
                                filename_str,
                                VerificationError::MalformedEntry(hash_line));
                            return VERIF_BAD_ENTRY_ERR;
                        } else {
                            break; // EOF
                        }
                    }
                }
            }
            continue;
        }
        let file_obj = match File::open(file_name) {
            Ok(file) => file,
            Err(err) => {
                eprintln!("Error opening file {} for reading: {}",
                    filename_str, err);
                return DATA_READ_ERR;
            }
        };
        let file_size = file_obj.metadata().unwrap().len();
        let pb_hash_len = merkle_tree::node_count(file_size, block_size, branch_factor);
        let pb_file_style = ProgressStyle::default_bar()
            // 4 = max length of message strings below
            .template("{msg:4} {bar:20} {bytes:>11}/{total_bytes:11} | {bytes_per_sec:>12}")
            .unwrap();
        let pb_hash_style = ProgressStyle::default_bar()
            .template("{msg:4} {bar:20} {pos:>11}/{len:11} | {per_sec:>12} [{elapsed_precise}] ETA [{eta}]")
            .unwrap();

        let pb_holder = MultiProgress::new();
        let pb_file = pb_holder.add(ProgressBar::new(file_size));
        let pb_hash = pb_holder.add(ProgressBar::new(pb_hash_len));

        if quiet_count >= 1 {
            if quiet_count == 1 {
                eprintln!("Hashing {}...", filename_str);
            }
            pb_holder.set_draw_target(ProgressDrawTarget::hidden());
        } else { // quiet_count == 0
            pb_holder.set_draw_target(ProgressDrawTarget::stderr_with_hz(5));
            pb_hash.set_style(pb_hash_style);
            pb_file.set_style(pb_file_style);

            let file_part = Path::new(&file_name).file_name().unwrap()
                    .to_str().unwrap();

            // Leave a padding of at least 3 equal signs on each side
            // TODO: use fixed width, or scale with terminal size?
            let abbreviated_msg = abbreviate_filename(file_part, 80-8);
            eprintln!("{}", title_center(&abbreviated_msg));

            pb_file.set_message("File");
            pb_hash.set_message("Hash");
        }

        let (tx, rx, pb_hash): (ChannelOrPb<_>, _, _) = match short_output {
            true => (pb_hash.into(), None, None),
            false => {
                let (tx, rx) = bounded_channel::<HashRange>(16);
                (tx.into(), Some(rx), Some(pb_hash))
            }
        };
        let thread_handle = thread::Builder::new()
            .name(String::from(filename_str))
            .spawn(move || {
                /*let buf_size: usize = (block_size*(branch_factor as block_t))
                    .clamp(4*1024, 256*1024).try_into().unwrap();
                let file_buf = BufReader::with_capacity(
                    buf_size, file_obj);*/
                // Don't use BufReader because of a bad interaction with stream_position and seeks flushing the buffer
                // See merkle_utils::read_into_slice and https://github.com/rust-lang/rust/issues/86832 for details
                // Addition of the seek parameter *should* be a workaround 
                // Do more testing and benchmarking later
                // TODO: use rustversion cfg once this is fixed
                let pb_wrap = pb_file.wrap_read(file_obj);
                let result = merkle_tree_thunk(pb_wrap,
                    block_size, branch_factor, tx, thread_count);
                pb_file.finish();
                result
            })
            .unwrap();

        let mut hash_loop_status: Result<(), VerificationError> = Ok(());

        if let Some(rx) = rx {
            let block_iter = merkle_block_generator(
                file_size, block_size, branch_factor).into_iter();
            for block_hash in reorder_hashrange_iter(block_iter, rx.into_iter()) {
                if let Some(ref pb_hash) = pb_hash {
                    pb_hash.inc(1);
                }
                match &mut cmd_chosen {
                    HashCommand::GenerateHash(Some(w)) => {
                        writeln!(w, "{:3} {} {} {}",
                            file_index,
                            block_hash.block_range(),
                            block_hash.byte_range(),
                            hex::encode(block_hash.hash_result())
                        ).unwrap();
                    }
                    HashCommand::VerifyHash(Some(r)) => {
                        let mut line = String::new();
                        let line_len = r.read_line(&mut line).unwrap();
                        if line_len == 0 {
                            hash_loop_status = Err(VerificationError::UnexpectedEof);
                                break;
                        }

                        let hash_parts = extract_long_hash_parts(
                            &line, 2*expected_hash_len);
                        if let Ok((file_id, file_hash_range)) = hash_parts {
                            if file_id != file_index {
                                hash_loop_status = Err(VerificationError::MismatchedFileID);
                                break;
                            }
                            if block_hash.block_range() != file_hash_range.block_range() {
                                hash_loop_status = Err(VerificationError::MismatchedBlockRange(StoredAndComputed::new(file_hash_range.block_range(), block_hash.block_range())));
                                break;
                            }
                            if block_hash.byte_range() != file_hash_range.byte_range() {
                                hash_loop_status = Err(VerificationError::MismatchedByteRange(StoredAndComputed::new(file_hash_range.byte_range(), block_hash.byte_range())))
                            }
                            if block_hash.hash_result() != file_hash_range.hash_result() {
                                let file_hash_box = file_hash_range.hash_result().to_vec().into_boxed_slice();
                                let block_hash_box = block_hash.hash_result().to_vec().into_boxed_slice();
                                hash_loop_status = Err(VerificationError::MismatchedHash(Some(block_hash.byte_range()), StoredAndComputed::new(file_hash_box,block_hash_box)));
                                break;
                            }
                        } else {
                            hash_loop_status = Err(VerificationError::MalformedEntry(line));
                            break;
                        }
                    }
                    _ => unreachable!()
                }
                thread::yield_now();
            }
        }

        if let Some(ref pb_hash) = pb_hash {
            pb_hash.finish();

            if quiet_count == 0 && hash_loop_status.is_ok() {
                assert_eq!(pb_hash.position(), pb_hash.length().unwrap());
            }
        }
        let final_hash_option = thread_handle.join().unwrap();

        if short_output {
            /*
             * Only using final result for short output
             * A None result means the channel hung up
             * This is only possible in long mode when an error occurs
             */
            let final_hash = final_hash_option.unwrap();
            match &mut cmd_chosen {
                HashCommand::GenerateHash(Some(w)) => {
                    let escaped_filename = escape_chars(filename_str);
                    writeln!(w, "{}  {}",
                        hex::encode(final_hash),
                        enquote::enquote('"', &escaped_filename)).unwrap();
                    w.flush().unwrap();
                },
                HashCommand::VerifyHash(Some(r)) => {
                    let mut line = String::new();
                    r.read_line(&mut line).unwrap();

                    let hash_parts = extract_short_hash_parts(&line, 2*expected_hash_len);
                    if let Ok((file_hash_box, quoted_name)) = hash_parts {
                        assert_eq!(filename_str,
                            enquote::unquote(quoted_name).unwrap());
                        if final_hash == file_hash_box {
                            hash_loop_status = Ok(());
                        } else {
                            hash_loop_status = Err(VerificationError::MismatchedHash(None, StoredAndComputed::new(file_hash_box, final_hash)));
                        }
                    } else {
                        hash_loop_status = Err(VerificationError::MalformedEntry(line));
                    }
                },
                _ => unreachable!()
            }
        }
        match hash_loop_status {
            Ok(_) => {
                if quiet_count < 2 {
                    match cmd_chosen {
                        HashCommand::GenerateHash(_) => {
                            if quiet_count == 1 {
                                eprintln!("Done")
                            }
                        },
                        HashCommand::VerifyHash(_) => {
                            eprintln!("Info: {} hash matches", filename_str)
                        }
                    }
                }
            },
            Err(err) => {
                eprintln!("Error verifying file {}: {}", filename_str, err);
                // TODO: error recovery when not using failfast
                if cmd_matches.get_flag("failfast") || !short_output {
                    return VERIF_BAD_ENTRY_ERR;
                }
                // Long output and failfast not specified
                match err {
                    VerificationError::MismatchedHash(..)
                    | VerificationError::MalformedEntry(..) => {
                        hashing_final_status = VERIF_BAD_ENTRY_ERR;
                        continue;
                    }
                    _ => {return VERIF_BAD_ENTRY_ERR;}
                }
            }
        }
    }
    // Consume hash_file_handle to ensure it isn't used again
    if let HashCommand::VerifyHash(Some(mut r)) = cmd_chosen {
        // Check if at EOF
        let current_pos = r.stream_position().unwrap();
        let end_pos = r.seek(SeekFrom::End(0)).unwrap();
        if current_pos != end_pos {
            eprintln!("Error: hash file has extra lines left over");
            return VERIF_BAD_ENTRY_ERR;
        }
    }
    return hashing_final_status;
}
