#![forbid(unsafe_code)]
extern crate merkle_tree;
#[macro_use]
extern crate clap;

extern crate enquote;

mod crc32_utils;
mod utils;
mod parse_functions;

use std::thread;
use std::sync::mpsc;

use std::fs::{File, OpenOptions};
use hex::ToHex;
use std::io::{Write, Seek, SeekFrom, BufRead, BufReader, BufWriter};

use semver::VersionReq;
use parse_functions::{ParsingErrors, size_str_to_num,
    extract_short_hash_parts, extract_long_hash_parts};
use std::path::{Path,PathBuf};
use utils::escape_chars;

use crc32_utils::Crc32;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};

use merkle_tree::{merkle_hash_file, merkle_block_generator};
use merkle_tree::{BlockRange, HashRange};
use merkle_tree::{branch_t, block_t};
use merkle_tree::reorder_hashrange_iter;

use utils::HashFunctions;
use utils::StoredAndComputed;

use clap::{App, AppSettings, Arg, SubCommand, ArgMatches};
use indicatif::{ProgressBar, ProgressStyle,
    ProgressDrawTarget, MultiProgress};

const GENERATE_HASH_CMD_NAME: &str = "generate-hash";
const VERIFY_HASH_CMD_NAME: &str = "verify-hash";

#[derive(Debug)]
enum HashCommand<W, R>
where
    W: Write+Send+std::fmt::Debug,
    R: BufRead+Seek+Send+std::fmt::Debug
{
    GenerateHash(Option<W>),
    VerifyHash(Option<R>)
}

#[derive(PartialEq, Eq, Debug, Clone)]
enum VerificationError {
    MismatchedFileID, // No StoredAndComputed as this would not be helpful
    MismatchedBlockRange(StoredAndComputed<BlockRange>),
    MismatchedByteRange(StoredAndComputed<BlockRange>),
    // Range is byte range, which exists when verifying long hashes
    MismatchedHash(Option<BlockRange>, StoredAndComputed<Box<[u8]>>),
    MalformedEntry(String), // String is the malformed line
    UnexpectedEof
}
impl std::fmt::Display for VerificationError {
    fn fmt(&self, fmt: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Will be printed as "Error verifying file {name}: {err}\n"
        match self {
            Self::MismatchedFileID => write!(fmt, "found entry for different file"),
            Self::MismatchedBlockRange(s_c) => {
                write!(fmt, concat!("mismatched block range in entry:\n",
                    "  stored:   {}\n",
                    "  computed: {}"),
                    s_c.stored(), s_c.computed())
            }
            Self::MismatchedByteRange(s_c) => {
                write!(fmt, concat!("mismatched byte range in entry:\n",
                    "  stored:   {}\n",
                    "  computed: {}"),
                    s_c.stored(), s_c.computed())
            }
            Self::MismatchedHash(range_option, s_c) => {
                match range_option {
                    Some(range) => write!(fmt,
                        "hash mismatch over byte range {}:\n", range),
                    None => write!(fmt, "hash mismatch:\n")
                }?;
                write!(fmt, concat!(
                    "  stored:   {}\n",
                    "  computed: {}"),
                    Vec::<u8>::encode_hex::<String>(&s_c.stored().to_vec()),
                    Vec::<u8>::encode_hex::<String>(&s_c.computed().to_vec()))
            }
            Self::MalformedEntry(line) => {
                write!(fmt, "found malformed entry {}", line)
            }
            Self::UnexpectedEof => write!(fmt, "unexpected EOF")
        }
    }
}
impl std::error::Error for VerificationError {}

fn main() {
    let status_code = run();
    std::process::exit(status_code);
}

fn parse_cli<'a>() -> Result<ArgMatches<'a>, clap::Error> {
    let gen_hash_command = SubCommand::with_name(GENERATE_HASH_CMD_NAME)
        .about("Generates Merkle tree hashes")
        .setting(AppSettings::UnifiedHelpMessage)
        .after_help(concat!("Note: sha512-based hashes ",
            "(sha384, sha512, sha512trunc224, and sha512trunc256) ",
            "can be significantly faster than sha256-based hashes ",
            "(sha224 and sha256) ",
            "on 64-bit systems that lack SHA hardware acceleration."))
        .arg(Arg::with_name("hash").long("hash-function").short("f")
            .takes_value(true)
            .default_value("sha256").possible_values(&HashFunctions::variants())
            .case_insensitive(true)
            .help("Hash function to use"))
        .arg(Arg::with_name("branch").long("branch-factor").short("b")
            .takes_value(true).default_value("4")
            .validator(|input_str| -> Result<(), String> {
                match input_str.parse::<branch_t>() {
                    Ok(0) | Ok(1) => Err("branch must be >= 2".to_string()),
                    Ok(_) => Ok(()),
                    Err(err) => Err(err.to_string())
                }
            })
            .help("Branch factor for tree"))
        .arg(Arg::with_name("blocksize").long("block-length").short("l")
            .takes_value(true).default_value("4096")
            .validator(|input_str| -> Result<(), String> {
                match size_str_to_num(&input_str) {
                    Some(0) => Err("blocksize must be positive".to_owned()),
                    Some(_) => Ok(()),
                    None => Err("blocksize is invalid".to_owned())
                }
            })
            .help("Block size to hash over, in bytes")
            .long_help(concat!("Block size to hash over ",
                "(SI prefixes K,M,G and IEC prefixes Ki,Mi,Gi accepted")))
        .arg(Arg::with_name("output").long("output").short("o")
            .takes_value(true).required(true)
            .help("Output file"))
        .arg(Arg::with_name("overwrite").long("overwrite")
            .help("Overwrite output file if it already exists"))
        .arg(Arg::with_name("short").long("short").short("s")
            .help("Write only the summary hash")
            .long_help(concat!("Write only the summary hash to the output. ",
                "This will make identifying corrupted locations impossible.")))
        .arg(Arg::with_name("FILES").required(true).last(true)
            .multiple(true).max_values(u16::MAX.into()));
    let check_hash_command = SubCommand::with_name(VERIFY_HASH_CMD_NAME)
        .about("Verify Merkle tree hashes")
        .setting(AppSettings::UnifiedHelpMessage)
        .arg(Arg::with_name("failfast").long("fail-fast")
            .help("Bail immediately on hash mismatch")
            .long_help(concat!("Skip checking the rest of the files ",
                "when a hash mismatch is detected.")))
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
            .multiple(true)
            .help("Print less text")
            .long_help(concat!("Specify once to hide progress bars. ",
                "Specify twice to suppress all output besides errors.")))
        // TODO: specify thread count?
        .arg(Arg::with_name("jobs").long("jobs").short("j")
            .help("Use a thread pool for hashing"))
        .subcommand(gen_hash_command)
        .subcommand(check_hash_command);
    clap_app.get_matches_safe()
}

fn run() -> i32 {
    let matches_result = parse_cli();
    if let Err(e) = matches_result {
        // Mirror e.exit, but use scoping to call destructors
        if e.use_stderr() {
            eprintln!("{}", e.message);
        } else {
            println!("{}", e.message);
        }
        return 1;
    }
    let matches = matches_result.unwrap();

    let (mut cmd_chosen, cmd_matches): (HashCommand<_,_>, ArgMatches)
            = match matches.subcommand() {
        (GENERATE_HASH_CMD_NAME, Some(gencmd_matches)) => 
                (HashCommand::GenerateHash(None), gencmd_matches.clone()),
        (VERIFY_HASH_CMD_NAME, Some(verify_matches)) =>
                (HashCommand::VerifyHash(None), verify_matches.clone()),
        (_, _) => panic!("Invalid subcommand detected")
    };

    let mut hashing_final_status = 0;

    let (file_list_result, block_size, branch_factor, short_output, hash_enum, verify_start_pos):
            (Result<Vec<PathBuf>, String>, block_t, branch_t, bool, HashFunctions, Option<u64>)
            = match cmd_chosen {
        HashCommand::GenerateHash(_) => {
            let file_vec = cmd_matches.values_of("FILES").unwrap().collect();
            // Validators should already have caught errors
            (
                utils::get_file_list(file_vec),
                size_str_to_num(
                    cmd_matches.value_of("blocksize").unwrap()).unwrap(),
                value_t!(cmd_matches, "branch", branch_t)
                    .unwrap_or_else(|e| e.exit()),
                cmd_matches.is_present("short"),
                value_t!(cmd_matches, "hash", HashFunctions)
                    .unwrap_or_else(|e| e.exit()),
                None
            )
        },
        HashCommand::VerifyHash(_) => {
            let hash_file_str = cmd_matches.value_of("FILE").unwrap();
            let hash_file = match File::open(hash_file_str) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Error opening hash file {}: {}",
                            hash_file_str, e);
                    return 1;
                }
            };
            let mut hash_file_reader = BufReader::new(hash_file);

            let mut file_vec : Vec<PathBuf> = Vec::new();
            // Parse version number
            let mut version_line = String::new();
            let version_read_result = hash_file_reader.read_line(&mut version_line);
            if version_read_result.is_err() {
                eprintln!("Error: unable to read in version line");
                return 1;
            }
            match parse_functions::check_version_line(&version_line) {
                Ok(version) => {
                    // TODO: Do more precise version checking later
                    let range_str = concat!("~",crate_version!());
                    let recognized_range = VersionReq::parse(range_str).unwrap();
                    if !recognized_range.matches(&version) {
                        eprintln!("Error: hash file has unsupported version {}", version);
                        return 1;
                    }
                },
                Err(e) => match e {
                    ParsingErrors::MalformedFile => {
                        eprintln!("Error: hash file is malformed: unable to parse version line");
                        return 1;
                    },
                    ParsingErrors::MalformedVersion(s) => {
                        eprintln!("Error: hash file has malformed version {}",s);
                        return 1;
                    }
                    _ => unreachable!()
                }
            }
            // Read in the next three lines
            let mut hash_param_arr = [String::default(), String::default(), String::default()];
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
                    return 1;
                }
            }
            let (block_size_result,
                branch_factor_result,
                hash_function_result,
                other_errors)
                = parse_functions::get_hash_params(&hash_param_arr);
            if !other_errors.is_empty() {
                let mut error_vec_string: Vec<String> = Vec::new();
                let mut error_string = String::default();
                for error in other_errors {
                    match error {
                        ParsingErrors::MalformedFile => {
                            error_string = "hash file is malformed: unable to parse tree parameters".to_string();
                            break;
                        },
                        ParsingErrors::UnexpectedParameter(s) => {
                            error_vec_string.push(s);
                        },
                        _ => unreachable!()
                    };
                }
                if error_string.is_empty() {
                    error_string = format!("hash file has unexpected parameters {}",
                        error_vec_string.join(", "));
                }
                eprintln!("Error: {}", error_string);
                return 1;
            }

            let mut format_line = String::new();
            let format_line_result = hash_file_reader.read_line(&mut format_line);
            if format_line_result.is_err() {
                eprintln!("Error: hash file is malformed: file should have file list or hash list");
                return 1;
            }
            let is_short_hash = match format_line.as_str() {
                "Hashes:\n" | "Hashes:\r\n" => true,
                "Files:\n" | "Files:\r\n" => false,
                _ => {
                    eprintln!("Error: hash file is malformed: file should have file list or hash list");
                    return 1;
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
                        }
                    } else {
                        eprintln!("Error: Error in reading file: {}", read_err);
                    }
                    return 1;
                }
                if let Some((quoted_name, len_option)) = parse_functions::extract_quoted_filename(&next_line) {
                    assert_eq!(len_option.is_none(), is_short_hash);
                    let unquoted_name = match enquote::unquote(&quoted_name) {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("Error: unable to unquote file name {}: {}",
                                quoted_name, e);
                            return 1;
                        }
                    };
                    let path = PathBuf::from(unquoted_name.clone());
                    if let Some(expected_len) = len_option {
                        let actual_len = path.metadata().unwrap().len();
                        if actual_len == expected_len {
                            file_vec.push(path);
                        } else {
                            eprintln!(concat!(
                                "Error: {} has length mismatch:\n",
                                "  expected: {}\n",
                                "  actual:   {}\n"),
                                unquoted_name, expected_len, actual_len);
                            if cmd_matches.is_present("failfast") {
                                return 2;
                            } else {
                                hashing_final_status = 2;
                            }
                        }
                    } else {
                        file_vec.push(path);
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
                    return 1;
                }
            }
            assert!(is_short_hash == list_begin_pos.is_some());
            if let Some(seek_pos) = list_begin_pos {
                hash_file_reader.seek(SeekFrom::Start(seek_pos)).unwrap();
            }

            (
                match file_vec.iter().find(|path| !path.is_file()) {
                    Some(i) => Err(i.to_str().unwrap().to_owned()),
                    None => Ok(file_vec)
                },
                match block_size_result {
                    Ok(val) => val,
                    Err(e) => {
                        let err_str = match e {
                            ParsingErrors::MissingParameter => "missing block size".to_owned(),
                            ParsingErrors::BadParameterValue(v) => v,
                            _ => unreachable!()
                        };
                        eprintln!("Error: {}", err_str);
                        return 1;
                    }
                },
                match branch_factor_result {
                    Ok(val) => val,
                    Err(e) => {
                        let err_str = match e {
                            ParsingErrors::MissingParameter => "missing branch factor".to_owned(),
                            ParsingErrors::BadParameterValue(v) => v,
                            _ => unreachable!()
                        };
                        eprintln!("Error: {}", err_str);
                        return 1;
                    }
                },
                is_short_hash,
                match hash_function_result {
                    Ok(val) => val,
                    Err(e) => {
                        let err_str = match e {
                            ParsingErrors::MissingParameter => "missing hash function".to_owned(),
                            ParsingErrors::BadParameterValue(v) => v,
                            _ => unreachable!()
                        };
                        eprintln!("Error: {}", err_str);
                        return 1;
                    }
                },
                // We want to ensure that the seek call succeeded
                Some(hash_file_reader.stream_position().unwrap())
            )
        }
    };
    if file_list_result.is_err() {
        eprintln!("Error: file {} does not exist",
                file_list_result.unwrap_err());
        return 1;
    }
    let file_list = file_list_result.unwrap();

    let quiet_count = matches.occurrences_of("quiet");

    let multithread = matches.is_present("jobs");

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
        HashFunctions::sha512trunc224 =>
            merkle_hash_file::<_,Sha512Trunc224,_>,
        HashFunctions::sha512trunc256 =>
            merkle_hash_file::<_,Sha512Trunc256,_>,
    };
    let expected_hash_len = hash_enum.hash_len();

    if quiet_count < 2 && hash_enum == HashFunctions::crc32
            && matches!(cmd_chosen, HashCommand::GenerateHash(_)) {
        eprintln!("Warning: CRC32 is not cryptographically secure and will only prevent accidental corruption");
    }
    if quiet_count < 2 && matches!(cmd_chosen, HashCommand::VerifyHash(_))
            && !short_output && !cmd_matches.is_present("failfast") {
        eprintln!(
            concat!("Warning: Verification of long hashes is always failfast, ",
                "even when --fail-fast is not specified")
        );
    }

    match cmd_chosen {
        HashCommand::GenerateHash(_) => {
            let write_file_name = cmd_matches.value_of("output").unwrap();
            let overwrite = cmd_matches.is_present("overwrite");
            let open_result = match overwrite {
                true => OpenOptions::new().write(true).create(true)
                    .truncate(true).open(write_file_name),
                false => OpenOptions::new().write(true)
                    .create_new(true).open(write_file_name)
            };
            let mut file_handle = match open_result {
                Ok(file) => file,
                Err(err) => {
                    eprintln!("Error opening file {} for writing: {}",
                        write_file_name, err);
                    return 1
                }
            };
            // Write file prelude
            writeln!(file_handle, "{} v{}", crate_name!(), crate_version!()).unwrap();
            writeln!(file_handle, "Hash function: {}", hash_enum).unwrap();
            writeln!(file_handle, "Block size: {}", block_size).unwrap();
            writeln!(file_handle, "Branching factor: {}", branch_factor).unwrap();

            if !short_output {
                writeln!(file_handle, "Files:").unwrap();
                let list_str: Vec<String> = file_list.iter()
                    .map(|path| {
                        let path_metadata = path.metadata().unwrap();
                        (path.to_str().unwrap(), path_metadata.len())
                    })
                    .map(|(string, len)| {
                        let escaped_str = escape_chars(string);
                        let quoted_str = enquote::enquote('"', &escaped_str);
                        (quoted_str, len)
                    })
                    .map(|(string, len)| format!("{} {:#x} bytes", string, len))
                    .collect();
                writeln!(file_handle, "{}", list_str.join("\n")).unwrap();
            }
            writeln!(file_handle, "Hashes:").unwrap();
            file_handle.flush().unwrap();

            debug_assert!(verify_start_pos.is_none());
            cmd_chosen = HashCommand::GenerateHash(Some(BufWriter::new(file_handle)));
        },
        HashCommand::VerifyHash(_) => {
            let read_file_name = cmd_matches.value_of("FILE").unwrap();
            let mut hash_file = match File::open(read_file_name) {
                Ok(file) => file,
                Err(e) => {
                    eprintln!("Error opening hash file {}: {}",
                            read_file_name, e);
                    return 1;
                }
            };
            hash_file.seek(SeekFrom::Start(verify_start_pos.unwrap())).unwrap();
            cmd_chosen = HashCommand::VerifyHash(Some(BufReader::new(hash_file)))
        }
    };

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
        let file_size = file_obj.metadata().unwrap().len();
        let pb_hash_len = merkle_tree::node_count(file_size, block_size, branch_factor).unwrap();
        let pb_file_style = ProgressStyle::default_bar()
            // 4 = max length of message strings below
            .template("{msg:4} {bar:20} {bytes:>9}/{total_bytes:9} | {bytes_per_sec:>11}");
        let pb_hash_style = ProgressStyle::default_bar()
            .template("{msg:4} {bar:20} {pos:>9}/{len:9} | {per_sec:>11} [{elapsed_precise}] ETA [{eta}]");

        let pb_holder = MultiProgress::new();
        let pb_file = pb_holder.add(ProgressBar::new(file_size));
        let pb_hash = pb_holder.add(ProgressBar::new(pb_hash_len));

        if quiet_count >= 1 {
            if quiet_count == 1 {
                eprintln!("Hashing {}...", filename_str);
            }
            pb_holder.set_draw_target(ProgressDrawTarget::hidden());
        } else { // quiet_count == 0
            pb_hash.set_style(pb_hash_style);
            pb_file.set_style(pb_file_style);

            let file_part = Path::new(&file_name).file_name().unwrap()
                    .to_str().unwrap();

            // Leave a padding of at least 3 equal signs on each side
            // TODO: use fixed width, or scale with terminal size?
            let abbreviated_msg = utils::abbreviate_filename(file_part, 80-8);
            eprintln!("{:=^80}", " ".to_owned()+&abbreviated_msg+" ");

            pb_file.set_message("File");
            pb_file.set_draw_rate(4);

            pb_hash.set_message("Hash");
            pb_hash.set_draw_rate(4);
        }

        let pb_thread_handle = thread::Builder::new()
            .name(String::from(filename_str)+"_pb_wait")
            .spawn(move || {
                pb_holder.join().unwrap()
            })
            .unwrap();

        let (tx, rx) = mpsc::channel::<HashRange>();
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
                    block_size, branch_factor, tx, multithread);
                pb_file.finish_at_current_pos();
                result
            })
            .unwrap();

        let mut abort_hash_loop: Result<(), VerificationError> = Ok(());

        let block_iter = merkle_block_generator(file_size, block_size, branch_factor).into_iter();
        for block_hash in reorder_hashrange_iter(block_iter, rx.into_iter()) {
            pb_hash.inc(1);
            if !short_output {
                match &mut cmd_chosen {
                    HashCommand::GenerateHash(Some(w)) => {
                        writeln!(w, "{:3} {} {} {}",
                            file_index,
                            block_hash.block_range(),
                            block_hash.byte_range(),
                            hex::encode(&block_hash.hash_result())
                        ).unwrap();
                    }
                    HashCommand::VerifyHash(Some(r)) => {
                        let mut line = String::new();
                        let line_len = r.read_line(&mut line).unwrap();
                        if line_len == 0 {
                            abort_hash_loop = Err(VerificationError::UnexpectedEof);
                                break;
                        }

                        let hash_parts = extract_long_hash_parts(
                            &line, 2*expected_hash_len);
                        if let Some((file_id, file_hash_range)) = hash_parts {
                            if file_id != file_index {
                                abort_hash_loop = Err(VerificationError::MismatchedFileID);
                                break;
                            }
                            if block_hash.block_range() != file_hash_range.block_range() {
                                abort_hash_loop = Err(VerificationError::MismatchedBlockRange(StoredAndComputed::new(file_hash_range.block_range(), block_hash.block_range())));
                                break;
                            }
                            if block_hash.byte_range() != file_hash_range.byte_range() {
                                abort_hash_loop = Err(VerificationError::MismatchedByteRange(StoredAndComputed::new(file_hash_range.byte_range(), block_hash.byte_range())))
                            }
                            if block_hash.hash_result() != file_hash_range.hash_result() {
                                let file_hash_box = file_hash_range.hash_result().to_vec().into_boxed_slice();
                                let block_hash_box = block_hash.hash_result().to_vec().into_boxed_slice();
                                abort_hash_loop = Err(VerificationError::MismatchedHash(Some(block_hash.byte_range()), StoredAndComputed::new(file_hash_box,block_hash_box)));
                                break;
                            }
                        } else {
                            abort_hash_loop = Err(VerificationError::MalformedEntry(line));
                            break;
                        }
                    }
                    _ => unreachable!()
                }
            }
            thread::yield_now();
        }
        pb_hash.finish_at_current_pos();
        pb_thread_handle.join().unwrap();

        let final_hash_option = thread_handle.join().unwrap();

        if quiet_count == 0 && abort_hash_loop.is_ok() {
            assert_eq!(pb_hash.position(), pb_hash.length());
        }

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
                    if let Some((file_hash_box, quoted_name)) = hash_parts {
                        assert_eq!(filename_str,
                            enquote::unquote(&quoted_name).unwrap());
                        if final_hash == file_hash_box {
                            abort_hash_loop = Ok(());
                        } else {
                            abort_hash_loop = Err(VerificationError::MismatchedHash(None, StoredAndComputed::new(file_hash_box, final_hash)));
                        }
                    } else {
                        abort_hash_loop = Err(VerificationError::MalformedEntry(line));
                    }
                },
                _ => unreachable!()
            }
        }
        match abort_hash_loop {
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
                if cmd_matches.is_present("failfast") || !short_output {
                    return 2;
                }
                match err {
                    VerificationError::MismatchedHash(..) => {
                        if cmd_matches.is_present("failfast") {
                            return 2;
                        } else {
                            hashing_final_status = 2;
                            continue;
                        }
                    }
                    _ => {return 2;}
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
            return 2;
        }
    }
    return hashing_final_status;
}
