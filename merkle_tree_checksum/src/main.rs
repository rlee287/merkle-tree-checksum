#![forbid(unsafe_code)]
extern crate merkle_tree;
#[macro_use]
extern crate clap;

extern crate enquote;

mod crc32_utils;
mod utils;
mod parse_functions;

use std::convert::AsMut;
use std::iter::FromIterator;
use std::cmp::min;
use std::thread;
use std::sync::mpsc;

use chrono::Local;

use std::fs::File;
use std::io::{self, Write, Seek, SeekFrom, BufRead, BufReader, BufWriter};
use parse_functions::ParsingErrors;
use std::path::{Path,PathBuf};

use crc32_utils::Crc32;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};
use merkle_tree::merkle_hash_file;
use utils::HashFunctions;
use utils::MpscConsumer;

use clap::{App, AppSettings, Arg, SubCommand, ArgMatches};
use indicatif::{ProgressBar, ProgressStyle, ProgressBarWrap,
    ProgressDrawTarget, MultiProgress};

const GENERATE_HASH_CMD_NAME: &str = "generate-hash";
const VERIFY_HASH_CMD_NAME: &str = "verify-hash";

#[derive(PartialEq, Eq, Debug, Clone, Copy)]
enum HashCommand {
    GenerateHash,
    VerifyHash
}

fn main() {
    let status_code = run();
    std::process::exit(status_code);
}

fn run() -> i32 {
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

    let matches = clap_app.get_matches();

    let (cmd_chosen, cmd_matches): (HashCommand, ArgMatches)
            = match matches.subcommand() {
        (GENERATE_HASH_CMD_NAME, Some(gencmd_matches)) => 
                (HashCommand::GenerateHash, gencmd_matches.clone()),
        (VERIFY_HASH_CMD_NAME, Some(verify_matches)) =>
                (HashCommand::VerifyHash, verify_matches.clone()),
        (_, _) => panic!("Invalid subcommand detected")
    };

    // let mut hash_file_read: Option<Box<dyn Read + Send>> = None;
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
            let version_line = parse_functions::next_noncomment_line(&mut hash_file_reader).unwrap();
            match parse_functions::check_version_line(&version_line) {
                Ok(_v) => {
                    // Do nothing for now, select version format later
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
                    ParsingErrors::BadVersion(s) => {
                        eprintln!("Error: hash file has unsupported version {}", s);
                        return 1;
                    }
                    _ => unreachable!()
                }
            }
            // Read in the next three lines
            let mut hash_param_arr = [String::default(), String::default(), String::default()];
            for i in 0..3 {
                let line = parse_functions::next_noncomment_line(&mut hash_file_reader).unwrap();
                // Slice to remove newline
                hash_param_arr[i] = line[..line.len()-1].to_string();
            }
            let (block_size_result,
                branch_factor_result,
                hash_function_result,
                other_errors)
                = parse_functions::get_hash_params(&hash_param_arr);
            if other_errors.len() > 0 {
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

            let format_line = parse_functions::next_noncomment_line(&mut hash_file_reader).unwrap();
            let is_short_hash = match format_line.as_str() {
                "Hashes:\n" => true,
                "Files:\n" => false,
                _ => {
                    eprintln!("Error: hash file is malformed: file should have file list or hash list");
                    return 1;
                }
            };
            let list_begin_pos: Option<u64> = match is_short_hash {
                true => Some(
                    hash_file_reader.seek(SeekFrom::Current(0)).unwrap()
                ),
                false => None
            };
            let mut build_filename_str = String::default();
            // TODO: refactor
            loop {
                let (start_quote, end_quote)
                        = parse_functions::first_two_quotes(build_filename_str.as_str());
                if let Some(i) = end_quote {
                    let quote_slice = &build_filename_str[start_quote.unwrap()..=i];
                    let unquoted_res = enquote::unquote(quote_slice);
                    let unquoted = match unquoted_res {
                        Ok(s) => s,
                        Err(e) => {
                            eprintln!("Error: unable to unquote file name {}: {}",
                                quote_slice, e);
                            return 1;
                        }
                    };
                    file_vec.push(PathBuf::from(unquoted));
                    build_filename_str = build_filename_str[i+1..].to_owned();
                } else if let Some(_) = start_quote {
                    // read_line does append
                    if hash_file_reader.read_line(&mut build_filename_str)
                            .is_err() {
                        eprintln!("Error: unterminated quote at EOF");
                    }
                } else {
                    // TODO: rather fragile
                    if !is_short_hash && build_filename_str.trim() == "Hashes:" {
                        break;
                    }
                    if build_filename_str.len() >= 256 {
                        // Bail out to avoid reading rest of file into memory
                        eprintln!("Error: hash file is malformed: errors extracting file list");
                        return 1;
                    }
                    let next_line = match parse_functions::next_noncomment_line(&mut hash_file_reader) {
                        Ok(s) => s,
                        Err(_) => break
                    };
                    build_filename_str += next_line.as_str();
                }
            }
            assert!(is_short_hash == list_begin_pos.is_some());
            if list_begin_pos.is_some() {
                hash_file_reader.seek(SeekFrom::Start(list_begin_pos.unwrap())).unwrap();
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
                }
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
    } else {
        // temp
        todo!();
    }

    let is_quiet = matches.is_present("quiet");

    type HashConsumer = MpscConsumer<merkle_tree::HashRange>;
    let merkle_tree_thunk = match hash_enum {
        HashFunctions::crc32 =>
            merkle_hash_file::<ProgressBarWrap<File>,Crc32,HashConsumer>,
        HashFunctions::sha224 =>
            merkle_hash_file::<ProgressBarWrap<File>,Sha224,HashConsumer>,
        HashFunctions::sha256 =>
            merkle_hash_file::<ProgressBarWrap<File>,Sha256,HashConsumer>,
        HashFunctions::sha384 =>
            merkle_hash_file::<ProgressBarWrap<File>,Sha384,HashConsumer>,
        HashFunctions::sha512 =>
            merkle_hash_file::<ProgressBarWrap<File>,Sha512,HashConsumer>,
        HashFunctions::sha512trunc224 =>
            merkle_hash_file::<ProgressBarWrap<File>,Sha512Trunc224,HashConsumer>,
        HashFunctions::sha512trunc256 =>
            merkle_hash_file::<ProgressBarWrap<File>,Sha512Trunc256,HashConsumer>,
    };

    if !is_quiet && hash_enum == HashFunctions::crc32
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
        let file_size = file_obj.metadata().unwrap().len();
        let pb_hash_len = merkle_tree::node_count(file_size, block_size, branch_factor).unwrap();
        let pb_file_style = ProgressStyle::default_bar()
        .template("{msg:24!} {bytes:>8}/{total_bytes:8} | {bytes_per_sec:>9}");
        let pb_hash_style = ProgressStyle::default_bar()
            .template("{msg:24!} {pos:>8}/{len:8} | {per_sec:>9} [{elapsed_precise}] ETA [{eta_precise}]");

        let pb_holder = MultiProgress::new();
        let pb_file = pb_holder.add(ProgressBar::new(file_size));
        let pb_hash = pb_holder.add(ProgressBar::new(pb_hash_len));

        if is_quiet {
            pb_holder.set_draw_target(ProgressDrawTarget::hidden());
        } else {
            pb_hash.set_style(pb_hash_style);
            pb_file.set_style(pb_file_style);

            let file_part = Path::new(&file_name).file_name().unwrap()
                    .to_str().unwrap();
            let abbreviated_msg = utils::abbreviate_filename(file_part, 24);
            assert!(abbreviated_msg.len() <= 24);

            pb_file.set_message(&abbreviated_msg);
            pb_file.set_draw_delta((block_size*branch_factor as u32) as u64);

            pb_hash.set_message(&abbreviated_msg);
            pb_hash.set_draw_delta(min(pb_hash_len/100, 256));
        }

        let pb_thread_handle = thread::Builder::new()
            .name(String::from(filename_str)+"_pb_wait")
            .spawn(move || {
                pb_holder.join().unwrap()
            })
            .unwrap();

        let (tx, rx) = mpsc::channel::<merkle_tree::HashRange>();
        let tx_wrap = utils::MpscConsumer::new_async(tx);
        let thread_handle = thread::Builder::new()
            .name(String::from(filename_str))
            .spawn(move || {
                let wrap = pb_file.wrap_read(file_obj);
                let result = merkle_tree_thunk(wrap,
                    block_size, branch_factor, tx_wrap);
                pb_file.finish_at_current_pos();
                result
            })
            .unwrap();
        for block_hash in rx.into_iter() {
            pb_hash.inc(1);
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
        pb_hash.finish_at_current_pos();
        let final_hash = thread_handle.join().unwrap();
        pb_thread_handle.join().unwrap();
        if short_output {
            writeln!(write_handle, "{}  {}",
                utils::arr_to_hex_str(final_hash.as_ref()),
                enquote::enquote('"',filename_str)).unwrap();
        }
        write_handle.flush().unwrap();
        if !is_quiet {
            assert_eq!(pb_hash.position(), pb_hash.length());
        }
    }
    return 0;
}
