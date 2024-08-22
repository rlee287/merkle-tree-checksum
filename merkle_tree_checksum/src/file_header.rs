use crate::{StoredAndComputed, TreeParams};
use crate::hash_enum::HashFunctions;
use crate::error_types::PreHashError;
use crate::parse_functions::extract_quoted_filename;
use crate::utils::path_to_files;
use merkle_tree::{block_t, branch_t};

use std::fs::File;
use std::io::{Read, BufRead, Seek, SeekFrom};
use std::path::PathBuf;

use std::fmt;

use clap::ArgMatches;

#[derive(Debug, Clone)]
pub(crate) struct FileHeader {
    file_vec: Vec<(PathBuf, Option<PreHashError>)>,
    block_size: block_t,
    branch_factor: branch_t,
    hash_function: HashFunctions,
    short_output: bool,
}

impl FileHeader {
    pub fn from_arg_matches(args: &ArgMatches) -> Self {
        let file_vec: Vec<_> = args.get_many::<PathBuf>("FILES").unwrap().collect();
        let mut collect_vec: Vec<_> = Vec::with_capacity(file_vec.len());
        for file_path in file_vec {
            match path_to_files(file_path) {
                Some(paths) => {
                    for path in paths {
                        match File::open(&path) {
                            Ok(_) => collect_vec.push((path, None)),
                            Err(_) => collect_vec.push((path, Some(PreHashError::ReadPermissionError)))
                        }
                    }
                },
                None => collect_vec.push((file_path.to_owned(), Some(PreHashError::FileNotFound)))
            }
        };
        // unwraps will always succeed due to default values
        Self {
            file_vec: collect_vec,
            // block_size has a special parser invoked in parse_cli
            block_size: *args.get_one("blocksize").unwrap(),
            branch_factor: *args.get_one("branch").unwrap(),
            hash_function: *args.get_one("hash").unwrap(),
            short_output: args.get_flag("short"),
        }
    }
    pub fn from_file<F: Read+BufRead+Seek>(file: &mut F) -> Result<Self, i32> {
        let mut file_vec = Vec::new();
        // TODO: this was moved from main; do cleanup
        const EMPTY_STRING: String = String::new();
        // Read in the next three lines
        let mut hash_param_arr = [EMPTY_STRING; 3];
        for param_str in hash_param_arr.iter_mut() {
            let mut line = String::new();
            let line_result = file.read_line(&mut line);
            if line_result.is_ok() {
                // Needed because file might EOF early without newline
                if !(line.ends_with('\n')) {
                    eprintln!("Error: unable to read in parameter line (EOF)");
                    return Err(crate::VERIF_READ_ERR);
                }
                if &line[line.len()-2..line.len()-1] == "\r" {
                    // \r\n ending
                    *param_str = line[..line.len()-2].to_string();
                } else {
                    // \n ending
                    *param_str = line[..line.len()-1].to_string();
                }
            } else {
                eprintln!("Error: unable to read in parameter line");
                return Err(crate::VERIF_READ_ERR);
            }
        }
        let tree_param = match TreeParams::from_lines(&hash_param_arr){
            Ok(p) => p,
            Err(other_errors) => {
                for error in other_errors {
                    eprintln!("Error: {}", error);
                }
                return Err(crate::VERIF_BAD_HEADER_ERR);
            }
        };

        let mut format_line = String::new();
        let format_line_result = file.read_line(&mut format_line);
        if format_line_result.is_err() {
            eprintln!("Error: hash file is malformed: unable to read hashes or file list");
            return Err(crate::VERIF_READ_ERR);
        }
        let is_short_hash = match format_line.as_str() {
            "Hashes:\n" | "Hashes:\r\n" => true,
            "Files:\n" | "Files:\r\n" => false,
            _ => {
                eprintln!("Error: hash file is malformed: file should have file list or hash list");
                return Err(crate::VERIF_BAD_HEADER_ERR);
            }
        };
        let list_begin_pos: Option<u64> = match is_short_hash {
            true => Some(
                file.stream_position().unwrap()
            ),
            false => None
        };
        loop {
            let mut next_line = String::new();
            let next_line_result = file.read_line(&mut next_line);
            if let Err(read_err) = next_line_result {
                if read_err.kind() == std::io::ErrorKind::UnexpectedEof {
                    if !is_short_hash {
                        eprintln!("Error: unexpected EOF reading hashes");
                        return Err(crate::VERIF_BAD_HEADER_ERR);
                    }
                } else {
                    eprintln!("Error: Error in reading file: {}", read_err);
                    return Err(crate::VERIF_READ_ERR);
                }
            }
            if let Ok((quoted_name, len_option)) = extract_quoted_filename(&next_line) {
                assert_eq!(len_option.is_none(), is_short_hash);
                let unquoted_name = match enquote::unquote(quoted_name) {
                    Ok(s) => s,
                    Err(e) => {
                        eprintln!("Error: unable to unquote file name {}: {}",
                            quoted_name, e);
                        if is_short_hash {
                            return Err(crate::VERIF_BAD_ENTRY_ERR);
                        } else {
                            return Err(crate::VERIF_BAD_HEADER_ERR);
                        }
                    }
                };
                let path = PathBuf::from(unquoted_name);
                if path.is_file() {
                    if File::open(&path).is_err() {
                        // We already checked file existence
                        file_vec.push((path,
                            Some(PreHashError::ReadPermissionError)))
                    } else if let Some(expected_len) = len_option {
                        let actual_len = path.metadata().unwrap().len();
                        if actual_len == expected_len {
                            file_vec.push((path, None));
                        } else {
                            let mismatch_len_obj = StoredAndComputed::new
                                (expected_len, actual_len);
                            file_vec.push((
                                path,
                                Some(PreHashError::MismatchedLength(
                                    mismatch_len_obj
                                )))
                            )
                        }
                    } else {
                        file_vec.push((path, None))
                    }
                } else {
                    file_vec.push(
                        (
                            path,
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
                return Err(crate::VERIF_BAD_HEADER_ERR);
            }
        }
        // In short mode we need to seek back to before the hash list
        assert!(is_short_hash == list_begin_pos.is_some());
        if let Some(seek_pos) = list_begin_pos {
            file.seek(SeekFrom::Start(seek_pos)).unwrap();
        }

        Ok(Self {
            file_vec,
            block_size: tree_param.block_size,
            branch_factor: tree_param.branch_factor,
            hash_function: tree_param.hash_function,
            short_output: is_short_hash,
        })
    }

    pub(crate) fn file_vec(&self) -> &[(PathBuf, Option<PreHashError>)] {
        &self.file_vec
    }
    pub(crate) fn block_size(&self) -> block_t {
        self.block_size
    }
    pub(crate) fn branch_factor(&self) -> branch_t {
        self.branch_factor
    }
    pub(crate) fn hash_function(&self) -> HashFunctions {
        self.hash_function
    }
    pub(crate) fn short_output(&self) -> bool {
        self.short_output
    }
}

// TODO: rethink if we really want to impl Display
impl fmt::Display for FileHeader {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        writeln!(f, "Hash function: {}", self.hash_function)?;
        writeln!(f, "Block size: {}", self.block_size)?;
        writeln!(f, "Branching factor: {}", self.branch_factor)?;
        Ok(())
    }
}