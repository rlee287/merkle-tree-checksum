#![forbid(unsafe_code)]

extern crate merkle_tree;

use std::str::FromStr;
use std::fmt;
use crate::error_types::HeaderParsingErr;
use crate::parse_functions::size_str_to_num;

use crossbeam_channel::Sender as CrossbeamSender;
use indicatif::{ProgressDrawTarget, ProgressStyle, ProgressBar, MultiProgress};

use strum_macros::EnumString;

use crate::hash_enum::HashFunctions;

use merkle_tree::{block_t, branch_t, Consumer};

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

#[derive(Debug, Clone)]
pub(crate) enum ChannelOrPb<T> {
    Channel(CrossbeamSender<T>),
    ProgressBar(ProgressBar)
}
impl<T> From<CrossbeamSender<T>> for ChannelOrPb<T> {
    fn from(value: CrossbeamSender<T>) -> Self {
        Self::Channel(value)
    }
}
impl<T> From<ProgressBar> for ChannelOrPb<T> {
    fn from(value: ProgressBar) -> Self {
        Self::ProgressBar(value)
    }
}
// Have to impl by hand because both Consumer trait and ProgressBar struct are foreign
impl<T> Consumer<T> for ChannelOrPb<T> {
    fn accept(&self, var: T) -> Result<(), T> {
        match self {
            ChannelOrPb::Channel(sender) => sender.accept(var),
            ChannelOrPb::ProgressBar(pb) => {
                pb.inc(1);
                Ok(())
            },
        }
    }
}
// Uses drop impl to finish the pb
impl<T> Drop for ChannelOrPb<T> {
    fn drop(&mut self) {
        match self {
            ChannelOrPb::Channel(_) => {/* do nothing */},
            // Unfortunately can't check if pb finished here
            ChannelOrPb::ProgressBar(pb) => {pb.finish()},
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct StoredAndComputed<T> {
    stored: T,
    computed: T
}
impl<T> StoredAndComputed<T> {
    pub const fn new(stored: T, computed: T) -> Self {
        StoredAndComputed {stored, computed}
    }
    #[inline]
    pub const fn stored(&self) -> &T {
        &self.stored
    }
    #[inline]
    pub const fn computed(&self) -> &T {
        &self.computed
    }
}
impl<T: Copy> Copy for StoredAndComputed<T> {}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[derive(EnumString, strum_macros::Display)]
// Don't use strum(ascii_case_insensitive) because we only accept two types
pub(crate) enum HeaderElement {
    #[strum(to_string = "Block size", serialize = "block size")]
    BlockSize,
    #[strum(to_string = "Branching factor", serialize = "branch factor")]
    BranchFactor,
    #[strum(to_string = "Hash function", serialize = "hash function")]
    HashFunction
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TreeParams {
    pub block_size: block_t,
    pub branch_factor: branch_t,
    pub hash_function: HashFunctions
}
impl TreeParams {
    pub fn from_lines(string_arr: &[String; 3]) -> Result<TreeParams, Vec<HeaderParsingErr>> {
        let mut block_size_opt: Option<block_t> = None;
        let mut branch_factor_opt: Option<branch_t> = None;
        let mut hash_function_opt: Option<HashFunctions> = None;
        let mut errors: Vec<HeaderParsingErr> = Vec::new();
        for string_element in string_arr {
            let string_split: Vec<&str> = string_element.split(':').collect();
            if string_split.len() != 2 {
                errors.push(HeaderParsingErr::MalformedFile);
                continue;
            }
            let (key, value) = (string_split[0], string_split[1].trim());
            match HeaderElement::from_str(key) {
                Ok(HeaderElement::BlockSize) => {
                    match size_str_to_num(value) {
                        Ok(0) | Err(_) => {
                            errors.push(HeaderParsingErr::BadParameterValue(
                                HeaderElement::BlockSize, value.to_owned()));
                        }
                        Ok(val) => {
                            block_size_opt = Some(val);
                        }
                    }
                },
                Ok(HeaderElement::BranchFactor) => {
                    match value.parse::<branch_t>() {
                        Ok(0) | Ok(1) | Err(_) => {
                            errors.push(HeaderParsingErr::BadParameterValue(
                                HeaderElement::BranchFactor, value.to_owned()));
                        },
                        Ok(val) => {
                            branch_factor_opt = Some(val)
                        }
                    }
                },
                Ok(HeaderElement::HashFunction) => {
                    match value.parse::<HashFunctions>() {
                        Err(_) => {
                            errors.push(HeaderParsingErr::BadParameterValue(
                                HeaderElement::HashFunction, value.to_owned()));
                        },
                        Ok(val) => {
                            hash_function_opt = Some(val)
                        }
                    }
                },
                Err(_) => {
                    errors.push(
                        HeaderParsingErr::UnexpectedParameter(key.to_owned()));
                    continue;
                }
            }
        }
        if let (Some(block_size), Some(branch_factor), Some(hash_function)) = (block_size_opt, branch_factor_opt, hash_function_opt) {
            Ok(TreeParams {
                block_size,
                branch_factor,
                hash_function
            })
        } else {
            if block_size_opt.is_none() {
                errors.push(
                    HeaderParsingErr::MissingParameter(HeaderElement::BlockSize));
            }
            if branch_factor_opt.is_none() {
                errors.push(
                    HeaderParsingErr::MissingParameter(HeaderElement::BranchFactor));
            }
            if hash_function_opt.is_none() {
                errors.push(
                    HeaderParsingErr::MissingParameter(HeaderElement::HashFunction));
            }
            assert!(!errors.is_empty());
            Err(errors)
        }
    }
}
impl fmt::Display for TreeParams {
    fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
        writeln!(fmt, "Hash function: {}", self.hash_function)?;
        writeln!(fmt, "Block size: {}", self.block_size)?;
        writeln!(fmt, "Branching factor: {}", self.branch_factor)?;
        Ok(())
    }
}

pub(crate) fn str_to_files(file_str: &str) -> Option<Vec<PathBuf>> {
    let mut file_list = Vec::<PathBuf>::new();
    let file_path = Path::new(&file_str);
    if file_path.is_file() {
        file_list.push(file_path.to_path_buf());
    } else if file_path.is_dir() {
        // Walk directory to find all the files in it
        for entry in WalkDir::new(file_path).min_depth(1).follow_links(true) {
            let entry_unwrap = entry.unwrap();
            let entry_path = entry_unwrap.path();
            if entry_path.is_file() {
                file_list.push(entry_path.to_path_buf());
            }
        }
    } else {
        return None;
    }
    return Some(file_list);
}

pub(crate) fn setup_pbs(pb_draw_target: ProgressDrawTarget, file_size: u64, pb_hash_len: u64) -> (ProgressBar, ProgressBar) {
    let pb_holder = MultiProgress::with_draw_target(pb_draw_target);

    let pb_file = pb_holder.add(ProgressBar::new(file_size));
    let pb_hash = pb_holder.add(ProgressBar::new(pb_hash_len));

    let pb_file_style = ProgressStyle::default_bar()
        // 4 = max length of message strings below
        .template("{msg:4} {bar:20} {bytes:>11}/{total_bytes:11} | {bytes_per_sec:>12}")
        .unwrap();
    let pb_hash_style = ProgressStyle::default_bar()
        .template("{msg:4} {bar:20} {pos:>11}/{len:11} | {per_sec:>12} [{elapsed_precise}] ETA [{eta}]")
        .unwrap();

    pb_hash.set_style(pb_hash_style);
    pb_file.set_style(pb_file_style);

    pb_file.set_message("File");
    pb_hash.set_message("Hash");

    (pb_file, pb_hash)
}
