#![forbid(unsafe_code)]

extern crate merkle_tree;

use digest::Digest;
use crate::crc32_utils::Crc32;
use sha2::{Sha224, Sha256, Sha384, Sha512, Sha512Trunc224, Sha512Trunc256};

use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use std::sync::mpsc;

arg_enum!{
    #[derive(PartialEq, Eq, Debug, Clone, Copy)]
    #[allow(non_camel_case_types)]
    pub enum HashFunctions {
        crc32,
        sha224,
        sha256,
        sha384,
        sha512,
        sha512trunc224,
        sha512trunc256
    }
}

#[inline]
pub fn enum_hash_len(hash_enum: HashFunctions) -> usize {
    match hash_enum {
        HashFunctions::crc32 => Crc32::output_size(),
        HashFunctions::sha224 => Sha224::output_size(),
        HashFunctions::sha256 => Sha256::output_size(),
        HashFunctions::sha384 => Sha384::output_size(),
        HashFunctions::sha512 => Sha512::output_size(),
        HashFunctions::sha512trunc224 => Sha512Trunc224::output_size(),
        HashFunctions::sha512trunc256 => Sha512Trunc256::output_size()
    }
}

pub(crate) fn abbreviate_filename(name: &str, len_threshold: usize) -> String {
    let name_chars = name.chars().collect::<Vec<_>>();
    if name_chars.len() <= len_threshold {
        return name.to_owned();
    } else if len_threshold < 3 {
        // Return the first len_threshold chars (*not* bytes)
        return name_chars[..len_threshold].iter().collect::<String>();
    } else {
        // Join the beginning and end part of the name with ~
        let filechar_count = len_threshold - 1;
        // Use subtraction to ensure consistent sum
        let end_half_len = filechar_count / 2;
        let begin_half_len = filechar_count - end_half_len;

        let ret_str =
            (&name_chars[..begin_half_len]).iter().collect::<String>()
            + "~"
            + &name_chars[name.len()-end_half_len..].iter().collect::<String>();
        assert!(ret_str.len() <= len_threshold);
        return ret_str;
    }
}

pub(crate) fn escape_chars(string: &str) -> String {
    /*
     * Escape \t, \r, and \n from filenames
     * Technically we only really need to escape \n for correctness
     * Escape the others to avoid confusion
     * (It is the user's responsibility to avoid other weird characters)
     */
    string.chars().map(|c| {
        match c {
            '\t' => r"\t".into(),
            '\r' => r"\r".into(),
            '\n' => r"\n".into(),
            l => l.to_string()
        }
    }).collect()
}

pub(crate) fn get_file_list(file_strs: Vec<&str>) -> Result<Vec<PathBuf>,String> {
    let mut file_list = Vec::<PathBuf>::new();
    for file_str in file_strs {
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
            return Err(file_str.to_owned());
        }
    }
    return Ok(file_list);
}

// allow(dead_code) for switching between unbouned and bounded channels
#[derive(Debug, Clone)]
enum SenderTypes<T> {
    #[allow(dead_code)]
    UnboundedSend(mpsc::Sender<T>),
    #[allow(dead_code)]
    BoundedSend(mpsc::SyncSender<T>)
}

#[derive(Debug, Clone)]
pub struct MpscConsumer<T> {
    sender: SenderTypes<T>
}

impl<T> MpscConsumer<T> {
    #[allow(dead_code)]
    pub fn new_async(tx: mpsc::Sender<T>) -> MpscConsumer<T> {
        MpscConsumer::<T> {sender: SenderTypes::UnboundedSend(tx)}
    }
    #[allow(dead_code)]
    pub fn new_sync(tx: mpsc::SyncSender<T>) -> MpscConsumer<T> {
        MpscConsumer::<T> {sender: SenderTypes::BoundedSend(tx)}
    }
}

impl<T> merkle_tree::Consumer<T> for MpscConsumer<T> {
    fn accept(&mut self, var: T) -> Result<(), T> {
        match &self.sender {
            SenderTypes::UnboundedSend(sender) => {
                match sender.send(var) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(e.0)
                }
            },
            SenderTypes::BoundedSend(sender) => {
                match sender.send(var) {
                    Ok(()) => Ok(()),
                    Err(e) => Err(e.0)
                }
            }
        }
    }
}