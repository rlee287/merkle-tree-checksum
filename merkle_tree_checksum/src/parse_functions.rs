#![forbid(unsafe_code)]

use std::io::{self, BufRead};
use semver::{Version, VersionReq};

use crate::utils::HashFunctions;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum ParsingErrors {
    MalformedFile,
    UnexpectedParameter(String),
    MissingParameter,
    BadParameterValue(String),
    MalformedVersion(String),
    BadVersion(Version),
}

pub(crate) fn first_two_quotes(s: &str) -> (Option<usize>, Option<usize>) {
    let mut result_tuple: (Option<usize>, Option<usize>) = (None, None);
    result_tuple.0 = s.find('"');
    if let Some(i) = result_tuple.0 {
        result_tuple.1 = match s[i+1..].find('"') {
            None => None,
            Some(val) => Some(val+i+1)
        }
    }
    return result_tuple;
}

// Contents of working_str is the line after comments
pub(crate) fn next_noncomment_line(reader: &mut dyn BufRead) -> io::Result<String> {
    let mut working_str = String::default();
    loop {
        let read_len = reader.read_line(&mut working_str)?;
        if read_len == 0 {
            return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "EOF"));
        }
        if !working_str.is_empty() && working_str.as_bytes()[0] != b'#' {
            return Ok(working_str);
        }
        working_str.clear();
    }
}

pub(crate) fn check_version_line(version_line: &String)
        -> Result<Version, ParsingErrors> {
    let mut version_str_iter = version_line.split_whitespace();
    let version_obj: Option<Version>;
    if let Some(name_check) = version_str_iter.next() {
        if name_check != crate_name!() {
            return Err(ParsingErrors::MalformedFile);
        }
    } else {
        return Err(ParsingErrors::MalformedFile);
    }
    if let Some(version_str_token) = version_str_iter.next() {
        if version_str_token.as_bytes()[0] != b'v' {
            return Err(
                ParsingErrors::MalformedVersion(version_str_token.to_string())
            );
        }
        let version_str = &version_str_token[1..];
        // TODO: adjust allowable ranges as things get developed more
        let range_str = ["^", crate_version!()].join("");
        let recognized_range = VersionReq::parse(range_str.as_ref()).unwrap();
        let file_version = match Version::parse(version_str) {
            Ok(v) => v,
            Err(_e) => {
                return Err(
                    ParsingErrors::MalformedVersion(version_str.to_string())
                );
            }
        };
        if !recognized_range.matches(&file_version) {
            return Err(ParsingErrors::BadVersion(file_version));
        }
        version_obj = Some(file_version);
    } else {
        return Err(ParsingErrors::MalformedFile);
    }
    if version_str_iter.next() == None {
        return Ok(version_obj.unwrap());
    } else {
        return Err(ParsingErrors::MalformedFile);
    }
}

// Tuple is block_size, branch, hash, other_error
// TODO: tunnel full error information out when necessary
pub(crate) fn get_hash_params(string_arr: &[String; 3])
        -> (Result<u32, ParsingErrors>,
            Result<u16, ParsingErrors>,
            Result<HashFunctions, ParsingErrors>,
            Vec<ParsingErrors>) {
    let mut block_size_result: Result<u32, ParsingErrors>
            = Err(ParsingErrors::MissingParameter);
    let mut branch_factor_result: Result<u16, ParsingErrors>
            = Err(ParsingErrors::MissingParameter);
    let mut hash_function_result: Result<HashFunctions, ParsingErrors>
            = Err(ParsingErrors::MissingParameter);
    let mut other_errors: Vec<ParsingErrors> = Vec::new();
    for i in 0..3 {
        let string_split: Vec<&str> = string_arr[i].split(":").collect();
        if string_split.len() != 2 {
            other_errors.push(ParsingErrors::MalformedFile);
            break;
        }
        let (key, value) = (string_split[0], string_split[1].trim());
        match key {
            "Hash function" => {
                hash_function_result = match value.parse::<HashFunctions>() {
                    Ok(val) => Ok(val),
                    Err(_e) => Err(ParsingErrors::BadParameterValue(
                        format!("invalid hash function {}", value)
                    ))
                }
            },
            "Block size" => {
                block_size_result = match value.parse::<u32>() {
                    Ok(0) | Err(_) => Err(ParsingErrors::BadParameterValue(
                        format!("invalid block size {}", value)
                    )),
                    Ok(val) => Ok(val)
                }
            },
            "Branching factor" => {
                branch_factor_result = match value.parse::<u16>() {
                    Ok(0) | Ok(1) | Err(_) =>
                        Err(ParsingErrors::BadParameterValue(
                            format!("invalid branching factor {}", value)
                        )
                    ),
                    Ok(val) => Ok(val)
                }
            },
            _ => {
                other_errors.push(
                    ParsingErrors::UnexpectedParameter(
                        key.to_owned()
                    )
                );
            }
        }
    }
    return (block_size_result, branch_factor_result, hash_function_result, other_errors);
}

