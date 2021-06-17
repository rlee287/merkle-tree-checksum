#![forbid(unsafe_code)]

use std::io::{self, BufRead};
use semver::{Version, VersionReq};

use std::sync::Arc;
use cached::cached;

use std::str::FromStr;
use regex::Regex;
use hex::FromHex;
use crate::utils::HashFunctions;
use merkle_tree::{BlockRange, HashRange};

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
        result_tuple.1 = s[i+1..].find('"').map(|val| val+i+1)
    }
    result_tuple
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

pub(crate) fn check_version_line(version_line: &str)
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
    for string_element in string_arr {
        let string_split: Vec<&str> = string_element.split(':').collect();
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

// Using cache instead of once-cell for future flexibility
cached!{
    SHORT_REGEX_CACHE;
    fn short_hash_regex(hex_digit_count: usize) -> Arc<Regex> = {
        // hex_digits{count}  "(anything except quote | escaped quote)+" optional_newline
        let hash_regex = format!("([[:xdigit:]]{{{}}})", hex_digit_count);
        let quoted_name_regex = "(\"(?:[^\"]|\\\\\")+\")";
        let regex_str = format!("^{}  {}(?:\\n|\\r\\n)?$",
            hash_regex, quoted_name_regex);
        Arc::new(Regex::new(&regex_str).unwrap())
    }
}
pub(crate) fn extract_short_hash_parts(line: &str, hex_digit_count: usize) -> Option<(Box<[u8]>, String)> {
    let parsing_regex = short_hash_regex(hex_digit_count);
    let portions = parsing_regex.captures(line)?;
    debug_assert!(portions.len() == 3);
    let hash_hex_vec = Vec::<u8>::from_hex(&portions[1]).ok()?;
    let quoted_name = &portions[2];
    Some((hash_hex_vec.into_boxed_slice(), quoted_name.to_string()))
}

cached!{
    LONG_REGEX_CACHE;
    fn long_hash_regex(hex_digit_count: usize) -> Arc<Regex> = {
        let file_id_regex = " *([[:digit:]]+)";
        let blockrange_regex = "\\[0x([[:xdigit:]]+)-0x([[:xdigit:]]+)(\\]|\\))";
        let hash_regex = format!("([[:xdigit:]]{{{}}})", hex_digit_count);
        // rfile_id hexrange hexrange hex_digits{count} optional_newline
        let regex_str = format!("^{0} {1} {1} {2}(?:\\n|\\r\\n)?$",
            file_id_regex, blockrange_regex, hash_regex);
        Arc::new(Regex::new(&regex_str).unwrap())
    }
}
pub(crate) fn extract_long_hash_parts(line: &str, hex_digit_count: usize) -> Option<(usize, HashRange)> {
    let parsing_regex = long_hash_regex(hex_digit_count);
    let portions = parsing_regex.captures(line)?;
    debug_assert!(portions.len() == 9);
    // Use unwraps+panics as regex should ensure validity already
    let file_id = usize::from_str(&portions[1]).unwrap();
    let block_start = u64::from_str_radix(&portions[2], 16).unwrap();
    let block_end = u64::from_str_radix(&portions[3], 16).unwrap();
    let block_end_incl = match &portions[4] {
        "]" => true,
        ")" => false,
        _ => unreachable!()
    };
    let block_range = BlockRange::new(block_start, block_end, block_end_incl);

    let byte_start = u64::from_str_radix(&portions[5], 16).unwrap();
    let byte_end = u64::from_str_radix(&portions[6], 16).unwrap();
    let byte_end_incl = match &portions[7] {
        "]" => true,
        ")" => false,
        _ => unreachable!()
    };
    let byte_range = BlockRange::new(byte_start, byte_end, byte_end_incl);

    let hash_hex_vec = Vec::<u8>::from_hex(&portions[8]).ok()?;

    let hash_range = HashRange::new(block_range, byte_range, hash_hex_vec.into_boxed_slice());
    Some((file_id, hash_range))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_hash_regex_examples() {
        let short_regex = short_hash_regex(8);
        let captures_base = short_regex.captures("1f2e3d4c  \"filename_text\"\n").unwrap();
        assert_eq!(captures_base.len(), 3);
        assert_eq!(&captures_base[1], "1f2e3d4c");
        assert_eq!(&captures_base[2], "\"filename_text\"");

        let captures_w_quote = short_regex.captures("5b6a7988  \"filename with\\\" quotes\"\r\n").unwrap();
        assert_eq!(captures_base.len(), 3);
        assert_eq!(&captures_w_quote[1], "5b6a7988");
        assert_eq!(&captures_w_quote[2], "\"filename with\\\" quotes\"");
    }

    #[test]
    fn long_hash_regex_examples() {
        let long_regex = long_hash_regex(4);
        let captures_base = long_regex.captures("  1 [0x12-0x34] [0x56-0x78] 7f8a\n").unwrap();
        assert_eq!(captures_base.len(), 9);
        assert_eq!(&captures_base[1], "1");
        assert_eq!(&captures_base[2], "12");
        assert_eq!(&captures_base[3], "34");
        assert_eq!(&captures_base[4], "]");
        assert_eq!(&captures_base[5], "56");
        assert_eq!(&captures_base[6], "78");
        assert_eq!(&captures_base[7], "]");
        assert_eq!(&captures_base[8], "7f8a");
    }
}
