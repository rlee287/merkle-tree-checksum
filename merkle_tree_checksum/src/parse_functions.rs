#![forbid(unsafe_code)]

use clap::crate_name;

use semver::Version;

use std::sync::{Arc, OnceLock};
use cached::cached;

use std::str::FromStr;
use regex::Regex;
use hex::FromHex;

use merkle_tree::{BlockRange, HashData, HashRange, block_t};
use crate::error_types::{FilenameExtractionError, HashExtractionError, HeaderParsingErr, SizeStrToNumErr};

const QUOTED_STR_REGEX: &str = "(\"(?:[^\"]|\\\\\")*\")";
const NEWLINE_REGEX: &str = "(?:\\n|\\r\\n)?";

static SIZE_REGEX: OnceLock<Regex> = OnceLock::new();
#[inline]
fn get_size_regex() -> &'static Regex {
    // SIZE_REGEX does not need to match normal ints
    /*
     * Capture groups:
     * 0: entire thing
     * 1: nonzero integer
     * 2: decimal number
     * 3: multiplier prefix
     * 4: whether prefix is base-10 or base-2
     */
    SIZE_REGEX.get_or_init(|| Regex::new(concat!(
        "^",
        "(?:([1-9][0-9]*)|([0-9]+\\.[0-9]+))",
        "(K|M|G)(i)?",
        "$")).unwrap())
}
static QUOTED_FILENAME_REGEX: OnceLock<Regex> = OnceLock::new();
#[inline]
fn get_quoted_filename_regex() -> &'static Regex {
    let hash_regex = "(?:[[:xdigit:]][[:xdigit:]])+";
    let length_regex = "0x([[:xdigit:]]+) bytes";
    /*
     * Capture groups:
     * 0: entire thing
     * 1: first branch of the |
     * 2: quoted string for first branch
     * 3: second branch of the |
     * 4: quoted string for the second branch
     * 5: file length for the second branch
     */
    let combined_regex = format!("^(?:({0} +{1})|({1} {2})){3}$",
        hash_regex, QUOTED_STR_REGEX, length_regex, NEWLINE_REGEX);
    QUOTED_FILENAME_REGEX.get_or_init(|| Regex::new(&combined_regex).unwrap())
}

pub(crate) fn size_str_to_num(input_str: &str) -> Result<block_t, SizeStrToNumErr> {
    match input_str.parse::<block_t>() {
        Ok(val) => Ok(val),
        Err(_) => {
            let number_parts_res = get_size_regex().captures(input_str);
            if let Some(captures) = number_parts_res {
                debug_assert!(captures.len() == 5);
                assert!(captures.get(1).is_some() ^ captures.get(2).is_some());
                let base_mult: block_t = match captures.get(4) {
                    Some(_) => 1024,
                    None => 1000
                };
                let exponent = match &captures[3] {
                    "K" => 1,
                    "M" => 2,
                    "G" => 3,
                    _ => unreachable!()
                };
                let unit_mult = base_mult.checked_pow(exponent)
                    .ok_or(SizeStrToNumErr::default())?;
                let final_val: block_t;
                if captures.get(1).is_some() {
                    let text_val: block_t = captures[1].parse().unwrap();
                    final_val = unit_mult.checked_mul(text_val)
                        .ok_or(SizeStrToNumErr::default())?;
                } else if captures.get(2).is_some() {
                    // f64 can represent integers beyond u32 so no issue here
                    let mut text_val: f64 = captures[2].parse::<f64>().unwrap();
                    text_val *= unit_mult as f64;
                    assert!(text_val >= 0.0);
                    if text_val > block_t::MAX.into() {
                        return Err(SizeStrToNumErr::default());
                    }
                    // Overflow was previously checked-for
                    final_val = text_val.trunc() as block_t;
                } else {
                    unreachable!();
                }
                Ok(final_val)
            } else {
                Err(SizeStrToNumErr::default())
            }
        }
    }
}

// (String, Option<u64>) is (quoted_filename, file_len_if_present)
pub(crate) fn extract_quoted_filename(line: &str) -> Result<(&str, Option<u64>), FilenameExtractionError> {
    let line_portions = get_quoted_filename_regex().captures(line).ok_or(FilenameExtractionError::default())?;
    debug_assert!(line_portions.len() == 6);
    if line_portions.get(1).is_some() {
        Ok((line_portions.get(2).unwrap().as_str(), None))
    } else {
        debug_assert!(line_portions.get(3).is_some());
        Ok((line_portions.get(4).unwrap().as_str(),
            Some(u64::from_str_radix(&line_portions[5], 16).unwrap())))
    }
}

pub(crate) fn parse_version_line(version_line: &str)
        -> Result<Version, HeaderParsingErr> {
    let mut version_str_iter = version_line.split_whitespace();
    let version_obj: Option<Version>;
    if let Some(name_check) = version_str_iter.next() {
        if name_check != crate_name!() {
            return Err(HeaderParsingErr::MalformedFile);
        }
    } else {
        return Err(HeaderParsingErr::MalformedFile);
    }
    if let Some(version_str_token) = version_str_iter.next() {
        if !version_str_token.starts_with('v') {
            return Err(
                HeaderParsingErr::MalformedVersion(version_str_token.to_string())
            );
        }
        let version_str = &version_str_token[1..];
        let file_version = match Version::parse(version_str) {
            Ok(v) => v,
            Err(_e) => {
                return Err(
                    HeaderParsingErr::MalformedVersion(version_str.to_string())
                );
            }
        };
        version_obj = Some(file_version);
    } else {
        return Err(HeaderParsingErr::MalformedFile);
    }
    if version_str_iter.next().is_none() {
        return Ok(version_obj.unwrap());
    } else {
        return Err(HeaderParsingErr::MalformedFile);
    }
}

// Using cache instead of once-cell for future flexibility
cached!{
    SHORT_REGEX_CACHE;
    fn short_hash_regex(hex_digit_count: usize) -> Arc<Regex> = {
        // hex_digits{count}  "(anything except quote | escaped quote)+" optional_newline
        let hash_regex = format!("([[:xdigit:]]{{{}}})", hex_digit_count);
        /*
         * Capture groups:
         * 0: entire thing
         * 1: hexadecimal hash
         * 2: quoted filename
         */
        let regex_str = format!("^{} +{}{}$",
            hash_regex, QUOTED_STR_REGEX, NEWLINE_REGEX);
        Arc::new(Regex::new(&regex_str).unwrap())
    }
}
pub(crate) fn extract_short_hash_parts(line: &str, hex_digit_count: usize) -> Result<(HashData<64>, &str), HashExtractionError> {
    let parsing_regex = short_hash_regex(hex_digit_count);
    let portions = parsing_regex.captures(line)
        .ok_or(HashExtractionError::default())?;
    debug_assert!(portions.len() == 3);
    let hash_hex = HashData::from_hex(&portions[1])
        .map_err(|_| HashExtractionError::default())?;
    let quoted_name = portions.get(2).unwrap();
    Ok((hash_hex, &line[quoted_name.range()]))
}

cached!{
    LONG_REGEX_CACHE;
    fn long_hash_regex(hex_digit_count: usize) -> Arc<Regex> = {
        let file_id_regex = " *([[:digit:]]+)";
        let blockrange_regex = "\\[0x([[:xdigit:]]+)-0x([[:xdigit:]]+)(\\]|\\))";
        let hash_regex = format!("([[:xdigit:]]{{{}}})", hex_digit_count);
        // rfile_id hexrange hexrange hex_digits{count} optional_newline
        /*
         * Capture groups:
         * 0: entire thing
         * 1: file id counter
         * 2: start block, in hexadecimal
         * 3: end block, in hexadecimal
         * 4: whether the block range includes the end
         * 5: start file byte, in hexadecimal
         * 6: end file byte, in hexadecimal
         * 7: whether the byte range includes the end
         * 8: hexadecimal hash
         */
        let regex_str = format!("^{0} {1} {1} {2}{3}$",
            file_id_regex, blockrange_regex, hash_regex, NEWLINE_REGEX);
        Arc::new(Regex::new(&regex_str).unwrap())
    }
}
pub(crate) fn extract_long_hash_parts(line: &str, hex_digit_count: usize) -> Result<(usize, HashRange), HashExtractionError> {
    let parsing_regex = long_hash_regex(hex_digit_count);
    let portions = parsing_regex.captures(line)
        .ok_or(HashExtractionError::default())?;
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

    let hash_hex = HashData::from_hex(&portions[8]).map_err(|_| HashExtractionError::default())?;

    let hash_range = HashRange::new(block_range, byte_range, hash_hex);
    Ok((file_id, hash_range))
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
