#![forbid(unsafe_code)]

#[inline]
pub(crate) fn title_center(title: &str) -> String {
    let space_padded = format!(" {} ", title);
    format!("{:=^80}", space_padded)
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