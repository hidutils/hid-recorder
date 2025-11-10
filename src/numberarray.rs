// SPDX-License-Identifier: MIT
//

use anyhow::Result;
use std::path::Path;

use crate::{Backend, BpfOption, EventNode, ReportDescriptor};

#[derive(Debug)]
pub struct NumberArrayBackend {
    name: String,
    bustype: u32,
    vid: u32,
    pid: u32,
    rdesc: Vec<u8>,
}

impl TryFrom<&Path> for NumberArrayBackend {
    type Error = anyhow::Error;

    fn try_from(path: &Path) -> Result<Self> {
        let data: String = std::fs::read_to_string(path)?;

        // Formats supported:
        // 01020304...
        // 01 02 03 04...
        // 01, 02, 03, 04...
        // [01, 02, 03, 04...]
        //
        // And all of the above as 0x01

        let data = data.trim().trim_start_matches('[').trim_end_matches(']');
        let has_separators = data.chars().any(|c| c.is_whitespace() || c == ',');

        let rdesc = if has_separators {
            data.split(|c: char| c.is_whitespace() || c == ',')
                .filter(|s| !s.is_empty())
                .map(|token| {
                    let hex_str = token
                        .trim()
                        .strip_prefix("0x")
                        .or_else(|| token.trim().strip_prefix("0X"))
                        .unwrap_or(token.trim());

                    u8::from_str_radix(hex_str, 16)
                        .map_err(|e| anyhow::anyhow!("Failed to parse '{}' as hex: {}", token, e))
                })
                .collect::<Result<Vec<u8>>>()?
        } else {
            let hex_str = data
                .strip_prefix("0x")
                .or_else(|| data.strip_prefix("0X"))
                .unwrap_or(data);

            if hex_str.len() % 2 != 0 {
                anyhow::bail!("Continuous hex string must have an even number of digits");
            }

            (0..hex_str.len())
                .step_by(2)
                .map(|i| {
                    let pair = &hex_str[i..i + 2];
                    u8::from_str_radix(pair, 16)
                        .map_err(|e| anyhow::anyhow!("Failed to parse '{}' as hex: {}", pair, e))
                })
                .collect::<Result<Vec<u8>>>()?
        };

        Ok(NumberArrayBackend {
            name: String::from("No Name"),
            bustype: 0x0,
            vid: 0x0,
            pid: 0x0,
            rdesc,
        })
    }
}

impl Backend for NumberArrayBackend {
    fn name(&self) -> &str {
        &self.name
    }

    fn bustype(&self) -> u32 {
        self.bustype
    }

    fn vid(&self) -> u32 {
        self.vid
    }

    fn pid(&self) -> u32 {
        self.pid
    }

    fn rdesc(&self) -> &[u8] {
        &self.rdesc
    }

    fn event_nodes(&self) -> &[EventNode] {
        &[]
    }

    fn read_events(&self, _use_bpf: BpfOption, _rdesc: &ReportDescriptor) -> Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use tempfile::NamedTempFile;

    fn create_temp_file_with_content(content: &str) -> NamedTempFile {
        let mut file = NamedTempFile::new().unwrap();
        file.write_all(content.as_bytes()).unwrap();
        file.flush().unwrap();
        file
    }

    fn parse_from_string(content: &str) -> Result<Vec<u8>> {
        let file = create_temp_file_with_content(content);
        let backend = NumberArrayBackend::try_from(file.path())?;
        Ok(backend.rdesc)
    }

    #[test]
    fn test_space_separated() {
        let result = parse_from_string("01 02 03 04 05").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_comma_separated() {
        let result = parse_from_string("01, 02, 03, 04, 05").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_bracketed() {
        let result = parse_from_string("[01, 02, 03, 04, 05]").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_space_separated_with_0x_prefix() {
        let result = parse_from_string("0x01 0x02 0x03 0x04 0x05").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_comma_separated_with_0x_prefix() {
        let result = parse_from_string("0x01, 0x02, 0x03, 0x04, 0x05").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_bracketed_with_0x_prefix() {
        let result = parse_from_string("[0x01, 0x02, 0x03, 0x04, 0x05]").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_uppercase_0x_prefix() {
        let result = parse_from_string("0X01 0X02 0X03").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_mixed_spacing_and_commas() {
        let result = parse_from_string("01, 02  03,04 05").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04, 0x05]);
    }

    #[test]
    fn test_mixed_prefix_formats() {
        let result = parse_from_string("0x01, 02, 0x03, 04").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_single_value() {
        let result = parse_from_string("ff").unwrap();
        assert_eq!(result, vec![0xff]);
    }

    #[test]
    fn test_single_value_with_prefix() {
        let result = parse_from_string("0xff").unwrap();
        assert_eq!(result, vec![0xff]);
    }

    #[test]
    fn test_uppercase_hex() {
        let result = parse_from_string("AA BB CC DD EE FF").unwrap();
        assert_eq!(result, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_lowercase_hex() {
        let result = parse_from_string("aa bb cc dd ee ff").unwrap();
        assert_eq!(result, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_mixed_case_hex() {
        let result = parse_from_string("Aa bB Cc dD Ee Ff").unwrap();
        assert_eq!(result, vec![0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    }

    #[test]
    fn test_two_digit_values() {
        let result = parse_from_string("00 01 7f 80 fe ff").unwrap();
        assert_eq!(result, vec![0x00, 0x01, 0x7f, 0x80, 0xfe, 0xff]);
    }

    #[test]
    fn test_with_newlines() {
        let result = parse_from_string("01\n02\n03\n04").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_with_tabs() {
        let result = parse_from_string("01\t02\t03\t04").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_with_multiple_spaces() {
        let result = parse_from_string("01    02     03").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_with_leading_trailing_whitespace() {
        let result = parse_from_string("  01 02 03  ").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_bracketed_with_whitespace() {
        let result = parse_from_string("  [ 01, 02, 03 ]  ").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03]);
    }

    #[test]
    fn test_realistic_hid_descriptor() {
        let result =
            parse_from_string("05 01 09 06 a1 01 05 07 19 e0 29 e7 15 00 25 01 75 01 95 08 81 02")
                .unwrap();
        assert_eq!(
            result,
            vec![
                0x05, 0x01, 0x09, 0x06, 0xa1, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00,
                0x25, 0x01, 0x75, 0x01, 0x95, 0x08, 0x81, 0x02
            ]
        );
    }

    #[test]
    fn test_invalid_hex() {
        let result = parse_from_string("01 02 GG 04");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_value_too_large() {
        let result = parse_from_string("01 02 100 04");
        assert!(result.is_err());
    }

    #[test]
    fn test_invalid_characters() {
        let result = parse_from_string("01 02 xyz 04");
        assert!(result.is_err());
    }

    #[test]
    fn test_empty_string() {
        let result = parse_from_string("").unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_whitespace_only() {
        let result = parse_from_string("   \n\t  ").unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_empty_brackets() {
        let result = parse_from_string("[]").unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_backend_properties() {
        let file = create_temp_file_with_content("01 02 03");
        let backend = NumberArrayBackend::try_from(file.path()).unwrap();

        assert_eq!(backend.name(), "No Name");
        assert_eq!(backend.bustype(), 0x0);
        assert_eq!(backend.vid(), 0x0);
        assert_eq!(backend.pid(), 0x0);
        assert_eq!(backend.rdesc(), &[0x01, 0x02, 0x03]);
        assert_eq!(backend.event_nodes().len(), 0);
    }

    // Tests for continuous hex string format (no separators)
    #[test]
    fn test_continuous_hex_string() {
        let result = parse_from_string("01020304").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_continuous_hex_string_mixed_case() {
        let result = parse_from_string("01ab02cd").unwrap();
        assert_eq!(result, vec![0x01, 0xab, 0x02, 0xcd]);
    }

    #[test]
    fn test_continuous_hex_string_uppercase() {
        let result = parse_from_string("AABBCCDD").unwrap();
        assert_eq!(result, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn test_continuous_hex_string_lowercase() {
        let result = parse_from_string("aabbccdd").unwrap();
        assert_eq!(result, vec![0xaa, 0xbb, 0xcc, 0xdd]);
    }

    #[test]
    fn test_continuous_hex_string_with_0x_prefix() {
        let result = parse_from_string("0x01020304").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_continuous_hex_string_with_uppercase_0x_prefix() {
        let result = parse_from_string("0X01ab02cd").unwrap();
        assert_eq!(result, vec![0x01, 0xab, 0x02, 0xcd]);
    }

    #[test]
    fn test_continuous_hex_string_single_byte() {
        let result = parse_from_string("ff").unwrap();
        assert_eq!(result, vec![0xff]);
    }

    #[test]
    fn test_continuous_hex_string_long() {
        let result = parse_from_string("0501090601050719e029e71500250175019508").unwrap();
        assert_eq!(
            result,
            vec![
                0x05, 0x01, 0x09, 0x06, 0x01, 0x05, 0x07, 0x19, 0xe0, 0x29, 0xe7, 0x15, 0x00, 0x25,
                0x01, 0x75, 0x01, 0x95, 0x08
            ]
        );
    }

    #[test]
    fn test_continuous_hex_string_bracketed() {
        let result = parse_from_string("[01020304]").unwrap();
        assert_eq!(result, vec![0x01, 0x02, 0x03, 0x04]);
    }

    #[test]
    fn test_continuous_hex_string_bracketed_with_prefix() {
        let result = parse_from_string("[0x01ab02cd]").unwrap();
        assert_eq!(result, vec![0x01, 0xab, 0x02, 0xcd]);
    }

    #[test]
    fn test_continuous_hex_string_odd_length() {
        let result = parse_from_string("01020");
        assert!(result.is_err());
        assert!(result.unwrap_err().to_string().contains("even number"));
    }

    #[test]
    fn test_continuous_hex_string_invalid_char() {
        let result = parse_from_string("0102GG04");
        assert!(result.is_err());
    }

    #[test]
    fn test_continuous_hex_empty() {
        let result = parse_from_string("").unwrap();
        assert_eq!(result, Vec::<u8>::new());
    }

    #[test]
    fn test_continuous_vs_separated_distinction() {
        // With space separator - should parse each as separate bytes
        let separated = parse_from_string("1 2 3").unwrap();
        assert_eq!(separated, vec![0x01, 0x02, 0x03]);

        // Without separator - should parse pairs
        let continuous = parse_from_string("010203").unwrap();
        assert_eq!(continuous, vec![0x01, 0x02, 0x03]);
    }
}
