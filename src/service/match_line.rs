use crate::error::new_io_error;
use crate::service::version_info::{DataField, VersionInfo};
use crate::to_kebab_case;
use std::{fmt::Display, str::FromStr};

#[derive(Clone, Debug)]
pub struct Regex {
  /// 分割符 一般为 | 或者 /
  pub delimiter: char,
  /// 正则表达式
  pub schematic: String,
  // 正则标识
  pub flag: Vec<Flags>,
}

impl Display for Regex {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    if self.flag.is_empty() {
      f.write_str(&self.schematic)
    } else {
      let flag = format!(
        "(?{}){}",
        self
          .flag
          .iter()
          .map(|f| f.to_string())
          .collect::<Vec<_>>()
          .join(""),
        self.schematic
      );
      f.write_str(&flag)
    }
  }
}

#[derive(Debug, Clone, Copy)]
pub enum Flags {
  /// 区分大小写
  CaseSensitive,
  /// 忽略空格
  IgnoreWhiteSpace,
}

impl Display for Flags {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    match self {
      Flags::CaseSensitive => f.write_str("i"),
      Flags::IgnoreWhiteSpace => f.write_str("x"),
    }
  }
}

impl FromStr for Flags {
  type Err = std::io::Error;
  fn from_str(s: &str) -> crate::error::Result<Self> {
    Flags::from_char(s.chars().nth(0).unwrap())
  }
}

impl Flags {
  fn from_char(s: char) -> crate::error::Result<Self> {
    Ok(match s {
      'i' => Flags::IgnoreWhiteSpace,
      's' => Flags::CaseSensitive,
      _flag => {
        return Err(new_io_error("'i' or 's'"));
      }
    })
  }
}

#[derive(Clone, Debug)]
pub struct MatchLine {
  /// 服务名称
  pub service: String,
  /// 匹配正则
  pub pattern: Regex,
  /// 版本信息
  pub version_info: VersionInfo,
}

impl MatchLine {
  fn parse_regex(pattern_version_info: &str) -> crate::error::Result<(Regex, usize)> {
    let mut offset = 0;
    let mut cursor = pattern_version_info.chars();
    let m = cursor.next().ok_or_else(|| new_io_error("m"))?;
    offset += 1;
    return if m == 'm' {
      // |
      let delimiter = cursor.next().ok_or_else(|| new_io_error("|"))?;
      offset += 1;
      let mut regex_cursor = pattern_version_info.split(delimiter);
      regex_cursor.next().ok_or_else(|| new_io_error("|"))?;
      let pattern = regex_cursor.next().ok_or_else(|| new_io_error("pattern"))?;
      regex_cursor.next().ok_or_else(|| new_io_error("|"))?;
      // Unicode character
      cursor.nth(pattern.chars().count());
      offset += pattern.len() + 1;
      let mut flag = Vec::new();
      for c in cursor {
        offset += 1;
        match c {
          ' ' => {
            break;
          }
          _ => {
            flag.push(Flags::from_char(c)?);
          }
        }
      }
      Ok((
        Regex {
          delimiter,
          schematic: pattern.to_string(),
          flag,
        },
        offset,
      ))
    } else {
      Err(new_io_error("m"))
    };
  }
  fn parse_version_info(version_info_str: &str, version_info: &mut VersionInfo) {
    let mut head_buf = String::new();
    let mut cursor = version_info_str.chars();
    let mut current_delimiter: Option<char> = None;
    let get_data = move |cursor: &mut std::str::Chars, mut current_delimiter: Option<char>| {
      let mut data_buf = String::new();
      for cc in cursor.by_ref() {
        if current_delimiter.is_none() && cc == ' ' {
          break;
        }
        if current_delimiter.is_none() {
          continue;
        }
        if Some(cc) == current_delimiter {
          current_delimiter = None;
        } else {
          data_buf.push(cc);
        }
      }
      data_buf
    };
    while let Some(c) = cursor.next() {
      if c == '|' || c == '/' {
        current_delimiter = Some(c);
      }
      head_buf.push(c);
      if current_delimiter.is_some() {
        match head_buf.as_str().trim() {
          "p/" | "p|" => {
            let data = get_data(&mut cursor, current_delimiter);
            version_info.product_name = Some(DataField::new(data.as_str()));
            head_buf = String::new();
          }
          "v/" | "v|" => {
            let data = get_data(&mut cursor, current_delimiter);
            version_info.version = Some(DataField::new(data.as_str()));
            head_buf = String::new();
          }
          "i/" | "i|" => {
            let data = get_data(&mut cursor, current_delimiter);
            version_info.info = Some(DataField::new(data.as_str()));
            head_buf = String::new();
          }
          "h/" | "h|" => {
            let data = get_data(&mut cursor, current_delimiter);
            version_info.hostname = Some(DataField::new(data.as_str()));
            head_buf = String::new();
          }
          "o/" | "o|" => {
            let data = get_data(&mut cursor, current_delimiter);
            version_info.operating_system = Some(DataField::new(data.as_str()));
            head_buf = String::new();
          }
          "d/" | "d|" => {
            let data = get_data(&mut cursor, current_delimiter);
            version_info.device_type = Some(DataField::new(data.as_str()));
            head_buf = String::new();
          }
          "cpe:/" | "cpe:|" => {
            let data = get_data(&mut cursor, current_delimiter);
            version_info.cpe.push(DataField::new(data.as_str()));
            head_buf = String::new();
          }
          _ => {}
        }
      }
    }
  }
}

impl FromStr for MatchLine {
  type Err = std::io::Error;

  fn from_str(s: &str) -> crate::error::Result<Self> {
    if let Some((service, pattern_version_info)) = s.split_once(' ') {
      let (pattern, offset) = Self::parse_regex(pattern_version_info)?;
      let version_info_str = pattern_version_info.get(offset..);
      let mut version_info = Default::default();
      if let Some(version_info_str) = version_info_str {
        if !version_info_str.is_empty() {
          Self::parse_version_info(version_info_str, &mut version_info);
        }
      }
      Ok(MatchLine {
        service: to_kebab_case(service),
        pattern,
        version_info,
      })
    } else {
      Err(new_io_error(""))
    }
  }
}
