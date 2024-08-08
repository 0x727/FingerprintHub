pub mod cli;
mod error;
pub mod nmap;
mod service;
mod v3;

pub use v3::{WebFingerPrint, V3WebFingerPrint};
use crate::error::{new_io_error, Result};
pub use crate::service::match_line::MatchLine;
pub use crate::service::probe::{Probe, ZeroDuration};
use engine::request::PortRange;
use std::str::{FromStr, Lines};
use pinyin::ToPinyin;

// 转下划线风格
pub fn to_kebab_case(input: &str) -> String {
  let mut result = String::new();
  let mut prev_is_uppercase = false;
  let mut prev_is_underscore = false;
  let mut prev_is_hyphen = false;

  for (i, ch) in input.replace(' ', "-").chars().enumerate() {
    if ch == '_' || ch == '-' || ch == ' ' {
      result.push(ch);
      prev_is_uppercase = false; // reset the uppercase flag when encountering '_' or '-'
      prev_is_underscore = ch == '_';
      prev_is_hyphen = ch == '-';
    } else if ch.is_uppercase() {
      if i != 0 && !prev_is_uppercase && !prev_is_underscore && !prev_is_hyphen {
        result.push('-');
      }
      result.push(ch.to_ascii_lowercase());
      prev_is_uppercase = true;
      prev_is_underscore = false;
      prev_is_hyphen = false;
    } else {
      result.push(ch);
      prev_is_uppercase = false;
      prev_is_underscore = false;
      prev_is_hyphen = false;
    }
  }

  result.replace("_-", "-")
}

// https://nmap.org/book/vscan-fileformat.html
#[derive(Clone, Debug)]
pub struct FingerPrintParse<'buffer> {
  // 当前行数
  current_line: usize,
  offset: usize,
  lines: Lines<'buffer>,
  exclude_port: PortRange,
  probes: Vec<Probe>,
}

impl<'buffer> FingerPrintParse<'buffer> {
  pub fn new(buffer: &str) -> FingerPrintParse {
    let lines = buffer.lines();
    FingerPrintParse {
      current_line: 0,
      offset: 0,
      lines,
      exclude_port: PortRange::default(),
      probes: Default::default(),
    }
  }
  fn next(&mut self) -> Option<&'buffer str> {
    match self.lines.next() {
      Some(line) => {
        self.current_line += 1;
        Some(line)
      }
      None => None,
    }
  }
}

impl<'buffer> FingerPrintParse<'buffer> {
  pub fn parse(&mut self) -> Result<Vec<Probe>> {
    // 获取排除端口
    self.exclude_port = self.exclude_port()?;
    let mut current_probe = Probe::default();
    while let Some(line) = self.next() {
      // 跳过注释和空行
      if line.starts_with('#') || line.is_empty() {
        continue;
      }
      self.offset = 0;
      if let Some((action, payload)) = line.split_once(' ') {
        self.offset += action.len();
        match action {
          // Syntax: Probe <protocol> <probename> <probestring> [no-payload]
          "Probe" => {
            // 忽略第一个默认探针
            if !current_probe.name.is_empty() {
              self.probes.push(current_probe.clone());
            }
            current_probe = Probe::from_str(payload)?;
          }
          // Syntax: totalwaitms <milliseconds>
          "totalwaitms" => {
            current_probe.wait_total_ms = ZeroDuration::from_str(payload)?;
          }
          // Syntax: tcpwrappedms <milliseconds>
          "tcpwrappedms" => {
            current_probe.wait_wrapped_ms = ZeroDuration::from_str(payload)?;
          }
          // Syntax: match <service> <pattern> [<versioninfo>]
          "match" => {
            current_probe.matches.push(MatchLine::from_str(payload)?);
          }
          // Syntax: softmatch <service> <pattern>
          "softmatch" => {
            current_probe
              .soft_matches
              .push(MatchLine::from_str(payload)?);
          }
          // Syntax: rarity <value between 1 and 9>
          "rarity" => {
            current_probe.rarity =
              u8::from_str(payload).map_err(|x| new_io_error(&x.to_string()))?;
          }
          // Syntax: ports <portlist>
          "ports" => {
            current_probe.ports =
              PortRange::from_str(payload).map_err(|e| new_io_error(&e.to_string()))?;
          }
          // Syntax: sslports <portlist>
          "sslports" => {
            current_probe.ssl_ports =
              PortRange::from_str(payload).map_err(|e| new_io_error(&e.to_string()))?;
          }
          // Syntax: fallback <Comma separated list of probes>
          "fallback" => {
            current_probe.fallback = payload.split(',').map(|s| s.to_string()).collect();
          }
          _ => {
            println!("{:?},{:?}", action, payload);
            break;
          }
        }
      }
    }
    // 补充最后一个探针
    if !current_probe.name.is_empty() {
      self.probes.push(current_probe.clone());
    }
    Ok(self.probes.clone())
  }
  // 排除端口
  fn exclude_port(&mut self) -> Result<PortRange> {
    while let Some(line) = self.next() {
      // 跳过注释和空行
      if line.starts_with('#') || line.is_empty() {
        continue;
      }
      // Syntax: Exclude <port specification>
      if line.starts_with("Exclude ") {
        return PortRange::from_str(line.trim_start_matches("Exclude "))
          .map_err(|e| new_io_error(&e.to_string()));
      }
    }
    Err(new_io_error("exclude"))
  }
}

pub fn hans_to_pinyin(hans: &str) -> String {
  let mut pinyin_str = String::new();
  let mut is_han = false;
  let mut is_letter = false;
  for c in hans.chars() {
    if let Some(py) = c.to_pinyin() {
      if is_han || is_letter {
        pinyin_str.push('-');
      }
      pinyin_str.push_str(py.plain());
      is_han = true;
      is_letter = false;
    } else {
      if is_han {
        pinyin_str.push('-');
        is_han = false;
      }
      is_letter = true;
      pinyin_str.push(c);
    }
  }
  pinyin_str = pinyin_str.replace(" ", "-");
  pinyin_str = pinyin_str.replacen("--", "-", 10);
  pinyin_str
}

#[cfg(test)]
mod tests {
  #[test]
  fn it_works() {}
}
