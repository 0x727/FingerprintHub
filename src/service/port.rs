use crate::error::{new_io_error, Result};
use std::ops::Range;

// 端口，支持单个端口和范围：80，443-1024
#[derive(Debug, Clone, PartialEq, Eq, Hash, Default)]
pub struct PortRange {
  /// 单个端口列表
  single: Vec<u16>,
  /// 范围端口列表
  range: Vec<Range<u16>>,
}

impl PortRange {
  /// 判断是否存在给定端口
  pub fn contains(&self, other: u16) -> bool {
    self.single.contains(&other) || self.range.iter().any(|p| p.contains(&other))
  }
}

impl std::str::FromStr for PortRange {
  type Err = std::io::Error;

  /// Accepts '80-443', '80', '0-10'
  fn from_str(src: &str) -> Result<Self> {
    port_parser(src)
  }
}

pub fn port_parser(src: &str) -> Result<PortRange> {
  let port_list: Vec<&str> = src.split(',').collect();
  let mut single = Vec::new();
  let mut range = Vec::new();
  // Exclude 53,T:9100,U:30000-40000
  let m: &[_] = &['T', 'U', ':'];
  for port in port_list {
    if let Some((start, end)) = port.split_once('-') {
      range.push(
        start.trim_start_matches(m).parse::<u16>().map_err(|x|new_io_error(&x.to_string()))?..end.trim_start_matches(m).parse::<u16>().map_err(|x|new_io_error(&x.to_string()))?,
      )
    } else {
      single.push(port.trim_start_matches(m).parse::<u16>().map_err(|x|new_io_error(&x.to_string()))?)
    }
  }
  Ok(PortRange { single, range })
}
