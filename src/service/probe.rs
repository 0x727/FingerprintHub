use crate::error::{new_io_error, Result};
use crate::service::match_line::MatchLine;
use crate::to_kebab_case;
use engine::request::PortRange;
use std::str::FromStr;
use std::time::Duration;

/// # 探针模块
/// 协议枚举
#[derive(Debug, Copy, Clone)]
pub enum Protocol {
  /// TCP
  Tcp,
  /// UDP
  Udp,
  // HTTP Nmap没有的，使用侦查守卫的Web指纹替换
  Http,
}

impl FromStr for Protocol {
  type Err = std::io::Error;

  fn from_str(s: &str) -> crate::error::Result<Self> {
    match s {
      "TCP" => Ok(Self::Tcp),
      "UDP" => Ok(Self::Udp),
      "HTTP" => Ok(Self::Http),
      _ => Err(new_io_error("not TCP,UDP,HTTP")),
    }
  }
}

impl Default for Protocol {
  fn default() -> Self {
    Self::Tcp
  }
}

/// 连接超时时间
#[derive(Debug, Clone)]
pub struct ZeroDuration(pub Duration);

impl Default for ZeroDuration {
  fn default() -> Self {
    Self(Duration::from_millis(0))
  }
}

impl FromStr for ZeroDuration {
  type Err = std::io::Error;

  fn from_str(s: &str) -> Result<Self> {
    Ok(Self(Duration::from_millis(
      s.parse::<u64>().map_err(|x| new_io_error(&x.to_string()))?,
    )))
  }
}

/// 探针数据结构
#[derive(Default, Clone, Debug)]
pub struct Probe {
  /// 探针名称
  pub name: String,
  /// 请求协议
  pub protocol: Protocol,
  /// 发送的payload请求
  pub payload: String,
  /// 总等待超时时间
  pub wait_total_ms: ZeroDuration,
  /// 连接超时时间
  pub wait_wrapped_ms: ZeroDuration,
  /// 指纹匹配列表
  pub matches: Vec<MatchLine>,
  /// 软匹配列表
  pub soft_matches: Vec<MatchLine>,
  /// 数字越高，探测就越罕见，针对服务进行尝试的可能性就越小
  pub rarity: u8,
  /// 端口列表，判断常见端口是否在当前探针的端口列表，和优先级一样，优先发送端口存在的探针
  pub ports: PortRange,
  /// tls端口，同上
  pub ssl_ports: PortRange,
  /// 回调探针，例如：当TCP探针发现是一个HTTP服务，会调用HTTP的探针继续探测一次
  pub fallback: Vec<String>,
}

impl FromStr for Probe {
  type Err = std::io::Error;
  /// Syntax: Probe <protocol> <probename> <probestring> [no-payload]
  fn from_str(s: &str) -> Result<Self> {
    // TCP GetRequest q|GET / HTTP/1.0\r\n\r\n|
    let parts: Vec<String> = s.splitn(3, ' ').map(|s| s.to_string()).collect();
    let slice = &parts;
    if parts.len() == 3 {
      let payload = slice[2]
        .trim_start_matches("q|")
        .trim_end_matches(" no-payload")
        .trim_end_matches('|')
        .to_string();
      let protocol = Protocol::from_str(&slice[0])?;
      let name = slice[1].clone();
      return Ok(Self {
        name: to_kebab_case(&name),
        protocol,
        payload,
        wait_total_ms: Default::default(),
        wait_wrapped_ms: Default::default(),
        matches: vec![],
        soft_matches: vec![],
        rarity: 0,
        ports: Default::default(),
        ssl_ports: Default::default(),
        fallback: vec![],
      });
    }
    Ok(Self::default())
  }
}
