use crate::hans_to_pinyin;
use engine::info::{Info, Severity, VPF};
use engine::matchers::{Condition, Favicon, Matcher, MatcherType, Part, Word};
use engine::request::Requests;
use engine::template::Template;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, HashSet};
// 旧版指纹，数据结构

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebFingerPrintRequest {
  /// 请求路径
  pub path: String,
  /// 请求方法
  pub request_method: String,
  /// 请求头
  pub request_headers: BTreeMap<String, String>,
  /// 请求数据，base64编码后的
  pub request_data: String,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebFingerPrintMatch {
  /// 匹配状态码
  pub status_code: u16,
  /// 匹配favicon的hash列表
  #[serde(default)]
  pub favicon_hash: Vec<String>,
  /// 匹配的请求头
  pub headers: BTreeMap<String, String>,
  /// 匹配的关键词列表
  pub keyword: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct V3WebFingerPrint {
  /// 组件名称
  #[serde(default)]
  pub name: String,
  /// 权重
  #[serde(default)]
  pub priority: u32,
  pub fingerprint: Vec<WebFingerPrint>,
}

/// 单个指纹结构
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct WebFingerPrint {
  /// 指纹的自定义请求
  #[serde(flatten)]
  pub fingerprint: WebFingerPrintRequest,
  /// 匹配部分
  #[serde(flatten)]
  pub match_rules: WebFingerPrintMatch,
}

impl From<V3WebFingerPrint> for Template {
  fn from(val: V3WebFingerPrint) -> Self {
    let mut info = Info {
      name: val.name.to_lowercase().clone(),
      severity: Severity::Info,
      author: vec!["cn-kali-team".to_string()],
      tags: vec!["detect".to_string(), "tech".to_string()],
      ..Info::default()
    };
    info.set_vpf(VPF {
      vendor: "00_unknown".to_string(),
      product: val.name.clone(),
      framework: None,
      verified: false,
    });
    let mut index = Requests::default_web_index();
    index.http[0].operators.matchers = v3_finger_to_matcher(&val.fingerprint);
    Template {
      id: hans_to_pinyin(&val.name).to_lowercase(),
      info,
      flow: None,
      requests: index,
      self_contained: false,
      stop_at_first_match: false,
      variables: Default::default(),
    }
  }
}

fn v3_finger_to_matcher(finger: &Vec<WebFingerPrint>) -> Vec<Matcher> {
  let mut ms = Vec::new();
  let mut or_word = HashSet::new();
  let mut header = HashSet::new();
  let mut favicon = HashSet::new();
  for wfp in finger.iter() {
    header.extend(
      wfp
        .match_rules
        .headers
        .iter()
        .map(|(k, v)| {
          format!(
            "{}: {}",
            k.to_lowercase(),
            v.trim_end_matches('*').to_lowercase()
          )
        })
        .collect::<Vec<String>>(),
    );
    favicon.extend(wfp.match_rules.favicon_hash.clone());
    if wfp.match_rules.keyword.len() > 1 {
      // 多个必须AND关系
      ms.push(Matcher {
        matcher_type: MatcherType::Word(Word {
          words: wfp.match_rules.keyword.clone(),
        }),
        condition: Condition::And,
        ..Matcher::default()
      })
    } else {
      if !wfp.match_rules.favicon_hash.is_empty() {
        continue;
      }
      or_word.extend(wfp.match_rules.keyword.clone());
      // 单个OR，或者空
    }
  }
  if !header.is_empty() {
    ms.push(Matcher {
      part: Part::Header,
      matcher_type: MatcherType::Word(Word {
        words: header.into_iter().collect(),
      }),
      ..Matcher::default()
    })
  }
  if !favicon.is_empty() {
    ms.push(Matcher {
      matcher_type: MatcherType::Favicon(Favicon {
        hash: favicon.into_iter().collect(),
      }),
      ..Matcher::default()
    })
  }
  if !or_word.is_empty() {
    ms.push(Matcher {
      matcher_type: MatcherType::Word(Word {
        words: or_word.into_iter().collect(),
      }),
      condition: Condition::Or,
      ..Matcher::default()
    })
  }
  ms
}
