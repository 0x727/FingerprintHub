use crate::{to_kebab_case, FingerPrintParse, MatchLine, Probe};
use engine::common::http::murmur3_32;
use engine::extractors::{Extractor, ExtractorType};
use engine::info::{Info, Severity, VPF};
use engine::matchers::{Matcher, Part};
use engine::operators::Operators;
use engine::request::{Input, Requests, TCPRequest};
use engine::serde_format::Value;
use engine::template::Template;
use std::env;
use std::fs::File;

fn matchline_to_ext(m: &MatchLine) -> Extractor {
  Extractor {
    name: Some(m.service.clone()),
    part: Part::default(),
    extractor_type: ExtractorType::Regex(engine::extractors::ERegex {
      regex: vec![m.pattern.to_string()],
      group: None,
    }),
    internal: false,
    case_insensitive: false,
    regex: Vec::new(),
  }
}

fn matchline_to_op(m: Vec<Matcher>, e: Vec<Extractor>) -> Operators {
  Operators {
    stop_at_first_match: false,
    matchers_condition: Default::default(),
    matchers: m,
    extractors: e,
  }
}

fn probe_to_request(fp: &Probe, op: Operators) -> Requests {
  let tcp = TCPRequest {
    operators: op,
    id: None,
    name: Some(fp.name.clone()),
    host: vec!["{{Hostname}}".to_string()],
    payload_attack: None,
    threads: None,
    inputs: vec![Input {
      data: Some(fp.payload.clone()),
      read: None,
    }],
    port: if fp.ports.is_empty() {
      None
    } else {
      Some(fp.ports.clone())
    },
    exclude_ports: None,
    read_size: None,
    read_all: false,
  };
  Requests {
    tcp: vec![tcp],
    ..Requests::default()
  }
}

fn match_line_to_info(m: &MatchLine, fp: &Probe) -> Info {
  let mut info = Info {
    severity: Severity::Info,
    author: vec!["nmap".to_string(), "cn-kali-team".to_string()],
    tags: vec![
      "detect".to_string(),
      "tech".to_string(),
      m.service.to_string(),
      "service".to_string(),
    ],
    ..Info::default()
  };

  if let Some(product) = &m.version_info.product_name {
    info.name = product.to_string();
  }
  if let Some(i) = &m.version_info.info {
    if info.name.is_empty() {
      info.name = i.to_string()
    }
  }
  if !fp.fallback.is_empty() {
    info.metadata.insert(
      "fallback".to_string(),
      Value::List(
        fp.fallback
          .iter()
          .map(|x| Value::String(to_kebab_case(x)))
          .collect(),
      ),
    );
  }
  info
    .metadata
    .insert("rarity".to_string(), Value::Num(fp.rarity as u32));
  if let Some(os) = &m.version_info.info {
    info.metadata.insert(
      "info".to_string(),
      engine::serde_format::Value::String(os.to_string()),
    );
  }
  if let Some(os) = &m.version_info.operating_system {
    info.metadata.insert(
      "operating_system".to_string(),
      engine::serde_format::Value::String(os.to_string()),
    );
  }
  if let Some(v) = &m.version_info.version {
    info.metadata.insert(
      "version".to_string(),
      engine::serde_format::Value::String(v.to_string()),
    );
  }
  if let Some(h) = &m.version_info.hostname {
    info.metadata.insert(
      "hostname".to_string(),
      engine::serde_format::Value::String(h.to_string()),
    );
  }
  if let Some(d) = &m.version_info.device_type {
    info.metadata.insert(
      "device_type".to_string(),
      engine::serde_format::Value::String(d.to_string()),
    );
  }
  if !m.version_info.cpe.is_empty() {
    for cpe in m.version_info.cpe.iter() {
      let uri = format!("cpe:2.3:{}{}", cpe.to_string(), ":".repeat(10 - cpe.to_string().matches(':').count()));
      let cpe_uri = nvd_cpe::CPEName::from_uri(&uri).unwrap();
      match cpe_uri.part.to_string().as_str() {
        "a" => {
          info.set_vpf(VPF {
            vendor: cpe_uri.vendor.to_string(),
            product: cpe_uri.product.to_string(),
            framework: None,
            verified: false,
          })
        }
        _ => {}
      }
    }
  }
  info
}

fn to_template(fp: &Probe, m: &MatchLine) -> Template {
  let info = match_line_to_info(m, fp);
  Template {
    id: to_kebab_case(&m.service),
    info,
    flow: None,
    requests: probe_to_request(fp, matchline_to_op(vec![], vec![matchline_to_ext(m)])),
    self_contained: Default::default(),
    stop_at_first_match: false,
    variables: Default::default(),
  }
}

pub fn nmap() {
  let p = include_str!("service/nmap-service-probes");
  let f = FingerPrintParse::new(p).parse().unwrap();
  let current_fingerprint_dir = env::current_dir().unwrap().join("service-fingerprint");
  for fp in f {
    // println!("探针名称:{}", to_kebab_case(&fp.name));
    // 没有产品或者描述的
    let probe_name = fp.name.clone();
    let probe_dir = current_fingerprint_dir.join(&probe_name);
    for m in fp.matches.iter() {
      let service_dir = probe_dir.join(&m.service);
      std::fs::create_dir_all(&service_dir).unwrap_or_default();
      let template = to_template(&fp, m);
      let hash = murmur3_32(m.pattern.to_string().as_bytes(), 0) as u32;
      let template_path = service_dir.join(&format!("{}.yaml", hash));
      if let Ok(f) = File::create(&template_path) {
        serde_yaml::to_writer(f, &template).unwrap();
      }
    }
  }
}
