use engine::common::http::murmur3_32;
use engine::extractors::{Extractor, ExtractorType};
use engine::find_yaml_file;
use engine::info::{Info, Severity};
use engine::matchers::{Favicon, Matcher, MatcherType, Part};
use engine::operators::Operators;
use engine::request::{HttpRaw, Input, Requests, TCPRequest};
use engine::template::Template;
use helper::{to_kebab_case, FingerPrintParse, MatchLine, Probe};
use std::collections::BTreeMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::path::Path;
use std::str::FromStr;

const BUILT_TAGS: [&str; 59] = [
  "misconfig",
  "fileupload",
  "intrusive",
  "php",
  "hackerone",
  "oob",
  "authenticated",
  "oss",
  "deserialization",
  "db",
  "c2",
  "panel",
  "detect",
  "default-login",
  "miscellaneous",
  "token-spray",
  "tech",
  "phishing",
  "cloud",
  "sql",
  "bypass",
  "exposure",
  "wp-theme",
  "dos",
  "info",
  "misc",
  "exposure",
  "config",
  "lfr",
  "auth",
  "login",
  "fuzz",
  "xxe",
  "packetstorm",
  "crlf",
  "auth-bypass",
  "injection",
  "ssti",
  "rfi",
  "redirect",
  "vulhub",
  "xmlswf",
  "plugin",
  "wp",
  "xss",
  "lfi",
  "edb",
  "cms",
  "sqli",
  "rce",
  "msf",
  "kev",
  "iot",
  "wordpress",
  "wp-plugin",
  "wpscan",
  "unauth",
  "ssrf",
  "oast",
];

fn remove_built_tags(tags: &[String]) -> Vec<String> {
  let mut tags = tags.to_owned();
  tags.retain(|x| {
    !(BUILT_TAGS.contains(&x.as_str())
      || x.starts_with("top-")
      || x.starts_with("cve")
      || x.starts_with("osint")
      || x.starts_with("cnvd"))
  });
  tags
}

fn sync_nuclei() {
  //
  let mut yaml_paths = Vec::new();
  for path in ["cnvd", "cves", "default-logins", "vulnerabilities"] {
    let y = format!(
      "/home/kali-team/IdeaProjects/nuclei-templates/http/{}",
      path
    );
    yaml_paths.extend(find_yaml_file(&Path::new(&y).to_path_buf(), true));
  }
  let mut count = 0;
  let current_dir = env::current_dir().unwrap().join("plugins");
  for yaml_path in yaml_paths {
    if let Ok(f) = File::open(&yaml_path) {
      match serde_yaml::from_reader::<std::fs::File, Template>(f) {
        Ok(template) => {
          // 先挑选有cpe和厂商和产品的yaml。如果有分类复制文件后跳过
          if let Some(vpf) = template.info.get_vpf() {
            // 如果有框架的直接复制到框架文件夹，注：只针对wordpress
            let mut default_path = current_dir.join(&vpf.vendor).join(&vpf.product);
            if let Some(framework) = vpf.framework {
              if framework.as_str() == "wordpress" {
                let wp_path = current_dir.join("wordpress").join("wordpress");
                let _ = std::fs::remove_dir_all(default_path);
                // 如果剩下的文件夹为空，删除
                let _ = std::fs::remove_dir(&current_dir.join(&vpf.vendor));
                default_path = wp_path;
              }
            }
            std::fs::create_dir_all(&default_path).unwrap();
            let f_path =
              default_path.join(&yaml_path.file_name().unwrap().to_string_lossy().to_string());
            std::fs::copy(&yaml_path, &f_path).unwrap();
            count += 1;
            continue;
          }
          // 根据tags分类
          let tags = remove_built_tags(&template.info.tags);
          let mut has_vendor = false;
          let mut has_product = false;
          for tag in tags.iter() {
            if current_dir.join(tag).is_dir() {
              has_vendor = true;
              for sub_tag in tags.iter() {
                // 厂商和产品不一样
                if current_dir.join(tag).join(sub_tag).is_dir() && sub_tag != tag {
                  has_product = true;
                  let _ = std::fs::copy(
                    &yaml_path,
                    current_dir
                      .join(tag)
                      .join(sub_tag)
                      .join(yaml_path.file_name().unwrap().to_string_lossy().to_string()),
                  )
                  .unwrap();
                  break;
                }
              }
              if !has_product && tags.len() == 1 {
                has_product = true;
                let product = tags.first().unwrap();
                let _ = std::fs::create_dir_all(current_dir.join(tag).join(product));
                let _ = std::fs::copy(
                  &yaml_path,
                  current_dir
                    .join(tag)
                    .join(product)
                    .join(yaml_path.file_name().unwrap().to_string_lossy().to_string()),
                )
                .unwrap();
              }
              continue;
            }
          }
          if has_vendor {
            if !has_product {
              // 有厂商没有产品
              println!("{:?}", yaml_path);
              println!("{:?}", tags);
            }
          } else {
            // 什么都匹配不到
            // println!("{:?}", yaml_path);
            // println!("{:?}", tags);
          }
        }
        Err(err) => {
          println!("-----   {:?}   -----", yaml_path);
          println!("{:?}", err);
        }
      };
    }
  }
  println!("{}", count);
}

fn rename_fingerprint_yaml() {
  let current_plugin_dir = env::current_dir().unwrap().join("plugins");
  let current_fingerprint_dir = env::current_dir().unwrap().join("web-fingerprint");
  let yaml_paths = find_yaml_file(&current_fingerprint_dir.join("00_unknown"), false);
  let all_vs: Vec<String> = std::fs::read_dir(&current_plugin_dir)
    .unwrap()
    .map(|p| p.unwrap().file_name().to_string_lossy().to_string())
    .collect();
  for yaml_path in yaml_paths {
    if let Ok(f) = File::open(&yaml_path) {
      match serde_yaml::from_reader::<std::fs::File, Template>(f) {
        Ok(template) => {
          let vpf = template.info.get_vpf();
          if all_vs.contains(&template.id) {
            let same = current_plugin_dir.join(&template.id);
            if same.is_dir() {
              let finger = same.join(format!("{}.yaml", &template.id));
              std::fs::rename(&yaml_path, finger).unwrap();
              continue;
            }
          }
          if let Some((v, p)) = template.id.split_once('-') {
            if all_vs.contains(&v.to_string()) {
              let same = current_plugin_dir.join(v);
              let path = same.join(p);
              if path.is_dir() {
                let finger = same.join(format!("{}.yaml", p));
                std::fs::rename(&yaml_path, finger).unwrap();
                continue;
              }
            }
          };
          if let Some(vpf) = vpf {
            if vpf.vendor == "00_unknown" {
              continue;
            }
            let p = current_plugin_dir.join(&vpf.vendor).join(&vpf.product);
            if p.exists() && p.is_dir() {
              std::fs::create_dir_all(current_fingerprint_dir.join(&vpf.vendor)).unwrap();
              let finger = current_fingerprint_dir
                .join(&vpf.vendor)
                .join(format!("{}.yaml", vpf.product));
              std::fs::rename(&yaml_path, finger).unwrap();
              continue;
            }
          }
        }
        Err(err) => {
          println!("{}", err)
        }
      }
    }
  }
  for name in all_vs.iter() {
    for yaml_path in find_yaml_file(&current_plugin_dir.join(name), false) {
      let finger_path = current_fingerprint_dir.join(name);
      std::fs::create_dir_all(&finger_path).unwrap();
      std::fs::rename(&yaml_path, finger_path.join(yaml_path.file_name().unwrap())).unwrap();
    }
  }
}

fn format() {
  let current_fingerprint_dir = env::current_dir().unwrap().join("web-fingerprint");
  let all_finger = find_yaml_file(&current_fingerprint_dir, true);
  for yaml_path in all_finger {
    let f = File::open(&yaml_path).unwrap();
    let mut new_template = None;
    if let Ok(mut template) = serde_yaml::from_reader::<std::fs::File, Template>(f) {
      for http in template.requests.http.iter_mut() {
        for matchers in http.operators.matchers.iter_mut() {
          if let MatcherType::Word(mut w) = matchers.matcher_type.clone() {
            let new: Vec<String> = w.words.iter().map(|x| x.to_ascii_lowercase()).collect();
            w.words.clone_from(&new);
            matchers.matcher_type = MatcherType::Word(w);
            if let Part::Name(name) = &matchers.part {
              if name == "favicon" {
                matchers.part = Part::Body;
                matchers.matcher_type = MatcherType::Favicon(Favicon { hash: new });
              }
            }
            matchers.case_insensitive = true;
          }
          if let MatcherType::Favicon(mut h) = matchers.matcher_type.clone() {
            let new: Vec<String> = h.hash.iter().map(|x| x.to_ascii_lowercase()).collect();
            h.hash = new;
            matchers.matcher_type = MatcherType::Favicon(h);
            matchers.case_insensitive = false;
          }
        }
        if let HttpRaw::Path(mut h) = http.http_raw.clone() {
          h.method =
            engine::slinger::http::Method::from_str(&h.method.as_str().to_uppercase()).unwrap();
          http.http_raw = HttpRaw::Path(h);
        }
      }
      if let Some(parent) = yaml_path.parent() {
        let product = yaml_path
          .file_name()
          .unwrap_or_default()
          .to_string_lossy()
          .to_string()
          .trim_end_matches(".yaml")
          .to_string();
        let vendor = parent
          .file_name()
          .unwrap_or_default()
          .to_string_lossy()
          .to_string();
        template.info.metadata = BTreeMap::from_iter([
          (
            "verified".to_string(),
            engine::serde_format::Value::Bool(vendor.as_str() != "00_unverified"),
          ),
          (
            "vendor".to_string(),
            engine::serde_format::Value::String(vendor),
          ),
          (
            "product".to_string(),
            engine::serde_format::Value::String(product),
          ),
        ])
      }
      new_template = Some(template);
    }
    if let Some(t) = new_template {
      let f = OpenOptions::new()
        .write(true)
        .create(true)
        .append(false)
        .truncate(true)
        .open(&yaml_path)
        .unwrap();
      serde_yaml::to_writer(f, &t).unwrap();
    }
  }
}

fn to_json() {
  let current_fingerprint_dir = env::current_dir().unwrap().join("web-fingerprint");
  let yaml_paths = find_yaml_file(&current_fingerprint_dir, true);
  let mut templates = Vec::new();
  for yaml_path in yaml_paths {
    if let Ok(f) = File::open(&yaml_path) {
      match serde_yaml::from_reader::<std::fs::File, Template>(f) {
        Ok(template) => {
          templates.push(template);
        }
        Err(err) => {
          println!("{}", err)
        }
      }
    }
  }
  let f = OpenOptions::new()
    .write(true)
    .create(true)
    .append(false)
    .truncate(true)
    .open("fingerprint_v4.json")
    .unwrap();
  serde_json::to_writer(f, &templates).unwrap();
}

fn to_template(fp: &Probe, m: &MatchLine) -> Template {
  let info = matchline_to_info(m);
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

// fn matchline_to_matcher(m: &MatchLine) -> Matcher {
//   Matcher {
//     name: Some(m.service.clone()),
//     matcher_type: MatcherType::Regex(MRegex {
//       regex: vec![m.pattern.to_string()],
//       group: None,
//     }),
//     ..Matcher::default()
//   }
// }

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
    port: None,
    exclude_ports: None,
    read_size: None,
    read_all: false,
  };
  Requests {
    tcp: vec![tcp],
    ..Requests::default()
  }
}

fn matchline_to_info(m: &MatchLine) -> Info {
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
  info
}

fn nmap() {
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

fn main() {
  sync_nuclei();
  // rename_fingerprint_yaml();
  // format();
  // to_json()
  // nmap();
}

#[cfg(test)]
mod tests {
  #[test]
  fn py() {}
}
