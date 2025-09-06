use engine::find_yaml_file;
use engine::info::{Info, Severity, CSE, VPF};
use engine::matchers::{Favicon, Matcher, MatcherType, Part};
use engine::request::{HttpRaw, Requests};
use engine::template::Template;
use helper::cli::HelperConfig;
use helper::nmap::nmap;
use helper::{load_yaml, save_yaml, to_kebab_case, V3WebFingerPrint};
use std::collections::BTreeMap;
use std::env;
use std::fs::{File, OpenOptions};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::Arc;

const UNKNOWN_VENDOR: &str = "00_unknown";
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
  //同步nuclei
  let mut yaml_paths = Vec::new();
  for path in ["cnvd", "cves", "default-logins", "vulnerabilities"] {
    let y = format!("nuclei-templates/http/{}", path);
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
                let _ = std::fs::remove_dir(current_dir.join(&vpf.vendor));
                default_path = wp_path;
              }
            }
            std::fs::create_dir_all(&default_path).unwrap();
            let f_path =
              default_path.join(yaml_path.file_name().unwrap().to_string_lossy().to_string());
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

fn merge_matcher(save_path: PathBuf, del_path: PathBuf) {
  if let Ok(del) = load_yaml(&del_path) {
    let del_matcher: Vec<Matcher> = del
      .requests
      .http
      .iter()
      .flat_map(|h| h.operators.matchers.clone())
      .collect();
    if let Ok(mut save) = load_yaml(&save_path) {
      if let Some(http) = save.requests.http.first_mut() {
        http.operators.matchers.extend(del_matcher);
        save_yaml(save_path, save).unwrap();
        std::fs::remove_file(&del_path).unwrap();
      }
    }
  }
}

// 将有厂商和产品的指纹移动到已经分类好的文件夹
fn rename_fingerprint_yaml() {
  let current_plugin_dir = env::current_dir().unwrap().join("plugins");
  let current_fingerprint_dir = env::current_dir().unwrap().join("web-fingerprint");
  let unknown_yaml_paths = find_yaml_file(&current_fingerprint_dir.join(UNKNOWN_VENDOR), false);
  let all_plugins_vendor_name: Vec<String> = std::fs::read_dir(&current_plugin_dir)
    .unwrap()
    .map(|p| p.unwrap().file_name().to_string_lossy().to_string())
    .collect();
  for unknown_yaml_path in unknown_yaml_paths {
    if let Ok(f) = File::open(&unknown_yaml_path) {
      match serde_yaml::from_reader::<std::fs::File, Template>(f) {
        Ok(template) => {
          let vpf = template.info.get_vpf();
          // 未知指纹名称和插件名称相同，如果没有这个指纹就复制到已知指纹文件夹
          if all_plugins_vendor_name.contains(&template.id) {
            let same = current_plugin_dir.join(&template.id);
            if same.is_dir() {
              let finger = same.join(format!("{}.yaml", &template.id));
              println!(
                "rename: {} to {}",
                unknown_yaml_path.to_string_lossy(),
                finger.to_string_lossy()
              );
              if !finger.exists() {
                std::fs::rename(&unknown_yaml_path, finger).unwrap();
              } else {
                // 已知指纹文件夹已经有了指纹了，把未知的删除掉
                merge_matcher(finger, unknown_yaml_path);
              }
              continue;
            }
          }
          if let Some((v, p)) = template.id.split_once('-') {
            if all_plugins_vendor_name.contains(&v.to_string()) {
              let same = current_plugin_dir.join(v);
              let path = same.join(p);
              if path.is_dir() {
                let finger = same.join(format!("{}.yaml", p));
                println!(
                  "rename: {} to {}",
                  unknown_yaml_path.to_string_lossy(),
                  finger.to_string_lossy()
                );
                if !finger.exists() {
                  std::fs::rename(&unknown_yaml_path, finger).unwrap();
                } else {
                  // 已知指纹文件夹已经有了指纹了，把未知的删除掉
                  merge_matcher(finger, unknown_yaml_path);
                }
                continue;
              }
            }
          };
          if let Some(vpf) = vpf {
            if vpf.vendor == UNKNOWN_VENDOR {
              continue;
            }
            let p = current_plugin_dir.join(&vpf.vendor).join(&vpf.product);
            if p.exists() && p.is_dir() {
              std::fs::create_dir_all(current_fingerprint_dir.join(&vpf.vendor)).unwrap();
              let finger = current_fingerprint_dir
                .join(&vpf.vendor)
                .join(format!("{}.yaml", vpf.product));
              println!(
                "rename: {} to {}",
                unknown_yaml_path.to_string_lossy(),
                finger.to_string_lossy()
              );
              if !finger.exists() {
                std::fs::rename(&unknown_yaml_path, finger).unwrap();
              } else {
                // 已知指纹文件夹已经有了指纹了，把未知的删除掉
                merge_matcher(finger, unknown_yaml_path);
              }
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
  for name in all_plugins_vendor_name.iter() {
    for yaml_path in find_yaml_file(&current_plugin_dir.join(name), false) {
      let finger_path = current_fingerprint_dir.join(name);
      std::fs::create_dir_all(&finger_path).unwrap();
      let finger = finger_path.join(yaml_path.file_name().unwrap());
      if !finger.exists() {
        std::fs::rename(&yaml_path, finger).unwrap();
      } else {
        // 已知指纹文件夹已经有了指纹了，把未知的删除掉
        merge_matcher(finger, yaml_path);
      }
    }
  }
}

fn update_template(template: &mut Template) {
  for http in template.requests.http.iter_mut() {
    for matchers in http.operators.matchers.iter_mut() {
      // 如果是关键词匹配，添加转小写和忽略大小写
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
    // 路径请求方式转大写
    if let HttpRaw::Path(mut h) = http.http_raw.clone() {
      h.method =
        engine::slinger::http::Method::from_str(&h.method.as_str().to_uppercase()).unwrap();
      http.http_raw = HttpRaw::Path(h);
    }
  }
}

fn update_info(template: &mut Template, fingerprint_yaml_path: &Path) {
  let vpf = if let Some(pvf) = template.info.get_vpf() {
    pvf
  } else if let Some(parent) = fingerprint_yaml_path.parent() {
    let product = fingerprint_yaml_path
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
    let verified = vendor != UNKNOWN_VENDOR;
    VPF {
      vendor,
      product,
      framework: None,
      verified,
    }
  } else {
    VPF {
      vendor: UNKNOWN_VENDOR.to_string(),
      product: UNKNOWN_VENDOR.to_string(),
      framework: None,
      verified: false,
    }
  };
  let new_vpf = BTreeMap::from_iter([
    (
      "verified".to_string(),
      engine::serde_format::Value::Bool(vpf.vendor.as_str() != UNKNOWN_VENDOR),
    ),
    (
      "vendor".to_string(),
      engine::serde_format::Value::String(vpf.vendor),
    ),
    (
      "product".to_string(),
      engine::serde_format::Value::String(vpf.product),
    ),
  ]);
  let info = Arc::make_mut(&mut template.info);
  for (k, v) in new_vpf {
    info.metadata.insert(k, v);
  }
}

fn format() {
  let current_fingerprint_dir = env::current_dir().unwrap().join("web-fingerprint");
  let all_fingerprint_path = find_yaml_file(&current_fingerprint_dir, true);
  for fingerprint_yaml_path in all_fingerprint_path {
    let f = File::open(&fingerprint_yaml_path).unwrap();
    let mut new_template = None;
    if let Ok(mut template) = serde_yaml::from_reader::<std::fs::File, Template>(f) {
      update_template(&mut template);
      update_info(&mut template, &fingerprint_yaml_path);
      new_template = Some(template);
    }
    if let Some(t) = new_template {
      let f = OpenOptions::new()
        .write(true)
        .create(true)
        .append(false)
        .truncate(true)
        .open(&fingerprint_yaml_path)
        .unwrap();
      serde_yaml::to_writer(f, &t).unwrap();
    }
  }
}

fn convert_json(dir: &str, filename: &str) {
  let current_fingerprint_dir = env::current_dir().unwrap().join(dir);
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
    .open(filename)
    .unwrap();
  serde_json::to_writer(f, &templates).unwrap();
}

// 空间搜索引擎自动转指纹规则
fn cse_to_finger() {
  let current_plugin_dir = env::current_dir().unwrap().join("plugins");
  let current_fingerprint_dir = env::current_dir().unwrap().join("web-fingerprint");
  let all_vendor_name: Vec<String> = std::fs::read_dir(&current_plugin_dir)
    .unwrap()
    .filter_map(|x| x.ok())
    .filter_map(|d| if d.path().is_dir() { Some(d) } else { None })
    .map(|p| p.file_name().to_string_lossy().to_string())
    .collect();
  for vendor in all_vendor_name {
    if vendor == "wordpress" {
      continue;
    }
    let vendor_path = current_plugin_dir.join(&vendor);
    let all_product: Vec<String> = std::fs::read_dir(&vendor_path)
      .unwrap()
      .filter_map(|x| x.ok())
      .filter_map(|d| if d.path().is_dir() { Some(d) } else { None })
      .map(|p| p.file_name().to_string_lossy().to_string())
      .collect();
    for product in all_product {
      let product_path = current_plugin_dir.join(&vendor_path).join(&product);
      let templates: Vec<Template> = find_yaml_file(&product_path, false)
        .iter()
        .map(File::open)
        .filter_map(|f| f.ok())
        .filter_map(|f| serde_yaml::from_reader::<std::fs::File, Template>(f).ok())
        .collect();
      let cse: Vec<CSE> = templates.iter().filter_map(|t| t.info.get_cse()).collect();
      if cse.is_empty() {
        continue;
      }
      let product_path = current_fingerprint_dir
        .join(&vendor)
        .join(format!("{}.yaml", product));
      if !product_path.exists() {
        let one_cse = to_one_cse(cse);
        let matchers: Vec<Matcher> = one_cse.clone().into();
        if matchers.is_empty() {
          continue;
        }
        let t = cse_to_template(
          one_cse,
          VPF {
            vendor: vendor.clone(),
            product,
            framework: None,
            verified: false,
          },
        );
        std::fs::create_dir_all(current_fingerprint_dir.join(&vendor)).unwrap();
        if let Ok(file) = File::create(&product_path) {
          serde_yaml::to_writer(file, &t).unwrap();
        } else {
          println!("创建失败：{}", product_path.to_string_lossy());
        }
      } else {
        println!("{}", product_path.to_string_lossy());
      }
    }
  }
}

fn to_one_cse(cse: Vec<CSE>) -> CSE {
  let mut one_cse = CSE {
    zoomeye_query: vec![],
    hunter_query: vec![],
    shodan_query: vec![],
    fofa_query: vec![],
    google_query: vec![],
  };
  for c in cse {
    for q in c.google_query {
      if !one_cse.google_query.contains(&q.to_lowercase()) {
        one_cse.google_query.push(q.to_lowercase());
      }
    }
    for q in c.fofa_query {
      if !one_cse.fofa_query.contains(&q.to_lowercase()) {
        one_cse.fofa_query.push(q.to_lowercase());
      }
    }
    for q in c.hunter_query {
      if !one_cse.hunter_query.contains(&q.to_lowercase()) {
        one_cse.hunter_query.push(q.to_lowercase());
      }
    }
    for q in c.shodan_query {
      if !one_cse.shodan_query.contains(&q.to_lowercase()) {
        one_cse.shodan_query.push(q.to_lowercase());
      }
    }
    for q in c.zoomeye_query {
      if !one_cse.zoomeye_query.contains(&q.to_lowercase()) {
        one_cse.zoomeye_query.push(q.to_lowercase());
      }
    }
  }
  one_cse
}

fn cse_to_template(one_cse: CSE, vpf: VPF) -> Template {
  let mut info = Info {
    name: vpf.product.clone(),
    severity: Severity::Info,
    author: vec!["cn-kali-team".to_string()],
    tags: vec![
      "detect".to_string(),
      "tech".to_string(),
      vpf.product.clone(),
    ],
    ..Info::default()
  };
  info.set_cse(one_cse.clone());
  info.set_vpf(vpf.clone());
  let mut index = Requests::default_web_index();
  index.http[0].operators.matchers = one_cse.into();
  let t = Template {
    id: to_kebab_case(vpf.product.as_str()),
    info: Arc::new(info),
    flow: None,
    requests: index,
    self_contained: Default::default(),
    stop_at_first_match: false,
    variables: Default::default(),
  };
  t
}

fn v3_to_v4(v3_path: PathBuf) {
  let v3_yaml_list = find_yaml_file(&v3_path, false);
  let current_fingerprint_dir = env::current_dir().unwrap().join("web-fingerprint");
  let all_product: Vec<String> = find_yaml_file(&current_fingerprint_dir, true)
    .into_iter()
    .map(|p| {
      p.file_name()
        .unwrap()
        .to_string_lossy()
        .trim_end_matches(".yaml")
        .to_string()
    })
    .collect();
  for v3_path in v3_yaml_list {
    let v3_file = File::open(&v3_path).unwrap();
    let v3_finger: V3WebFingerPrint = serde_yaml::from_reader(v3_file).unwrap();
    let template: Template = v3_finger.into();
    if !all_product.contains(&template.info.name) {
      if let Some((_x, y)) = template.info.name.split_once('-') {
        if all_product.contains(&y.to_string()) {
          continue;
        }
      }
      let v4_path = current_fingerprint_dir
        .join("00_unknown")
        .join(format!("{}.yaml", template.info.name));
      let v4_file = File::create(&v4_path).unwrap();
      serde_yaml::to_writer(v4_file, &template).unwrap();
    }
  }
}

fn main() {
  let config = HelperConfig::default();
  if config.convert {
    convert_json("web-fingerprint", "web_fingerprint_v4.json");
    convert_json("service-fingerprint", "service_fingerprint_v4.json");
  }
  if config.sync {
    sync_nuclei();
    // 同步完自动根据空间搜索引擎语法生成指纹规则
    cse_to_finger();
  }
  if config.format {
    format();
    rename_fingerprint_yaml();
  }
  if config.service {
    nmap();
  }
  if let Some(v3_path) = config.v3_to_v4 {
    v3_to_v4(v3_path);
  }
}

#[cfg(test)]
mod tests {
  #[test]
  fn py() {}
}
