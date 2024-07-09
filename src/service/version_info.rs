use std::fmt::Display;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DataField {
  schematic: String,
}
impl Display for DataField {
  fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
    f.write_str(&self.schematic)
  }
}
#[derive(Clone, Debug, Default)]
pub struct VersionInfo {
  /// 产品名称
  pub product_name: Option<DataField>,
  /// 版本号
  pub version: Option<DataField>,
  /// 信息
  pub info: Option<DataField>,
  /// 主机名
  pub hostname: Option<DataField>,
  /// 操作系统
  pub operating_system: Option<DataField>,
  /// 设备类型
  pub device_type: Option<DataField>,
  /// 通用枚举
  pub cpe: Vec<DataField>,
}

impl DataField {
  pub fn new(inner: &str) -> Self {
    let mut string = String::from(inner);
    string.shrink_to_fit();
    Self { schematic: string }
  }
}

impl From<String> for DataField {
  fn from(x: String) -> DataField {
    DataField::new(x.as_str())
  }
}

impl From<&str> for DataField {
  fn from(x: &str) -> DataField {
    DataField::new(x)
  }
}
