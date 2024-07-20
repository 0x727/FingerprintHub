use argh::FromArgs;

#[derive(Debug, Clone, FromArgs)]
#[argh(description = "observer_ward version")]
pub struct HelperConfig {
  /// convert yaml to json
  #[argh(switch)]
  pub convert: bool,
  /// sync nuclei template
  #[argh(switch)]
  pub sync: bool,
  /// format fingerprint yaml
  #[argh(switch)]
  pub format: bool,
  /// convert service fingerprint yaml
  #[argh(switch)]
  pub service: bool,
}

impl Default for HelperConfig {
  fn default() -> Self {
    let default: HelperConfig = argh::from_env();
    default
  }
}
