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
}
impl Default for HelperConfig {
    fn default() -> Self {
        let default: HelperConfig = argh::from_env();
        default
    }
}
