use tor_hsservice::config::OnionServiceConfigBuilder;
fn main() {
    let mut builder = OnionServiceConfigBuilder::default();
    builder.dos_protection();
}
