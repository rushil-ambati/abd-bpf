use anyhow::{anyhow, Context as _};
use aya_build::cargo_metadata;

fn main() -> Result<(), anyhow::Error> {
    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("MetadataCommand::exec")?;
    let ebpf_package = packages
        .into_iter()
        .find(|cargo_metadata::Package { name, .. }| name == "abd-ebpf")
        .ok_or_else(|| anyhow!("abd-ebpf package not found"))?;
    aya_build::build_ebpf([ebpf_package], aya_build::Toolchain::default())
}
