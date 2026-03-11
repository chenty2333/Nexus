//! Host-side compiler for the minimal Nexus component manifest format.

use anyhow::{Context, Result, anyhow, bail};
use nexus_component::{
    CapabilityKind, ChildDecl, ComponentDecl, ExposeDecl, ExposeSource, ProgramDecl, StartupMode,
    UseDecl,
};
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct ManifestDoc {
    url: String,
    #[serde(default)]
    startup: Option<String>,
    program: ProgramDoc,
    #[serde(rename = "use", default)]
    uses: Vec<UseDoc>,
    #[serde(rename = "exposes", default)]
    exposes: Vec<ExposeDoc>,
    #[serde(default)]
    children: Vec<ChildDoc>,
}

#[derive(Debug, Deserialize)]
struct ProgramDoc {
    runner: String,
    binary: String,
    #[serde(default)]
    args: Vec<String>,
    #[serde(default)]
    env: Vec<String>,
}

#[derive(Debug, Deserialize)]
struct UseDoc {
    kind: String,
    name: String,
    #[serde(default)]
    path: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ExposeDoc {
    kind: String,
    source: String,
    name: String,
    #[serde(rename = "as", default)]
    target_name: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ChildDoc {
    name: String,
    url: String,
    startup: String,
}

/// Parse one minimal text manifest into the shared component IR.
pub fn parse_manifest(source: &str) -> Result<ComponentDecl> {
    let doc: ManifestDoc = toml::from_str(source).context("parse manifest TOML")?;
    Ok(ComponentDecl {
        url: doc.url,
        program: ProgramDecl {
            runner: doc.program.runner,
            binary: doc.program.binary,
            args: doc.program.args,
            env: doc.program.env,
        },
        uses: doc
            .uses
            .into_iter()
            .map(|entry| {
                Ok(UseDecl {
                    kind: parse_capability_kind(&entry.kind)?,
                    source_name: entry.name,
                    target_path: entry.path,
                })
            })
            .collect::<Result<_>>()?,
        exposes: doc
            .exposes
            .into_iter()
            .map(|entry| {
                let kind = parse_capability_kind(&entry.kind)?;
                if !matches!(kind, CapabilityKind::Protocol | CapabilityKind::Directory) {
                    bail!("exposes only supports protocol or directory");
                }
                let source_name = entry.name;
                let target_name = entry.target_name.unwrap_or_else(|| source_name.clone());
                Ok(ExposeDecl {
                    kind,
                    source: parse_expose_source(&entry.source)?,
                    source_name,
                    target_name,
                })
            })
            .collect::<Result<_>>()?,
        children: doc
            .children
            .into_iter()
            .map(|child| {
                Ok(ChildDecl {
                    name: child.name,
                    url: child.url,
                    startup: parse_startup_mode(&child.startup)?,
                })
            })
            .collect::<Result<_>>()?,
        startup: parse_startup_mode(doc.startup.as_deref().unwrap_or("eager"))?,
    })
}

/// Compile one text manifest into the stable binary IR blob.
pub fn compile_manifest(source: &str) -> Result<Vec<u8>> {
    Ok(parse_manifest(source)?.encode_binary())
}

fn parse_capability_kind(value: &str) -> Result<CapabilityKind> {
    match value {
        "protocol" => Ok(CapabilityKind::Protocol),
        "directory" => Ok(CapabilityKind::Directory),
        "runner" => Ok(CapabilityKind::Runner),
        "resolver" => Ok(CapabilityKind::Resolver),
        _ => Err(anyhow!("unsupported capability kind `{value}`")),
    }
}

fn parse_startup_mode(value: &str) -> Result<StartupMode> {
    match value {
        "eager" => Ok(StartupMode::Eager),
        "lazy" => Ok(StartupMode::Lazy),
        _ => Err(anyhow!("unsupported startup mode `{value}`")),
    }
}

fn parse_expose_source(value: &str) -> Result<ExposeSource> {
    if value == "self" {
        return Ok(ExposeSource::Self_);
    }
    if let Some(child) = value.strip_prefix("child:") {
        if child.is_empty() {
            bail!("child expose source must name a child");
        }
        return Ok(ExposeSource::Child(child.to_owned()));
    }
    Err(anyhow!("unsupported expose source `{value}`"))
}

#[cfg(test)]
mod tests {
    use nexus_component::{CapabilityKind, ComponentDecl, ExposeSource, StartupMode};

    use super::{compile_manifest, parse_manifest};

    #[test]
    fn parses_and_compiles_minimal_manifest() {
        let manifest = r#"
url = "boot://root"
startup = "eager"

[program]
runner = "elf"
binary = "bin/root"
args = ["--verbose"]
env = ["RUST_LOG=debug"]

[[use]]
kind = "protocol"
name = "nexus.logger.LogSink"
path = "/svc/nexus.logger.LogSink"

[[use]]
kind = "runner"
name = "elf"

[[exposes]]
kind = "protocol"
source = "self"
name = "nexus.echo.Echo"
as = "nexus.echo.Echo"

[[children]]
name = "echo"
url = "local://echo"
startup = "lazy"
"#;

        let decl = parse_manifest(manifest).expect("parse manifest");
        assert_eq!(decl.url, "boot://root");
        assert_eq!(decl.startup, StartupMode::Eager);
        assert_eq!(decl.uses.len(), 2);
        assert_eq!(decl.uses[0].kind, CapabilityKind::Protocol);
        assert_eq!(decl.exposes[0].source, ExposeSource::Self_,);
        assert_eq!(decl.children[0].startup, StartupMode::Lazy);

        let blob = compile_manifest(manifest).expect("compile manifest");
        let decoded = ComponentDecl::decode_binary(&blob).expect("decode blob");
        assert_eq!(decoded, decl);
    }
}
