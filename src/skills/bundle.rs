use std::{
    fmt::{self, Display, Formatter},
    path::PathBuf,
    str::FromStr,
};

use serde::{Deserialize, Serialize};
use thiserror::Error;

pub const ROOT: &str = "turnkey-tk";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const MANIFEST_FILE: &str = "turnkey-tk.json";

#[derive(Debug)]
pub struct File {
    pub path: &'static str,
    pub kind: Kind,
    pub content: &'static str,
}

#[derive(Debug)]
pub(super) enum Kind {
    Skill {
        name: &'static str,
        description: &'static str,
    },
    Reference {
        name: &'static str,
    },
    Doc,
}

mod manifest {
    use super::{File, Kind};

    include!(concat!(env!("OUT_DIR"), "/bundle_manifest.rs"));
}

pub use manifest::{DIGEST, FILES};

#[derive(Clone, Debug)]
pub struct SkillName {
    name: &'static str,
    file: &'static File,
}

#[derive(Debug, Error)]
#[error("not a skill in this package; run `tk skills list`")]
pub struct UnknownSkillName;

impl FromStr for SkillName {
    type Err = UnknownSkillName;

    fn from_str(wanted: &str) -> Result<Self, Self::Err> {
        FILES
            .iter()
            .find_map(|file| match file.kind {
                Kind::Skill { name, .. } | Kind::Reference { name } if name == wanted => {
                    Some(Self { name, file })
                }
                Kind::Skill { .. } | Kind::Reference { .. } | Kind::Doc => None,
            })
            .ok_or(UnknownSkillName)
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
pub struct Listed {
    version: &'static str,
    digest: &'static str,
    skills: Vec<Skill>,
}

#[derive(Serialize)]
struct Skill {
    name: &'static str,
    description: &'static str,
}

impl Listed {
    pub fn embedded() -> Self {
        let skills = FILES
            .iter()
            .filter_map(|file| match file.kind {
                Kind::Skill { name, description } => Some(Skill { name, description }),
                Kind::Reference { .. } | Kind::Doc => None,
            })
            .collect();
        Self {
            version: VERSION,
            digest: DIGEST,
            skills,
        }
    }
}

impl Display for Listed {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        write!(f, "{ROOT} {} ({})", self.version, self.digest)?;
        for Skill { name, description } in &self.skills {
            write!(
                f,
                r#"

{name}
    {description}"#
            )?;
        }
        Ok(())
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
pub struct Shown {
    name: &'static str,
    path: String,
    content: &'static str,
}

impl From<SkillName> for Shown {
    fn from(SkillName { name, file }: SkillName) -> Self {
        Self {
            name,
            path: format!("{ROOT}/{}", file.path),
            content: file.content,
        }
    }
}

impl Display for Shown {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(self.content.strip_suffix('\n').unwrap_or(self.content))
    }
}

#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct InstallManifest {
    pub(super) binary_version: String,
    pub(super) digest: String,
    pub(super) files: Vec<String>,
}

impl InstallManifest {
    pub(super) fn embedded() -> Self {
        Self {
            binary_version: VERSION.to_owned(),
            digest: DIGEST.to_owned(),
            files: FILES.iter().map(|file| file.path.to_owned()).collect(),
        }
    }
}

#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct Installed {
    pub(super) destination: PathBuf,
    pub(super) version: &'static str,
    pub(super) digest: &'static str,
    pub(super) files: Vec<String>,
    pub(super) already_installed: bool,
}

impl Display for Installed {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let destination = self.destination.display();
        if self.already_installed {
            write!(
                f,
                "{ROOT} {} is already installed at {destination}",
                self.version
            )
        } else {
            write!(
                f,
                "installed {ROOT} {} to {destination} ({} files); start from its SKILL.md",
                self.version,
                self.files.len()
            )
        }
    }
}
