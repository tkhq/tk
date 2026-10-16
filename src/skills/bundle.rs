use std::{
    fmt::{self, Display, Formatter},
    path::PathBuf,
    str::FromStr,
};

use serde::{Deserialize, Serialize, Serializer};
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
    #[serde(flatten)]
    pub(super) change: Change,
}

#[cfg_attr(test, derive(Default))]
pub(super) enum Change {
    #[cfg_attr(test, default)]
    Installed,
    AlreadyInstalled,
    Replaced {
        version: String,
    },
}

impl Serialize for Change {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        #[derive(Serialize)]
        #[serde(rename_all = "camelCase")]
        struct Record<'a> {
            already_installed: bool,
            replaced_version: Option<&'a str>,
        }
        let (already_installed, replaced_version) = match self {
            Self::Installed => (false, None),
            Self::AlreadyInstalled => (true, None),
            Self::Replaced { version } => (false, Some(version.as_str())),
        };
        Record {
            already_installed,
            replaced_version,
        }
        .serialize(serializer)
    }
}

impl Display for Installed {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        let Self {
            destination,
            version,
            digest: _,
            files,
            change,
        } = self;
        let destination = destination.display();
        let count = files.len();
        match change {
            Change::AlreadyInstalled => {
                write!(f, "{ROOT} {version} is already installed at {destination}")
            }
            Change::Replaced { version: replaced } => write!(
                f,
                "replaced {ROOT} {replaced} with {version} at {destination} ({count} files); start from its SKILL.md"
            ),
            Change::Installed => write!(
                f,
                "installed {ROOT} {version} to {destination} ({count} files); start from its SKILL.md"
            ),
        }
    }
}
