mod bundle;
mod install;

#[cfg(test)]
mod commands;
#[cfg(test)]
mod extract;

use anyhow::Result;
use bundle::SkillName;
pub use bundle::{Installed, Listed, Shown};
use clap::{
    Subcommand,
    builder::{PathBufValueParser, TypedValueParser},
};
use install::InstallDir;

use crate::outcome::Outcome;

#[derive(Debug, Subcommand)]
pub enum SkillsCommand {
    /// List the embedded skills with their descriptions.
    List,
    /// Print one embedded skill as Markdown.
    Show {
        /// A skill name from `tk skills list`, or `references/NAME` for a reference.
        #[arg(long, value_name = "NAME")]
        name: SkillName,
    },
    /// Install the turnkey-tk package as DIR/turnkey-tk; an existing destination is never replaced, the same package is a no-op, and any other content is refused with `invalid_input`.
    Install {
        /// Directory that receives the `turnkey-tk` package; created when missing.
        #[arg(long, value_name = "DIR", value_parser = PathBufValueParser::new().try_map(InstallDir::try_from))]
        into: InstallDir,
    },
}

pub fn run(command: SkillsCommand) -> Result<Outcome> {
    match command {
        SkillsCommand::List => Ok(Outcome::SkillsListed(Listed::embedded())),
        SkillsCommand::Show { name } => Ok(Outcome::SkillsShown(Shown::from(name))),
        SkillsCommand::Install { into } => Ok(Outcome::SkillsInstalled(install::install(into)?)),
    }
}
