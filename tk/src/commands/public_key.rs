use clap::Args as ClapArgs;
use serde::Serialize;
use std::fmt::{self, Display, Formatter};

use crate::outcome::Outcome;
use crate::output::StdCtx;

/// Arguments for the `tk ssh public-key` subcommand.
#[derive(Debug, ClapArgs)]
#[command(about, long_about = None)]
pub struct Args {}

/// Terminal outcome of `tk ssh public-key`: the authorized_keys line.
#[derive(Serialize)]
#[cfg_attr(test, derive(Default))]
#[serde(rename_all = "camelCase")]
pub struct PublicKeyPrinted {
    /// The SSH public key in authorized_keys format.
    pub public_key: String,
}

impl Display for PublicKeyPrinted {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        f.write_str(&self.public_key)
    }
}

/// Runs the `tk ssh public-key` subcommand.
pub async fn run(_ctx: &mut StdCtx, _args: Args) -> anyhow::Result<Outcome> {
    Ok(Outcome::PublicKeyPrinted(PublicKeyPrinted {
        public_key: turnkey_auth::public_key::get_public_key_line().await?,
    }))
}
