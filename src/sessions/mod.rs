//! Short-lived agent credentials: request, provision, activate, and inspect.
//!
//! The agent generates its keypair with `request` and hands only the public
//! key to a provisioner, which registers it with `provision`. The agent then
//! switches to it with `activate` and watches its expiry with `status`.

mod activate;
pub(crate) mod duration;
mod pending;
mod provision;
pub(crate) mod public_key;
mod request;
mod status;

use anyhow::Result;
use clap::Subcommand;
use provision::ProvisionArgs;
use status::StatusArgs;

use crate::{
    auth::{self, AuthOptions},
    operations::OperationOutput,
};

#[derive(Debug, Subcommand)]
pub enum SessionCommand {
    /// Generate a new credential for a saved profile and print its public key
    /// for a provisioner to register.
    ///
    /// The private key never leaves this machine.
    Request {
        /// Saved profile that will use the new credential.
        #[arg(long = "profile-name")]
        name: String,
        /// Discard an unregistered pending request and start over.
        #[arg(long)]
        replace: bool,
    },
    /// Register a public key on a user as an expiring API key.
    Provision(ProvisionArgs),
    /// Switch a saved profile to its pending credential once it is registered.
    Activate {
        /// Saved profile with a pending session request.
        #[arg(long = "profile-name")]
        name: String,
    },
    /// Report when a saved profile's credential expires.
    Status(StatusArgs),
}

pub async fn run(command: SessionCommand, options: &AuthOptions) -> Result<OperationOutput> {
    match command {
        SessionCommand::Request { name, replace } => request::run(name, replace).await,
        SessionCommand::Provision(args) => {
            provision::run(auth::resolve(options).await?, args).await
        }
        SessionCommand::Activate { name } => activate::run(name).await,
        SessionCommand::Status(args) => status::run(args).await,
    }
}
