use crate::auth::{self, AuthCommand, AuthOptions, LoginArgs, ProfileCommand, ResolvedAuth};
use crate::commands;
use crate::gpg::{self, GpgCommand};
use crate::keygen::GenerateArgs;
use crate::operations::{ActivityCommand, RequestArgs, run_activity};
use crate::output::{ColorChoice, Ctx, ErrorMessage, MessageFormat, Shell, StdCtx};
use crate::resources::{ApiKeyCommand, PolicyCommand, PreparedResource, UserCommand};
use crate::secrets::{PreparedSecret, SecretCommand};
use crate::wallets::{PreparedWalletCommand, SignCommand, WalletCommand};
use clap::{ArgAction, Args, Parser, Subcommand, builder::FalseyValueParser, error::ErrorKind};
use serde::Serialize;
use std::ffi::OsString;
use std::fmt::Display;
use std::io::Write;
use std::process::ExitCode;
use tracing::debug;
use turnkey_auth::config::DEFAULT_CONFIG_DIR_DISPLAY;

pub(crate) const LONG_ABOUT: &str = r#"CLI for Turnkey backed auth workflows.

Interactive behavior:
    By default, commands may prompt when stdin is a TTY. Use --non-interactive
    or set TK_NON_INTERACTIVE=true to disable prompts and fail fast instead.

Output format:
    --message-format human (default) prints human-readable text. Use
    --message-format json to emit machine-readable output instead: one JSON
    object per line (newline-delimited JSON), each with a "reason" field
    identifying the message, including errors. JSON mode implies
    --non-interactive, so commands never prompt and fail fast on missing input.

    Errors emit reason "command_error" (or "missing_required_input") plus a
    "code" classifying the failure, an optional numeric "httpStatus", optional
    "details" for recovery (such as the last observed activity identity), and
    a "message" carrying the full error chain. The "code" taxonomy is:
        missing_required_input  a required value was absent (non-interactive)
        usage_error             bad flags/args (argument parsing failed)
        invalid_input           semantic validation failed in the command
        unauthorized            HTTP 401/403
        not_found               HTTP 404, or a resource that resolved to empty
        api_error               other non-success HTTP status, or a failed,
                                rejected, or unexpected activity
        approval_required       the activity needs more approvals
        network_error           connect/timeout/DNS: request never reached the
                                server
        network_uncertain       transport failure where delivery cannot be
                                ruled out; reconcile before retrying a mutation
        submission_unknown      a mutation was sent but its outcome could not
                                be observed; inspect before resubmitting
        wait_timeout            activity wait ran out of time; resume with the
                                same ID
        command_error           fallback for everything else
    Exit codes: 0 success, 1 runtime error, 2 usage error."#;

#[derive(Debug, Parser)]
#[command(
    about = "CLI for Turnkey backed auth workflows",
    long_about = LONG_ABOUT,
    after_help = after_help()
)]
pub struct Cli {
    #[command(flatten)]
    auth: AuthOptions,

    #[command(flatten)]
    output: OutputOptions,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Args)]
struct OutputOptions {
    /// Disable interactive prompts and fail fast when required values are missing.
    ///
    /// Via the environment, an empty or falsey value (false, 0, no, off) leaves
    /// prompts enabled and any other value disables them.
    #[arg(
        long,
        global = true,
        env = "TK_NON_INTERACTIVE",
        action = ArgAction::SetTrue,
        value_parser = FalseyValueParser::new()
    )]
    non_interactive: bool,

    /// Format user-facing output.
    #[arg(long, global = true, value_enum, default_value_t = MessageFormat::Human)]
    message_format: MessageFormat,

    /// Control ANSI color in user-facing output.
    #[arg(long, global = true, value_enum, default_value_t = ColorChoice::Auto)]
    color: ColorChoice,
}

impl Cli {
    pub async fn run() -> ExitCode {
        let args = match Cli::try_parse() {
            Ok(args) => args,
            Err(error) => return handle_parse_error(error),
        };
        args.run_parsed().await
    }

    async fn run_parsed(self) -> ExitCode {
        debug!(
            command = self.command.name(),
            non_interactive = self.output.non_interactive,
            message_format = ?self.output.message_format,
            color = ?self.output.color,
            "dispatching"
        );

        let shell = Shell::standard(self.output.message_format, self.output.color);
        let mut ctx = Ctx::new(shell, self.output.non_interactive);
        auth::sweep_state().await;
        let options = &self.auth;
        let result = match self.command {
            Commands::Config(args) => {
                let result = commands::config::run(&mut ctx, args).await;
                return emit(&mut ctx, result);
            }
            Commands::Ssh(args) => {
                let result = commands::ssh::run(&mut ctx, args).await;
                return emit(&mut ctx, result);
            }
            Commands::ApiKey {
                command: ApiKeyCommands::Generate(generate),
            } => return emit(&mut ctx, generate.run().await),
            Commands::Gpg { command } => return emit(&mut ctx, gpg::run(command, options).await),
            Commands::Request(request) => {
                run_prepared(request.prepare(), options, async |prepared, auth| {
                    prepared.run(&auth).await
                })
                .await
            }
            Commands::Activity { command } => {
                run_prepared(Ok(command), options, async |command, auth| {
                    run_activity(command, &auth).await
                })
                .await
            }
            Commands::User { command } => {
                run_prepared(command.prepare(), options, PreparedResource::run).await
            }
            Commands::Policy { command } => {
                run_prepared(command.prepare(), options, PreparedResource::run).await
            }
            Commands::ApiKey {
                command: ApiKeyCommands::Remote(command),
            } => run_prepared(command.prepare(), options, PreparedResource::run).await,
            Commands::Wallet { command } => {
                run_prepared(command.prepare(), options, PreparedWalletCommand::run).await
            }
            Commands::Sign { command } => {
                run_prepared(command.prepare(), options, PreparedWalletCommand::run).await
            }
            Commands::Secret { command } => {
                let result = run_prepared(
                    command.prepare(ctx.is_non_interactive()),
                    options,
                    PreparedSecret::run,
                )
                .await;
                return emit(&mut ctx, result);
            }
            Commands::Login(login) => auth::run_auth(AuthCommand::Login(login), options).await,
            Commands::Whoami => auth::run_auth(AuthCommand::Whoami, options).await,
            Commands::Auth { command } => auth::run_auth(command, options).await,
            Commands::Profile { command } => auth::run_profile(command, options).await,
        };
        emit(&mut ctx, result)
    }
}

async fn run_prepared<P, M>(
    prepared: anyhow::Result<P>,
    options: &AuthOptions,
    run: impl AsyncFnOnce(P, ResolvedAuth) -> anyhow::Result<M>,
) -> anyhow::Result<M> {
    let prepared = prepared?;
    let auth = auth::resolve(options).await?;
    run(prepared, auth).await
}

fn emit<M: Serialize + Display>(ctx: &mut StdCtx, result: anyhow::Result<M>) -> ExitCode {
    match result {
        Ok(message) => match ctx.shell().emit(&message) {
            Ok(()) => ExitCode::SUCCESS,
            // The command succeeded but its output never reached the user,
            // and it may be the only copy of a value the command consumed.
            // A zero exit would tell a wrapper script otherwise.
            Err(emit_error) => {
                let mut stderr = std::io::stderr();
                let _ = writeln!(stderr, "error: failed to write CLI output: {emit_error}");
                ExitCode::FAILURE
            }
        },
        Err(error) => {
            debug!(?error, "command failed");

            let shell = ctx.shell();
            let emit_result = if shell.message_format().is_json() {
                shell.emit(&ErrorMessage::from_error(&error))
            } else {
                shell.human().error(&error)
            };
            if let Err(emit_error) = emit_result {
                let mut stderr = std::io::stderr();
                let _ = writeln!(stderr, "error: failed to write CLI error: {emit_error}");
            }
            ExitCode::FAILURE
        }
    }
}

const USAGE_ERROR_EXIT_CODE: u8 = 2;

fn handle_parse_error(error: clap::Error) -> ExitCode {
    match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => error.exit(),
        _ if args_request_json_output(std::env::args_os()) => {
            let message = error.render().to_string().trim_end().to_string();
            let error_message = ErrorMessage::usage_error(message);

            let msg = serde_json::to_string(&error_message).unwrap_or_else(|e| e.to_string());

            let _ = writeln!(std::io::stdout(), "{msg}");
            ExitCode::from(USAGE_ERROR_EXIT_CODE)
        }
        _ => error.exit(),
    }
}

fn args_request_json_output(args: impl IntoIterator<Item = OsString>) -> bool {
    const FLAG: &str = "--message-format";
    const JSON_FLAG: &str = "--message-format=json";

    let args: Vec<_> = args.into_iter().collect();

    args.iter().any(|arg| arg == JSON_FLAG)
        || args
            .windows(2)
            .any(|pair| pair[0] == FLAG && pair[1] == "json")
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Inspect, approve, reject, and wait for activities.
    Activity {
        #[command(subcommand)]
        command: ActivityCommand,
    },
    /// Inspect and update persistent auth configuration.
    Config(commands::config::Args),
    /// SSH related commands.
    Ssh(commands::ssh::Args),
    /// Send an arbitrary signed API request.
    Request(RequestArgs),
    /// Manage users and user tags.
    User {
        #[command(subcommand)]
        command: UserCommand,
    },
    /// Manage policies and inspect evaluations.
    Policy {
        #[command(subcommand)]
        command: PolicyCommand,
    },
    /// Manage registered API credentials.
    ApiKey {
        #[command(subcommand)]
        command: ApiKeyCommands,
    },
    /// Manage wallets and accounts.
    Wallet {
        #[command(subcommand)]
        command: WalletCommand,
    },
    /// Sign payloads and serialized transactions.
    Sign {
        #[command(subcommand)]
        command: SignCommand,
    },
    /// List, import, and export Secrets.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Create OpenPGP keys as wallet accounts, export them, and sign with them.
    Gpg {
        #[command(subcommand)]
        command: GpgCommand,
    },
    /// Save an existing API credential as a named profile and select it.
    Login(LoginArgs),
    /// Verify the selected identity remotely.
    Whoami,
    /// Manage API authentication.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
    },
    /// Manage named API identities.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
}

#[derive(Debug, Subcommand)]
enum ApiKeyCommands {
    /// Generate a protected local credential file without registration.
    Generate(GenerateArgs),
    #[command(flatten)]
    Remote(ApiKeyCommand),
}

impl Commands {
    fn name(&self) -> &'static str {
        match self {
            Commands::Activity { .. } => "activity",
            Commands::Config(_) => "config",
            Commands::Ssh(_) => "ssh",
            Commands::Request(_) => "request",
            Commands::User { .. } => "user",
            Commands::Policy { .. } => "policy",
            Commands::ApiKey { .. } => "api-key",
            Commands::Wallet { .. } => "wallet",
            Commands::Sign { .. } => "sign",
            Commands::Secret { .. } => "secret",
            Commands::Gpg { .. } => "gpg",
            Commands::Login(_) => "login",
            Commands::Whoami => "whoami",
            Commands::Auth { .. } => "auth",
            Commands::Profile { .. } => "profile",
        }
    }
}

fn after_help() -> String {
    format!(
        "\
API identity (login, whoami, request, activity, user, policy, api-key, wallet,
sign, gpg):
  Resolved from exactly one source: the TURNKEY_ORGANIZATION_ID,
  TURNKEY_API_PUBLIC_KEY, TURNKEY_API_PRIVATE_KEY environment bundle; else the
  profile named by --profile or TK_PROFILE (an explicit profile always wins);
  else the registry's active profile.
  The profile registry lives at ~/.config/turnkey/tk.config.toml (override
  with --config or TK_CONFIG). TURNKEY_API_BASE_URL overrides the API endpoint.

Config file (config, ssh):
  Set TURNKEY_TK_CONFIG_PATH to override the config file location.
  Otherwise tk uses {DEFAULT_CONFIG_DIR_DISPLAY}/tk.toml.
  TURNKEY_PRIVATE_KEY_ID names the SSH signing key.

SSH agent:
  tk ssh agent start
  export SSH_AUTH_SOCK={DEFAULT_CONFIG_DIR_DISPLAY}/ssh-agent.sock

GPG signing:
  tk gpg use --wallet-id <uuid>
  git config --global gpg.format openpgp
  git config --global gpg.program tk
  TK_GPG_WALLET_ID and TK_GPG_KEY_INDEX override the profile's gpg table.
",
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn json_output_request_is_detected_in_both_spellings() {
        for args in [
            vec!["tk", "--message-format=json", "config", "list"],
            vec!["tk", "config", "list", "--message-format", "json"],
        ] {
            assert!(args_request_json_output(
                args.into_iter().map(OsString::from)
            ));
        }
        assert!(!args_request_json_output(
            ["tk", "config", "list"].into_iter().map(OsString::from)
        ));
    }
}
