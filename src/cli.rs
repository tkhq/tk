use std::{
    env,
    ffi::OsString,
    fmt::Display,
    io::{self, Write},
    process::ExitCode,
};

use anyhow::Result;
use clap::{
    ArgAction, Args, CommandFactory, Parser, Subcommand, builder::FalseyValueParser,
    error::ErrorKind,
};
use serde::Serialize;
use tracing::debug;

use crate::{
    auth::{
        self, AuthCommand, AuthOptions, LoginArgs, ProfileCommand, ResolvedAuth,
        SavedProfileCommand,
    },
    gpg::{self, GpgCommand},
    keygen::GenerateArgs,
    operations::{ActivityCommand, RequestArgs, run_activity},
    output::{ColorChoice, Ctx, ErrorMessage, MessageFormat, Shell, StdCtx},
    resources::{ApiKeyCommand, PolicyCommand, PreparedResource, UserCommand},
    secrets::{PreparedSecret, SecretCommand},
    sessions::{self, SessionCommand},
    skills::{self, SkillsCommand},
    ssh::{self, SshCommand},
    wallets::{PreparedWalletCommand, SignCommand, WalletCommand},
};

const LONG_ABOUT: &str = r#"CLI for Turnkey backed auth workflows.

Commands may prompt when stdin is a TTY. Pass --non-interactive or set
TK_NON_INTERACTIVE=true to fail fast instead.

--message-format json prints one JSON record per line, each with a `reason`
field; error records also carry a `code`. JSON output never prompts.

Record shapes and error codes: `tk skills show --name references/cli-convention`.
Exit codes: 0 success, 1 runtime error, 2 usage error."#;

const AFTER_HELP: &str = r#"API identity:
  Without --profile, resolved from exactly one source: the
  TURNKEY_ORGANIZATION_ID, TURNKEY_API_PUBLIC_KEY, TURNKEY_API_PRIVATE_KEY
  environment bundle; else the registry's active profile.
  The profile registry lives at ~/.config/turnkey/tk.config.toml.
  TURNKEY_API_BASE_URL overrides the API endpoint.

SSH agent:
  tk ssh agent start
  export SSH_AUTH_SOCK=~/.config/turnkey/ssh-agent.sock

Skills:
  tk skills install --into DIR
  Writes the turnkey-tk package embedded in this binary as DIR/turnkey-tk;
  start from its SKILL.md. The same package is published at
  https://github.com/tkhq/tk/tree/main/skills.
"#;

#[derive(Debug, Parser)]
#[command(
    // The package is `turnkey_tk` on crates.io; the binary and its help are `tk`.
    name = "tk",
    version,
    about = "CLI for Turnkey backed auth workflows",
    long_about = LONG_ABOUT,
    after_help = AFTER_HELP
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
        let Cli {
            auth,
            output,
            command,
        } = match Cli::try_parse() {
            Ok(args) => args,
            Err(error) => return handle_parse_error(error),
        };
        debug!(
            command = command.name(),
            non_interactive = output.non_interactive,
            message_format = ?output.message_format,
            color = ?output.color,
            "dispatching"
        );
        match command {
            Commands::Profile {
                command:
                    ProfileCommand::Saved(SavedProfileCommand::Set {
                        api_key_file: None, ..
                    }),
            } if auth.organization_id().is_none() && auth.api_base_url().is_none() => {
                handle_parse_error(Cli::command().error(
                    ErrorKind::MissingRequiredArgument,
                    "profile set requires --organization-id, --api-base-url, or --api-key-file",
                ))
            }
            Commands::Profile {
                command: ProfileCommand::Create(create),
            } => {
                let Some(organization_id) = auth.organization_id() else {
                    return handle_parse_error(Cli::command().error(
                        ErrorKind::MissingRequiredArgument,
                        "profile create requires --organization-id",
                    ));
                };
                let api_base_url = auth::endpoint_override(&auth).map(Option::unwrap_or_default);
                let mut ctx = ready(output).await;
                let result = match api_base_url {
                    Ok(api_base_url) => {
                        auth::create_profile(create, organization_id, api_base_url).await
                    }
                    Err(error) => Err(error),
                };
                emit(&mut ctx, result)
            }
            Commands::Profile {
                command: ProfileCommand::Saved(command),
            } => {
                let mut ctx = ready(output).await;
                emit(&mut ctx, auth::run_profile(command, &auth).await)
            }
            Commands::Operation(operation) => run_operation(&auth, output, operation).await,
        }
    }
}

async fn ready(output: OutputOptions) -> StdCtx {
    let shell = Shell::standard(output.message_format, output.color);
    let ctx = Ctx::new(shell, output.non_interactive);
    auth::sweep_state().await;
    ctx
}

async fn run_operation(
    options: &AuthOptions,
    output: OutputOptions,
    operation: Operation,
) -> ExitCode {
    let mut ctx = ready(output).await;
    let result = match operation {
        Operation::Ssh { command } => return emit(&mut ctx, ssh::run(command, options).await),
        Operation::ApiKey {
            command: ApiKeyCommands::Generate(generate),
        } => return emit(&mut ctx, generate.run().await),
        Operation::Gpg { command } => return emit(&mut ctx, gpg::run(command, options).await),
        Operation::Skills { command } => return emit(&mut ctx, skills::run(command)),
        Operation::Request(request) => {
            run_prepared(request.prepare(), options, async |prepared, auth| {
                prepared.run(&auth).await
            })
            .await
        }
        Operation::Activity { command } => {
            run_prepared(Ok(command), options, async |command, auth| {
                run_activity(command, &auth).await
            })
            .await
        }
        Operation::User { command } => {
            run_prepared(command.prepare(), options, PreparedResource::run).await
        }
        Operation::Policy { command } => {
            run_prepared(command.prepare(), options, PreparedResource::run).await
        }
        Operation::ApiKey {
            command: ApiKeyCommands::Remote(command),
        } => run_prepared(command.prepare(), options, PreparedResource::run).await,
        Operation::Wallet { command } => {
            run_prepared(command.prepare(), options, PreparedWalletCommand::run).await
        }
        Operation::Sign { command } => {
            run_prepared(command.prepare(), options, PreparedWalletCommand::run).await
        }
        Operation::Secret { command } => {
            let result = run_prepared(
                command.prepare(ctx.is_non_interactive()),
                options,
                PreparedSecret::run,
            )
            .await;
            return emit(&mut ctx, result);
        }
        Operation::Session { command } => sessions::run(command, options).await,
        Operation::Login(login) => auth::run_auth(AuthCommand::Login(login), options).await,
        Operation::Whoami => auth::run_auth(AuthCommand::Whoami, options).await,
        Operation::Auth { command } => auth::run_auth(command, options).await,
    };
    emit(&mut ctx, result)
}

async fn run_prepared<P, M>(
    prepared: Result<P>,
    options: &AuthOptions,
    run: impl AsyncFnOnce(P, ResolvedAuth) -> Result<M>,
) -> Result<M> {
    let prepared = prepared?;
    let auth = auth::resolve(options).await?;
    run(prepared, auth).await
}

fn emit<M: Serialize + Display>(ctx: &mut StdCtx, result: Result<M>) -> ExitCode {
    match result {
        Ok(message) => match ctx.shell().emit(&message) {
            Ok(()) => ExitCode::SUCCESS,
            Err(emit_error) => {
                let mut stderr = io::stderr();
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
                let mut stderr = io::stderr();
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
        _ if args_request_json_output(env::args_os()) => {
            let message = error.render().to_string().trim_end().to_string();
            let error_message = ErrorMessage::usage_error(message);

            // ErrorMessage holds only strings and an enum, so serializing it cannot fail.
            #[allow(clippy::expect_used)]
            let msg =
                serde_json::to_string(&error_message).expect("usage error message serializes");

            let _ = writeln!(io::stdout(), "{msg}");
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
    #[command(flatten)]
    Operation(Operation),
    /// Manage named API identities.
    Profile {
        #[command(subcommand)]
        command: ProfileCommand,
    },
}

#[derive(Debug, Subcommand)]
enum Operation {
    /// Manage activities and their approvals.
    Activity {
        #[command(subcommand)]
        command: ActivityCommand,
    },
    /// Manage SSH keys held in Turnkey and serve them to SSH and Git.
    Ssh {
        #[command(subcommand)]
        command: SshCommand,
    },
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
    /// Manage encrypted secrets.
    Secret {
        #[command(subcommand)]
        command: SecretCommand,
    },
    /// Rotate short-lived credentials for agent profiles.
    Session {
        #[command(subcommand)]
        command: SessionCommand,
    },
    /// Sign with PGP keys backed by wallet accounts.
    Gpg {
        #[command(subcommand)]
        command: GpgCommand,
    },
    /// Serve the embedded turnkey-tk agent skills.
    Skills {
        #[command(subcommand)]
        command: SkillsCommand,
    },
    /// Verify a saved profile with Turnkey and select it.
    Login(LoginArgs),
    /// Verify the selected identity with Turnkey.
    Whoami,
    /// Manage API authentication.
    Auth {
        #[command(subcommand)]
        command: AuthCommand,
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
            Commands::Operation(operation) => operation.name(),
            Commands::Profile { .. } => "profile",
        }
    }
}

impl Operation {
    fn name(&self) -> &'static str {
        match self {
            Operation::Activity { .. } => "activity",
            Operation::Ssh { .. } => "ssh",
            Operation::Request(_) => "request",
            Operation::User { .. } => "user",
            Operation::Policy { .. } => "policy",
            Operation::ApiKey { .. } => "api-key",
            Operation::Wallet { .. } => "wallet",
            Operation::Sign { .. } => "sign",
            Operation::Secret { .. } => "secret",
            Operation::Session { .. } => "session",
            Operation::Gpg { .. } => "gpg",
            Operation::Skills { .. } => "skills",
            Operation::Login(_) => "login",
            Operation::Whoami => "whoami",
            Operation::Auth { .. } => "auth",
        }
    }
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
