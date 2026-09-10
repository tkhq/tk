use crate::commands;
use crate::outcome::Outcome;
use crate::output::{ColorChoice, Ctx, ErrorMessage, MessageFormat, Shell, StdCtx};
use clap::{ArgAction, Args, Parser, Subcommand, builder::FalseyValueParser, error::ErrorKind};
use std::ffi::OsString;
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
    "code" classifying the failure, an optional numeric "httpStatus", and a
    "message" carrying the full error chain. The "code" taxonomy is:
        missing_required_input  a required value was absent (non-interactive)
        usage_error             bad flags/args (argument parsing failed)
        invalid_input           semantic validation failed in the command
        unauthorized            HTTP 401/403
        not_found               HTTP 404, or a resource that resolved to empty
        api_error               other non-success HTTP status, or a failed or
                                unexpected activity
        approval_required       the activity needs more approvals
        network_error           DNS/connect/TLS failure before delivery: the
                                server never received the request, so a retry
                                is safe
        network_uncertain       any other transport failure (timeout, dropped
                                connection, truncated response): delivery is
                                not established, so reconcile a mutation
                                before retrying it
        command_error           fallback for everything else
    Exit codes: 0 success, 1 runtime error, 2 usage error."#;

/// Top-level CLI arguments for the `tk` binary.
#[derive(Debug, Parser)]
#[command(
    about = "CLI for Turnkey backed auth workflows",
    long_about = LONG_ABOUT,
    after_help = after_help()
)]
pub struct Cli {
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
        let result = self.command.run(&mut ctx).await;
        match result {
            Ok(outcome) => {
                // Output delivery failure does not turn a completed command into a failure.
                if let Err(emit_error) = ctx.shell().emit(&outcome) {
                    let mut stderr = std::io::stderr();
                    let _ = writeln!(stderr, "warning: failed to write CLI output: {emit_error}");
                }
                ExitCode::SUCCESS
            }
            Err(error) => {
                // Record the full cause chain for diagnostics in either output mode.
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
}

const USAGE_ERROR_EXIT_CODE: u8 = 2;

fn handle_parse_error(error: clap::Error) -> ExitCode {
    match error.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => error.exit(),
        _ if args_request_json_output(std::env::args_os()) => {
            // Clap is built without color, so rendered usage is plain text inside JSON.
            let message = error.render().to_string().trim_end().to_string();
            let error_message = ErrorMessage::usage_error(message);

            let msg = serde_json::to_string(&error_message).unwrap_or_else(|e| e.to_string());

            let _ = writeln!(std::io::stdout(), "{msg}");
            ExitCode::from(USAGE_ERROR_EXIT_CODE)
        }
        _ => error.exit(),
    }
}

// Ambiguous flag-like positional values intentionally fail toward JSON output.
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
    /// Activity approval and rejection commands.
    Activity(commands::activity::Args),
    /// Inspect and update persistent auth configuration.
    Config(commands::config::Args),
    /// SSH related commands.
    Ssh(commands::ssh::Args),
}

impl Commands {
    fn name(&self) -> &'static str {
        match self {
            Commands::Activity(_) => "activity",
            Commands::Config(_) => "config",
            Commands::Ssh(_) => "ssh",
        }
    }

    async fn run(self, ctx: &mut StdCtx) -> anyhow::Result<Outcome> {
        match self {
            Commands::Activity(args) => commands::activity::run(ctx, args).await,
            Commands::Config(args) => commands::config::run(ctx, args).await,
            Commands::Ssh(args) => commands::ssh::run(ctx, args).await,
        }
    }
}

fn after_help() -> String {
    format!(
        "\
Environment:
  TURNKEY_ORGANIZATION_ID
  TURNKEY_API_PUBLIC_KEY
  TURNKEY_API_PRIVATE_KEY
  TURNKEY_PRIVATE_KEY_ID
  TURNKEY_API_BASE_URL

Config file:
  Set TURNKEY_TK_CONFIG_PATH to override the config file location.
  Otherwise tk uses {DEFAULT_CONFIG_DIR_DISPLAY}/tk.toml.

SSH agent:
  tk ssh agent start
  export SSH_AUTH_SOCK={DEFAULT_CONFIG_DIR_DISPLAY}/ssh-agent.sock
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
