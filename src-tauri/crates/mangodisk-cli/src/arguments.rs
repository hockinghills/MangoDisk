use clap::{Args, Parser, Subcommand, ValueEnum};

#[derive(Debug, Parser)]
#[command(
    name = "mangodisk",
    version,
    about = "Safely inspect and reclaim disk space",
    long_about = "MangoDisk scans cleanup candidates without changing files by default.\n\
Use `mangodisk clean --apply` to review and apply the same recommendations as the desktop app.",
    after_help = "Examples:\n  \
  mangodisk clean\n  \
  mangodisk clean --apply\n  \
  mangodisk clean --apply --selection all\n  \
  mangodisk clean --apply --dry-run\n  \
  mangodisk clean --format json --no-progress"
)]
pub struct Cli {
    /// Select the output format. JSON formats never contain terminal colors.
    #[arg(long, global = true, value_enum, default_value_t = OutputFormat::Human)]
    pub format: OutputFormat,

    /// Control colored human-readable output.
    #[arg(long, global = true, value_enum, default_value_t = ColorMode::Auto)]
    pub color: ColorMode,

    /// Include complete local paths in machine-readable output and progress.
    #[arg(long, global = true)]
    pub include_full_paths: bool,

    /// Suppress progress written to stderr.
    #[arg(long, global = true)]
    pub no_progress: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum OutputFormat {
    Human,
    Json,
    Jsonl,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ColorMode {
    Auto,
    Always,
    Never,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Scan cleanup candidates and optionally apply a reviewed selection.
    Clean(CleanArgs),
    /// Inspect running programs and triage them with the decision model saved in the app.
    #[command(subcommand)]
    RunningPrograms(RunningProgramsCommand),
}

#[derive(Debug, Subcommand)]
pub enum RunningProgramsCommand {
    /// Scan running programs and print the facts a triage would send, without sending them.
    Scan(RunningProgramsScanArgs),
    /// Scan, then ask the decision model saved in the desktop app about each program.
    ///
    /// Human output is a Markdown report; `--format json` prints the same export the
    /// desktop app saves. Each program costs two decision requests.
    #[command(after_help = "Examples:\n  \
    mangodisk running-programs triage > triage.md\n  \
    mangodisk --format json running-programs triage --questions my-questions.json\n  \
    mangodisk running-programs triage --model vendor/other-model --only <program-id>")]
    Triage(RunningProgramsTriageArgs),
    /// Show, check or create the questions the decision model is asked.
    Questions(RunningProgramsQuestionsArgs),
}

#[derive(Debug, Args)]
pub struct RunningProgramsScanArgs {
    /// Ask for administrator rights through the desktop's password prompt to read every process.
    #[arg(long)]
    pub administrator_rights: bool,
}

#[derive(Debug, Args)]
pub struct RunningProgramsTriageArgs {
    /// Ask for administrator rights through the desktop's password prompt to read every process.
    #[arg(long)]
    pub administrator_rights: bool,

    /// Ask the questions in this file for this run instead of the active set.
    #[arg(long, value_name = "FILE")]
    pub questions: Option<std::path::PathBuf>,

    /// Use this decision model for this run instead of the saved one.
    #[arg(long, value_name = "MODEL_ID")]
    pub model: Option<String>,

    /// Judge only these program ids (from a previous export). Repeat for several.
    #[arg(long = "only", value_name = "PROGRAM_ID")]
    pub only: Vec<String>,
}

#[derive(Debug, Args)]
pub struct RunningProgramsQuestionsArgs {
    /// Validate this question file instead of showing the active set.
    #[arg(long, value_name = "FILE", conflicts_with = "write_template")]
    pub check: Option<std::path::PathBuf>,

    /// Write the built-in questions to the active question file if it does not exist yet.
    #[arg(long)]
    pub write_template: bool,
}

#[derive(Debug, Args)]
#[command(after_help = "Examples:\n  \
    mangodisk clean\n  \
    mangodisk clean --apply\n  \
    mangodisk clean --apply --selection all\n  \
    mangodisk clean --apply --dry-run --yes")]
pub struct CleanArgs {
    /// Apply the selected cleanup rules after the read-only scan.
    #[arg(long)]
    pub apply: bool,

    /// Choose which cleanup candidates to apply.
    ///
    /// `recommended` matches the desktop app's smart selection. `all` includes
    /// every currently selectable candidate and requires additional review.
    #[arg(long, value_enum, requires = "apply")]
    pub selection: Option<CleanSelection>,

    /// Run preflight and measurement without changing files.
    #[arg(long, requires = "apply")]
    pub dry_run: bool,

    /// Skip the interactive confirmation.
    ///
    /// Required with `--apply` when stdin is not an interactive terminal.
    #[arg(long, requires = "apply")]
    pub yes: bool,

    /// Search local volumes for additional development projects.
    #[arg(long)]
    pub deep_project_discovery: bool,

    /// Include source counts and paths in human-readable scan output.
    #[arg(long)]
    pub details: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum CleanSelection {
    Recommended,
    All,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn clean_defaults_to_a_read_only_recommended_scan() {
        let parsed =
            Cli::try_parse_from(["mangodisk", "clean"]).expect("the documented command must parse");

        let Command::Clean(arguments) = parsed.command else {
            panic!("expected clean");
        };
        assert!(!arguments.apply);
        assert_eq!(arguments.selection, None);
        assert!(!arguments.dry_run);
        assert!(!arguments.yes);
    }

    #[test]
    fn clean_accepts_an_explicit_all_selection_dry_run() {
        let parsed = Cli::try_parse_from([
            "mangodisk",
            "--format",
            "json",
            "clean",
            "--apply",
            "--selection",
            "all",
            "--dry-run",
            "--yes",
        ])
        .expect("the documented command must parse");

        assert_eq!(parsed.format, OutputFormat::Json);
        let Command::Clean(arguments) = parsed.command else {
            panic!("expected clean");
        };
        assert!(arguments.apply);
        assert_eq!(arguments.selection, Some(CleanSelection::All));
        assert!(arguments.dry_run);
        assert!(arguments.yes);
    }

    #[test]
    fn clean_rejects_a_selection_without_apply() {
        let error = Cli::try_parse_from(["mangodisk", "clean", "--selection", "all"])
            .expect_err("selection must require --apply");

        assert!(error.to_string().contains("--apply"));
    }

    #[test]
    fn triage_accepts_questions_a_model_and_repeated_program_ids() {
        let parsed = Cli::try_parse_from([
            "mangodisk",
            "--format",
            "json",
            "running-programs",
            "triage",
            "--questions",
            "q.json",
            "--model",
            "vendor/m",
            "--only",
            "a",
            "--only",
            "b",
        ])
        .expect("the documented command must parse");
        let Command::RunningPrograms(RunningProgramsCommand::Triage(arguments)) = parsed.command
        else {
            panic!("expected triage");
        };
        assert_eq!(arguments.only, ["a", "b"]);
        assert_eq!(arguments.model.as_deref(), Some("vendor/m"));
        assert!(!arguments.administrator_rights);
    }

    #[test]
    fn questions_cannot_check_and_write_at_once() {
        assert!(Cli::try_parse_from([
            "mangodisk",
            "running-programs",
            "questions",
            "--check",
            "q.json",
            "--write-template"
        ])
        .is_err());
    }

    #[test]
    fn incomplete_read_only_workflows_are_not_public_commands() {
        for command in ["applications", "storage", "history"] {
            let error = Cli::try_parse_from(["mangodisk", command])
                .expect_err("removed workflows must not remain public commands");

            assert!(error.to_string().contains("unrecognized subcommand"));
        }
    }
}
