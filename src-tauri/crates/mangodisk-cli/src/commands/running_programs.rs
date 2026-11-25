//! `mangodisk running-programs`: the scan, triage and question set, for scripts and agents.

use std::{fs, path::Path, time::Duration};

use mangodisk_core::{
    cancel_triage, decisions::DecisionError, export_triage, questions_path, triage_programs,
    OperationCancellationToken, RunningProgramsService, TriageExportFormat, TriageQuestionSet,
    TriageRequest,
};
use serde_json::{json, Value};

use super::{CliFailure, CommandContext};
use crate::{
    arguments::{
        OutputFormat, RunningProgramsCommand, RunningProgramsQuestionsArgs,
        RunningProgramsTriageArgs,
    },
    exit_code::CliExitCode,
    output::CommandOutcome,
};

const MAX_QUESTION_FILE_BYTES: u64 = 256 * 1024;

pub fn run(
    command: RunningProgramsCommand,
    context: &CommandContext<'_>,
) -> Result<CommandOutcome, CliFailure> {
    match command {
        RunningProgramsCommand::Scan(arguments) => {
            scan(arguments.administrator_rights, context)?;
            export_outcome("running-programs scan", context.format)
        }
        RunningProgramsCommand::Triage(arguments) => triage(arguments, context),
        RunningProgramsCommand::Questions(arguments) => questions(arguments),
    }
}

fn scan(administrator_rights: bool, context: &CommandContext<'_>) -> Result<(), CliFailure> {
    if context.progress_enabled {
        eprintln!("Scanning running programs…");
    }
    let _active = context
        .cancellation
        .activate(OperationCancellationToken::running_programs_scan());
    RunningProgramsService::scan(administrator_rights)?;
    Ok(())
}

fn export_outcome(
    command: &'static str,
    format: OutputFormat,
) -> Result<CommandOutcome, CliFailure> {
    let markdown = export_triage(TriageExportFormat::Markdown).map_err(decision_failure)?;
    let json = export_triage(TriageExportFormat::Json).map_err(decision_failure)?;
    let data: Value = serde_json::from_str(&json)
        .map_err(|error| CliFailure::from(format!("failed to read the export: {error}")))?;
    // Human output is the Markdown report on its own, so it can be redirected to a file.
    let human = if format == OutputFormat::Human {
        markdown.trim_end().to_owned()
    } else {
        String::new()
    };
    Ok(CommandOutcome::success(command, human, data)?)
}

fn triage(
    arguments: RunningProgramsTriageArgs,
    context: &CommandContext<'_>,
) -> Result<CommandOutcome, CliFailure> {
    // Read the questions before scanning so a broken file fails fast and costs nothing.
    let questions = arguments
        .questions
        .as_deref()
        .map(read_question_file)
        .transpose()?;
    scan(arguments.administrator_rights, context)?;
    if context.cancellation.was_cancelled() {
        return Err(decision_failure(DecisionError::Cancelled));
    }
    let request = TriageRequest {
        program_ids: (!arguments.only.is_empty()).then_some(arguments.only),
        questions,
        model: arguments.model,
    };
    if context.progress_enabled {
        eprintln!("Asking the decision model about each program…");
    }
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let report = runtime.block_on(async {
        let watch = async {
            // Ctrl+C sets the CLI's flag; pass it on to the triage between requests.
            loop {
                tokio::time::sleep(Duration::from_millis(200)).await;
                if context.cancellation.was_cancelled() {
                    cancel_triage();
                    break;
                }
            }
            std::future::pending::<()>().await;
        };
        tokio::select! {
            result = triage_programs(request) => result,
            () = watch => unreachable!("the watch never finishes"),
        }
    });
    let report = report.map_err(decision_failure)?;
    if context.progress_enabled {
        eprintln!(
            "Judged {} programs with {} ({} failed, {} input tokens{}).",
            report.results.len(),
            report.model,
            report.failures.len(),
            report.input_tokens,
            report
                .cost_usd
                .map(|cost| format!(", ${cost:.4}"))
                .unwrap_or_default()
        );
    }
    let mut outcome = export_outcome("running-programs triage", context.format)?;
    if !report.failures.is_empty() {
        outcome.exit_code = CliExitCode::CompletedWithWarnings;
    }
    Ok(outcome)
}

fn questions(arguments: RunningProgramsQuestionsArgs) -> Result<CommandOutcome, CliFailure> {
    if let Some(path) = arguments.check {
        let set = read_question_file(&path)?;
        let human = format!(
            "{} is valid: {} questions.",
            path.display(),
            set.questions.len()
        );
        return Ok(CommandOutcome::success(
            "running-programs questions",
            human,
            json!({ "valid": true, "questions": set }),
        )?);
    }
    let path = if arguments.write_template {
        TriageQuestionSet::write_template().map_err(decision_failure)?
    } else {
        questions_path().map_err(decision_failure)?
    };
    let (set, source) = TriageQuestionSet::active().map_err(decision_failure)?;
    let text = serde_json::to_string_pretty(&set)
        .map_err(|error| CliFailure::from(format!("failed to write the questions: {error}")))?;
    let human = format!(
        "Question file: {}\nIn use: {source:?}\n\n{text}",
        path.display()
    );
    Ok(CommandOutcome::success(
        "running-programs questions",
        human,
        json!({ "path": path, "source": source, "questions": set }),
    )?)
}

fn read_question_file(path: &Path) -> Result<TriageQuestionSet, CliFailure> {
    let metadata = fs::metadata(path)?;
    if metadata.len() > MAX_QUESTION_FILE_BYTES {
        return Err(CliFailure::from(format!(
            "{} is larger than {} KB",
            path.display(),
            MAX_QUESTION_FILE_BYTES / 1024
        )));
    }
    let text = fs::read_to_string(path)?;
    TriageQuestionSet::check(&text).map_err(|problem| {
        CliFailure::from(format!(
            "{} is not a valid question set: {problem}",
            path.display()
        ))
    })
}

fn decision_failure(error: DecisionError) -> CliFailure {
    let (message, exit_code) = match error {
        DecisionError::NotConfigured => (
            "no decision model is connected; connect one on the desktop app's Running programs page",
            CliExitCode::Failure,
        ),
        DecisionError::InvalidConfiguration => ("the saved decision connection or model id is not valid", CliExitCode::Failure),
        DecisionError::ConfigurationUnavailable => ("the MangoDisk data folder could not be read", CliExitCode::Failure),
        DecisionError::Busy => ("a triage is already running", CliExitCode::OperationBusy),
        DecisionError::Cancelled => ("cancelled", CliExitCode::Cancelled),
        DecisionError::NothingToJudge => ("no programs to judge", CliExitCode::Failure),
        DecisionError::InvalidQuestions => (
            "the active question file is not valid; `mangodisk running-programs questions --check FILE` says why",
            CliExitCode::Failure,
        ),
        DecisionError::InvalidExportPath => ("exports are written only to .json or .md files", CliExitCode::Failure),
        DecisionError::ExportFailed => ("the export could not be written", CliExitCode::Failure),
        DecisionError::Unauthorized => ("the provider rejected the API key", CliExitCode::PermissionDenied),
        DecisionError::InsufficientCredits => ("the provider account is out of credits", CliExitCode::Failure),
        DecisionError::RateLimited => ("the provider is rate limiting requests; try again shortly", CliExitCode::Failure),
        DecisionError::ModelUnavailable => ("the provider does not offer that model", CliExitCode::Failure),
        DecisionError::RequestRejected => (
            "the provider rejected the request; MANGODISK_LOG=warn shows its reason",
            CliExitCode::Failure,
        ),
        DecisionError::ProviderUnavailable => ("the provider is unavailable", CliExitCode::Failure),
        DecisionError::ConnectionFailed => ("could not reach the provider", CliExitCode::Failure),
        DecisionError::Timeout => ("the provider did not answer in time", CliExitCode::Failure),
        DecisionError::InvalidResponse => ("the provider's answer could not be read", CliExitCode::Failure),
    };
    CliFailure {
        message: message.to_owned(),
        exit_code,
    }
}
