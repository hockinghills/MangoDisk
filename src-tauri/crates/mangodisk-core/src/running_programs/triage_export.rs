//! Exports the last scan and triage for review by a person or another model.
//!
//! The export holds exactly what the decision model saw for each program, the measured costs
//! that were kept from it, and every answer. It is meant to be read by a stronger model or a
//! coding agent checking the triage, so its prose is English and its JSON is stable: the
//! schema version changes whenever a field changes meaning. Command lines are never included.

use std::{fs, io::Write, path::Path};

use serde::Serialize;
use serde_json::Value;

use super::{
    models::{ProgramSafetyClass, RunningProgram},
    triage::{last_scan_and_report, program_state, ProgramTriage, TriageAnswer, TriageReport},
    triage_questions::{TriageQuestionKind, TriageQuestionSet, TriageQuestionSource},
};
use crate::decisions::DecisionError;

const EXPORT_SCHEMA_VERSION: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Deserialize, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TriageExportFormat {
    Json,
    Markdown,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportCost {
    memory_kb: u64,
    swap_kb: u64,
    memory_is_proportional: bool,
    cpu_percent_now: f64,
    cpu_percent_average: f64,
    process_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportProgram<'a> {
    id: &'a str,
    name: &'a str,
    package: Option<&'a str>,
    safety_class: ProgramSafetyClass,
    /// Core components are part of the session and are not sent for triage.
    judged: bool,
    /// The facts the decision model received for this program.
    facts: Value,
    cost: ExportCost,
    answers: Option<&'a std::collections::BTreeMap<String, TriageAnswer>>,
    /// Footprint in KB times the probability of the `leftover` role, when the role question ran.
    leftover_weight_kb: Option<f64>,
    error: Option<DecisionError>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportTriage<'a> {
    model: &'a str,
    question_source: TriageQuestionSource,
    questions: &'a TriageQuestionSet,
    input_tokens: u64,
    cost_usd: Option<f64>,
    judged_count: usize,
    failed_count: usize,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportDocument<'a> {
    schema_version: u32,
    generator: &'static str,
    captured_at: String,
    notes: [&'static str; 3],
    triage: Option<ExportTriage<'a>>,
    programs: Vec<ExportProgram<'a>>,
}

const NOTES: [&str; 3] = [
    "Answers come from a decision model that scored fixed options from the facts listed for each program; they are not checks.",
    "Each choice question was asked twice with its options in opposite orders and the probabilities were averaged; ordersAgree is false when the two passes chose differently.",
    "Costs were measured once at capture time: memory is proportional where the kernel allowed it, cpuPercentAverage is since the program started.",
];

fn footprint(program: &RunningProgram) -> u64 {
    program.memory_kb + program.swap_kb
}

fn leftover_weight(program: &RunningProgram, triage: Option<&ProgramTriage>) -> Option<f64> {
    let probability = match triage?.answers.get("role")? {
        TriageAnswer::Choice { probabilities, .. } => probabilities.get("leftover").copied()?,
        _ => return None,
    };
    Some(footprint(program) as f64 * probability)
}

fn iso_time(ms: u64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp_millis(i64::try_from(ms).unwrap_or(0))
        .map(|time| time.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
        .unwrap_or_default()
}

fn build<'a>(
    captured_at_ms: u64,
    home: Option<&str>,
    programs: &'a [RunningProgram],
    report: Option<&'a TriageReport>,
) -> ExportDocument<'a> {
    let by_id = |id: &str| {
        report.and_then(|report| report.results.iter().find(|result| result.program_id == id))
    };
    let error_of = |id: &str| {
        report.and_then(|report| {
            report
                .failures
                .iter()
                .find(|failure| failure.program_id == id)
                .map(|failure| failure.error)
        })
    };
    let mut entries: Vec<ExportProgram<'a>> = programs
        .iter()
        .map(|program| {
            let triage = by_id(&program.id);
            ExportProgram {
                id: &program.id,
                name: &program.name,
                package: program.package_name.as_deref(),
                safety_class: program.safety,
                judged: triage.is_some(),
                facts: program_state(program, captured_at_ms, home),
                cost: ExportCost {
                    memory_kb: program.memory_kb,
                    swap_kb: program.swap_kb,
                    memory_is_proportional: program.memory_is_proportional,
                    cpu_percent_now: program.cpu_percent_now,
                    cpu_percent_average: program.cpu_percent_average,
                    process_count: program.processes.len(),
                },
                answers: triage.map(|triage| &triage.answers),
                leftover_weight_kb: leftover_weight(program, triage),
                error: error_of(&program.id),
            }
        })
        .collect();
    // Judged programs first, by the weight a model calls leftover, then the rest by footprint.
    entries.sort_by(|left, right| {
        let weight = |entry: &ExportProgram| entry.leftover_weight_kb.unwrap_or(-1.0);
        weight(right).total_cmp(&weight(left)).then_with(|| {
            (right.cost.memory_kb + right.cost.swap_kb)
                .cmp(&(left.cost.memory_kb + left.cost.swap_kb))
        })
    });
    ExportDocument {
        schema_version: EXPORT_SCHEMA_VERSION,
        generator: "MangoDisk running-programs triage export",
        captured_at: iso_time(captured_at_ms),
        notes: NOTES,
        triage: report.map(|report| ExportTriage {
            model: &report.model,
            question_source: report.question_source,
            questions: &report.questions,
            input_tokens: report.input_tokens,
            cost_usd: report.cost_usd,
            judged_count: report.results.len(),
            failed_count: report.failures.len(),
        }),
        programs: entries,
    }
}

fn megabytes(kb: u64) -> String {
    format!("{:.0} MB", kb as f64 / 1024.0)
}

fn cell(text: &str) -> String {
    text.replace('|', "\\|").replace(['\n', '\r'], " ")
}

fn answer_text(answer: Option<&TriageAnswer>, question_kind: &TriageQuestionKind) -> String {
    match (answer, question_kind) {
        (
            Some(TriageAnswer::Choice {
                choice,
                confidence,
                orders_agree,
                ..
            }),
            _,
        ) => {
            let flag = if *orders_agree {
                ""
            } else {
                " (orders disagree)"
            };
            format!("{choice} {:.0}%{flag}", confidence * 100.0)
        }
        (Some(TriageAnswer::Score { expected, .. }), TriageQuestionKind::Score { levels }) => {
            format!("{expected:.1} of {}", levels.len().saturating_sub(1))
        }
        (Some(TriageAnswer::Noul { probability }), _) => format!("{:.0}%", probability * 100.0),
        _ => "—".to_owned(),
    }
}

fn fact_text(facts: &Value, key: &str) -> String {
    match facts.get(key) {
        Some(Value::String(text)) => text.clone(),
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(Value::as_str)
            .collect::<Vec<_>>()
            .join("; "),
        Some(other) => other.to_string(),
        None => String::new(),
    }
}

fn markdown(document: &ExportDocument) -> String {
    let mut out = String::new();
    out.push_str(if document.triage.is_some() {
        "# MangoDisk running-programs triage\n\n"
    } else {
        "# MangoDisk running programs\n\n"
    });
    out.push_str(&format!("Captured {}.", document.captured_at));
    match &document.triage {
        Some(triage) => out.push_str(&format!(
            " Judged by `{}` ({} programs, {} failed, {} input tokens{}). Questions: {:?}.\n\n",
            triage.model,
            triage.judged_count,
            triage.failed_count,
            triage.input_tokens,
            triage
                .cost_usd
                .map(|cost| format!(", ${cost:.4}"))
                .unwrap_or_default(),
            triage.question_source,
        )),
        None => out.push_str(" No triage has run yet; only scan facts are included.\n\n"),
    }
    for note in document.notes {
        out.push_str(&format!("- {note}\n"));
    }
    let questions: Vec<(&str, &TriageQuestionKind)> = document
        .triage
        .as_ref()
        .map(|triage| {
            triage
                .questions
                .questions
                .iter()
                .map(|question| (question.id.as_str(), &question.kind))
                .collect()
        })
        .unwrap_or_default();
    if document.triage.is_some() {
        out.push_str("\n## Judged programs\n\nSorted by footprint times the probability of `leftover`.\n\n| Program | Memory + swap | CPU avg |");
        for (id, _) in &questions {
            out.push_str(&format!(" {id} |"));
        }
        out.push_str(" Installed with | Installed | Needed by packages | Started by | Description |\n|---|---|---|");
        out.push_str(&"---|".repeat(questions.len() + 5));
        out.push('\n');
        for program in document.programs.iter().filter(|program| program.judged) {
            let name = match program.package {
                Some(package) => format!("{} ({package})", program.name),
                None => program.name.to_owned(),
            };
            out.push_str(&format!(
                "| {} | {} | {:.1}% |",
                cell(&name),
                megabytes(program.cost.memory_kb + program.cost.swap_kb),
                program.cost.cpu_percent_average
            ));
            for (id, kind) in &questions {
                let answer = program.answers.and_then(|answers| answers.get(*id));
                out.push_str(&format!(" {} |", cell(&answer_text(answer, kind))));
            }
            for key in [
                "installed_with",
                "installed",
                "installed_packages_that_depend_on_it",
                "started_by",
                "description",
            ] {
                out.push_str(&format!(" {} |", cell(&fact_text(&program.facts, key))));
            }
            out.push('\n');
        }
    }
    let rest: Vec<&ExportProgram> = document
        .programs
        .iter()
        .filter(|program| !program.judged)
        .collect();
    if !rest.is_empty() {
        out.push_str(if document.triage.is_some() {
            "\n## Not judged\n\n"
        } else {
            "\n## Programs\n\n"
        });
        out.push_str("| Program | Class | Memory + swap | CPU avg | Installed with | Started by | Not judged because |\n|---|---|---|---|---|---|---|\n");
        for program in rest {
            let reason = match (
                program.safety_class,
                program.error,
                document.triage.is_some(),
            ) {
                (ProgramSafetyClass::Core, _, _) => "core component".to_owned(),
                (_, Some(error), _) => format!("request failed: {error:?}"),
                (_, None, true) => "not asked".to_owned(),
                (_, None, false) => "no triage ran".to_owned(),
            };
            out.push_str(&format!(
                "| {} | {:?} | {} | {:.1}% | {} | {} | {reason} |\n",
                cell(program.name),
                program.safety_class,
                megabytes(program.cost.memory_kb + program.cost.swap_kb),
                program.cost.cpu_percent_average,
                cell(&fact_text(&program.facts, "installed_with")),
                cell(&fact_text(&program.facts, "started_by")),
            ));
        }
    }
    if let Some(triage) = &document.triage {
        out.push_str("\n## Questions asked\n\n```json\n");
        out.push_str(&serde_json::to_string_pretty(triage.questions).unwrap_or_default());
        out.push_str("\n```\n");
    }
    out
}

/// Renders the last scan and triage. Fails when nothing has been scanned yet.
pub fn export_triage(format: TriageExportFormat) -> Result<String, DecisionError> {
    let (captured_at_ms, home, programs, report) =
        last_scan_and_report().ok_or(DecisionError::NothingToJudge)?;
    let document = build(captured_at_ms, home.as_deref(), &programs, report.as_ref());
    Ok(match format {
        TriageExportFormat::Json => {
            let mut text = serde_json::to_string_pretty(&document)
                .map_err(|_| DecisionError::InvalidResponse)?;
            text.push('\n');
            text
        }
        TriageExportFormat::Markdown => markdown(&document),
    })
}

/// The file name offered in the save picker.
pub fn suggested_export_file_name(format: TriageExportFormat) -> &'static str {
    match format {
        TriageExportFormat::Json => "mangodisk-triage.json",
        TriageExportFormat::Markdown => "mangodisk-triage.md",
    }
}

/// Writes a rendered export to a file the user chose. Only `.json` and `.md` targets are
/// written, and never through a link, so a stray path cannot overwrite something else.
pub fn write_triage_export(
    path: &Path,
    format: TriageExportFormat,
    text: &str,
) -> Result<(), DecisionError> {
    let extension = path
        .extension()
        .and_then(|extension| extension.to_str())
        .map(str::to_ascii_lowercase);
    let expected = match format {
        TriageExportFormat::Json => matches!(extension.as_deref(), Some("json")),
        TriageExportFormat::Markdown => matches!(extension.as_deref(), Some("md" | "markdown")),
    };
    let is_link_or_folder =
        fs::symlink_metadata(path).is_ok_and(|metadata| !metadata.file_type().is_file());
    if !path.is_absolute() || !expected || is_link_or_folder {
        return Err(DecisionError::InvalidExportPath);
    }
    let directory = path.parent().ok_or(DecisionError::InvalidExportPath)?;
    let failure = |stage: &'static str, error: &std::io::Error| {
        log::warn!(
            "triage_export_write_failed stage={stage} kind={:?} os_code={:?}",
            error.kind(),
            error.raw_os_error()
        );
        DecisionError::ExportFailed
    };
    let mut temporary = tempfile::NamedTempFile::new_in(directory)
        .map_err(|error| failure("create_temporary", &error))?;
    temporary
        .write_all(text.as_bytes())
        .map_err(|error| failure("write", &error))?;
    temporary
        .persist(path)
        .map_err(|error| failure("persist", &error.error))?;
    log::info!(
        "triage_export_written format={format:?} bytes={}",
        text.len()
    );
    Ok(())
}

#[cfg(test)]
#[path = "triage_export_tests.rs"]
mod tests;
