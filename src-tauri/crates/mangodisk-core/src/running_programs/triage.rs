//! Sorts running programs with a decision model.
//!
//! Each program is described to the model from facts the scan measured or read: what the
//! program says it is, how it was installed and when, what starts it, and how many installed
//! packages need it. Command lines, costs and raw dates stay out: models handle quantities and
//! dates poorly, and the cost ranking is done here in code.
//!
//! Every program is asked twice with the answer options in opposite orders, because decision
//! models lean toward the first option; the two probability sets are averaged. The answers are
//! labels for the user to review. They never stop, disable or remove anything.

use std::{
    collections::BTreeMap,
    sync::{
        atomic::{AtomicBool, Ordering},
        Arc, Mutex,
    },
    time::Instant,
};

use futures_util::stream::{self, StreamExt};
use serde::Serialize;
use serde_json::{json, Map, Value};

use super::models::{
    ProgramLaunch, ProgramLaunchKind, ProgramOriginFact, ProgramOriginKind, ProgramPackageRequest,
    ProgramSafetyClass, RunningProgram,
};
use super::triage_questions::{
    RequestBody, TriageQuestion, TriageQuestionKind, TriageQuestionSet, TriageQuestionSource,
    MISS_QUESTION, ROLE_QUESTION,
};
use crate::decisions::{
    decide, DecisionAnswer, DecisionConfiguration, DecisionError, DecisionResponse,
};

const CONCURRENT_REQUESTS: usize = 8;
const MAX_PROGRAMS: usize = 400;
const DAY_MS: u64 = 86_400_000;
const BUILT_IN_MISS_LEVELS: usize = 5;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TriageRole {
    Desktop,
    Needed,
    Tool,
    Leftover,
    Unclear,
}

impl TriageRole {
    const ALL: [TriageRole; 5] = [
        Self::Desktop,
        Self::Needed,
        Self::Tool,
        Self::Leftover,
        Self::Unclear,
    ];

    fn key(self) -> &'static str {
        match self {
            Self::Desktop => "desktop",
            Self::Needed => "needed",
            Self::Tool => "tool",
            Self::Leftover => "leftover",
            Self::Unclear => "unclear",
        }
    }

    fn from_key(key: &str) -> Option<Self> {
        Self::ALL.into_iter().find(|role| role.key() == key)
    }
}

/// One question's answer after averaging both option orders.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TriageAnswer {
    #[serde(rename_all = "camelCase")]
    Choice {
        choice: String,
        probabilities: BTreeMap<String, f64>,
        confidence: f64,
        /// Both option orders picked the same option.
        orders_agree: bool,
    },
    #[serde(rename_all = "camelCase")]
    Score {
        /// Expected level, from 0 (the first level) upward.
        expected: f64,
        probabilities: Vec<f64>,
    },
    Noul {
        probability: f64,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramTriage {
    pub program_id: String,
    /// Every question's answer, keyed by question id.
    pub answers: BTreeMap<String, TriageAnswer>,
    /// From the `role` question when it uses the built-in options; drives the page's labels.
    pub role: Option<TriageRole>,
    pub role_probabilities: BTreeMap<TriageRole, f64>,
    pub confidence: f64,
    /// From the `miss` score question: 0 (nothing changes) to its highest level.
    pub miss_level: Option<f64>,
    pub miss_probabilities: Vec<f64>,
    pub orders_agree: bool,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageFailure {
    pub program_id: String,
    pub error: DecisionError,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageReport {
    /// The model that answered, as the provider reported it.
    pub model: String,
    pub questions: TriageQuestionSet,
    pub question_source: TriageQuestionSource,
    pub results: Vec<ProgramTriage>,
    pub failures: Vec<TriageFailure>,
    pub input_tokens: u64,
    pub cost_usd: Option<f64>,
    pub elapsed_ms: u64,
}

struct LastScan {
    captured_at_ms: u64,
    home: Option<String>,
    programs: Vec<RunningProgram>,
}

static LAST_SCAN: Mutex<Option<LastScan>> = Mutex::new(None);
static LAST_REPORT: Mutex<Option<TriageReport>> = Mutex::new(None);
static TRIAGE_RUNNING: AtomicBool = AtomicBool::new(false);
static TRIAGE_CANCELLED: AtomicBool = AtomicBool::new(false);

/// The triage judges the programs Core captured, never program data sent back by an adapter.
pub(super) fn remember_programs(
    captured_at_ms: u64,
    home: Option<String>,
    programs: &[RunningProgram],
) {
    if let Ok(mut last) = LAST_SCAN.lock() {
        *last = Some(LastScan {
            captured_at_ms,
            home,
            programs: programs.to_vec(),
        });
    }
    // A triage judged the facts of an earlier scan; exporting it beside new costs would mix them.
    if let Ok(mut report) = LAST_REPORT.lock() {
        *report = None;
    }
}

fn origin_phrase(kind: ProgramOriginKind) -> &'static str {
    use ProgramOriginKind as K;
    match kind {
        K::SystemPackage => "a package from the Linux distribution",
        K::PipUser => "pip install --user",
        K::PipSystem => "pip, system-wide",
        K::Pip => "pip, into a Python environment",
        K::Pipx => "pipx",
        K::UvTool => "uv tool install",
        K::Virtualenv => "a Python virtual environment",
        K::Conda => "a conda environment",
        K::NpmGlobal => "npm install -g",
        K::PnpmGlobal => "pnpm add -g",
        K::YarnGlobal => "yarn global add",
        K::BunGlobal => "bun add -g",
        K::Volta => "Volta",
        K::NpxCache => "an npx or pnpm dlx download cache",
        K::Project => "a project folder",
        K::NodeProject => "a Node.js project folder",
        K::AddedService => "a system service someone added by hand or with an install script",
        K::Homebrew => "Homebrew",
        K::Cargo => "cargo install",
        K::Rustup => "the rustup toolchain manager",
        K::Go => "go install",
        K::Flatpak => "Flatpak",
        K::Snap => "Snap",
        K::AppImage => "an AppImage file",
        K::Container => "a container",
        K::Nix => "Nix",
        K::GitClone => "a git clone",
        K::ManualLocal => "copied into /usr/local by an install script or make install",
        K::ManualOpt => "unpacked into /opt",
        K::HomeFile => "a file in the user's home folder",
        K::Unknown => "unknown",
    }
}

fn launch_phrase(launch: &ProgramLaunch) -> String {
    use ProgramLaunchKind as K;
    let unit = launch.unit.as_deref().unwrap_or("");
    let name = launch.desktop_name.as_deref().unwrap_or(unit);
    match launch.kind {
        K::Autostart => format!("started automatically at login by the autostart entry {name}"),
        K::AppLaunched => "opened by the user".to_owned(),
        K::OnDemand => format!("started on demand when another program asked for {name}"),
        K::Session => "part of the desktop session startup".to_owned(),
        K::UserService => format!("a user service ({unit})"),
        K::SystemService => format!("a system service ({unit})"),
        K::Transient => "started with systemd-run".to_owned(),
        K::Terminal => "started by the user from a terminal".to_owned(),
        K::LoginSession => "started directly by the login session".to_owned(),
        K::Cron => "a scheduled cron job".to_owned(),
        K::Container => "running inside a container or virtual machine".to_owned(),
        K::Init => "the init system".to_owned(),
        K::Widget => "a desktop panel widget".to_owned(),
        K::Ssh => "started from a remote ssh login".to_owned(),
        K::Child => match (&launch.spawned_by, launch.spawned_by_editor) {
            (Some(parent), true) => format!("started by the code editor {parent}"),
            (Some(parent), false) => format!("started by the program {parent}"),
            (None, _) => "started by another program".to_owned(),
        },
        K::Unknown => "unknown".to_owned(),
    }
}

fn age_phrase(installed_at_ms: Option<u64>, now_ms: u64) -> &'static str {
    let Some(installed) = installed_at_ms else {
        return "unknown";
    };
    match now_ms.saturating_sub(installed) / DAY_MS {
        0..=30 => "within the last month",
        31..=180 => "one to six months ago",
        181..=365 => "six to twelve months ago",
        366..=1095 => "one to three years ago",
        _ => "more than three years ago",
    }
}

fn request_phrase(request: Option<ProgramPackageRequest>) -> Option<&'static str> {
    request.map(|request| match request {
        ProgramPackageRequest::Requested => "someone installed it by name",
        ProgramPackageRequest::BulkInstall => {
            "part of a large or scripted install of many packages"
        }
        ProgramPackageRequest::Dependency => {
            "pulled in automatically as a dependency of another package"
        }
        ProgramPackageRequest::CameWithSystem => "came with the operating system install",
    })
}

fn home_relative(text: &str, home: Option<&str>) -> String {
    match home {
        Some(home) if !home.is_empty() && text.starts_with(home) => {
            format!("~{}", &text[home.len()..])
        }
        _ => text.to_owned(),
    }
}

/// The facts one program is judged on. Built only from Core's own scan.
pub(super) fn program_state(program: &RunningProgram, now_ms: u64, home: Option<&str>) -> Value {
    let origin = &program.origin;
    let mut state = Map::new();
    state.insert("name".into(), json!(program.name));
    if let Some(package) = &program.package_name {
        state.insert("package".into(), json!(package));
    }
    if origin.name != program.name && program.package_name.as_deref() != Some(origin.name.as_str())
    {
        state.insert("installed_as".into(), json!(origin.name));
    }
    if let Some(description) = &origin.description {
        state.insert("description".into(), json!(description));
    }
    state.insert("installed_with".into(), json!(origin_phrase(origin.kind)));
    state.insert(
        "installed".into(),
        json!(age_phrase(origin.installed_at_ms, now_ms)),
    );
    if let Some(request) = request_phrase(origin.package_request) {
        state.insert("why_installed".into(), json!(request));
    }
    if let Some(count) = origin.required_by_count {
        state.insert("installed_packages_that_depend_on_it".into(), json!(count));
    }
    if origin.facts.contains(&ProgramOriginFact::EssentialPackage) {
        state.insert("marked_essential_by_the_distribution".into(), json!(true));
    }
    if let Some(location) = &origin.location {
        if !matches!(
            origin.kind,
            ProgramOriginKind::SystemPackage | ProgramOriginKind::Container
        ) {
            state.insert("location".into(), json!(home_relative(location, home)));
        }
    }
    if let Some(container) = &origin.container {
        if let Some(image) = &container.image {
            state.insert("container_image".into(), json!(image));
        }
    }
    let started_by: Vec<String> = program.launches.iter().map(launch_phrase).collect();
    state.insert("started_by".into(), json!(started_by));
    let process_names: Vec<&str> = {
        let mut names: Vec<&str> = program
            .processes
            .iter()
            .map(|process| process.name.as_str())
            .collect();
        names.sort_unstable();
        names.dedup();
        names.truncate(12);
        names
    };
    state.insert("process_names".into(), json!(process_names));
    state.insert(
        "almost_idle_since_it_started".into(),
        json!(program.quiet_since_start),
    );
    Value::Object(state)
}

fn normalized(values: Vec<f64>) -> Vec<f64> {
    let total: f64 = values.iter().sum();
    if total > 0.0 {
        values.iter().map(|value| value / total).collect()
    } else {
        values
    }
}

fn average(rows: &[Vec<f64>]) -> Vec<f64> {
    let Some(width) = rows.first().map(Vec::len) else {
        return Vec::new();
    };
    normalized(
        (0..width)
            .map(|index| rows.iter().map(|row| row[index]).sum::<f64>() / rows.len() as f64)
            .collect(),
    )
}

/// Averages one question's answers from both option orders.
fn combine_question(
    question: &TriageQuestion,
    passes: &[&BTreeMap<String, DecisionAnswer>],
) -> Option<TriageAnswer> {
    let answers: Vec<&DecisionAnswer> = passes
        .iter()
        .filter_map(|pass| pass.get(&question.id))
        .collect();
    match &question.kind {
        TriageQuestionKind::Choice { options } => {
            let mut chosen = Vec::new();
            let rows: Vec<Vec<f64>> = answers
                .iter()
                .filter_map(|answer| match answer {
                    DecisionAnswer::Choice {
                        choice,
                        probabilities,
                    } => {
                        chosen.push(choice.clone());
                        Some(
                            options
                                .iter()
                                .map(|option| probabilities.get(&option.id).copied().unwrap_or(0.0))
                                .collect(),
                        )
                    }
                    _ => None,
                })
                .collect();
            let averaged = average(&rows);
            let (best, confidence) = averaged
                .iter()
                .enumerate()
                .max_by(|left, right| left.1.total_cmp(right.1))
                .map(|(index, probability)| (index, *probability))?;
            if confidence <= 0.0 {
                return None;
            }
            Some(TriageAnswer::Choice {
                choice: options[best].id.clone(),
                probabilities: options
                    .iter()
                    .map(|option| option.id.clone())
                    .zip(averaged)
                    .collect(),
                confidence,
                orders_agree: chosen.len() == 2 && chosen[0] == chosen[1],
            })
        }
        TriageQuestionKind::Score { levels } => {
            let rows: Vec<Vec<f64>> = answers
                .iter()
                .filter_map(|answer| match answer {
                    DecisionAnswer::Score { probabilities, .. } if !probabilities.is_empty() => {
                        Some(
                            (0..levels.len())
                                .map(|level| {
                                    probabilities
                                        .get(&level.to_string())
                                        .copied()
                                        .unwrap_or(0.0)
                                })
                                .collect(),
                        )
                    }
                    _ => None,
                })
                .collect();
            let probabilities = average(&rows);
            if probabilities.iter().sum::<f64>() <= 0.0 {
                return None;
            }
            let expected = probabilities
                .iter()
                .enumerate()
                .map(|(level, probability)| level as f64 * probability)
                .sum();
            Some(TriageAnswer::Score {
                expected,
                probabilities,
            })
        }
        TriageQuestionKind::Noul => {
            let values: Vec<f64> = answers
                .iter()
                .filter_map(|answer| match answer {
                    DecisionAnswer::Noul { probability } => Some(*probability),
                    _ => None,
                })
                .collect();
            (!values.is_empty()).then(|| TriageAnswer::Noul {
                probability: values.iter().sum::<f64>() / values.len() as f64,
            })
        }
    }
}

/// Combines both passes for one program. `None` when no question got a usable answer.
pub(super) fn combine(
    program_id: &str,
    set: &TriageQuestionSet,
    first: &BTreeMap<String, DecisionAnswer>,
    second: &BTreeMap<String, DecisionAnswer>,
) -> Option<ProgramTriage> {
    let passes = [first, second];
    let answers: BTreeMap<String, TriageAnswer> = set
        .questions
        .iter()
        .filter_map(|question| {
            combine_question(question, &passes).map(|answer| (question.id.clone(), answer))
        })
        .collect();
    if answers.is_empty() {
        return None;
    }
    let mut result = ProgramTriage {
        program_id: program_id.to_owned(),
        role: None,
        role_probabilities: BTreeMap::new(),
        confidence: 0.0,
        miss_level: None,
        miss_probabilities: Vec::new(),
        orders_agree: true,
        answers,
    };
    if let Some(TriageAnswer::Choice {
        choice,
        probabilities,
        confidence,
        orders_agree,
    }) = result.answers.get(ROLE_QUESTION)
    {
        // Labels apply only when the role question uses the built-in option ids.
        let roles: BTreeMap<TriageRole, f64> = probabilities
            .iter()
            .filter_map(|(key, probability)| {
                TriageRole::from_key(key).map(|role| (role, *probability))
            })
            .collect();
        if roles.len() == probabilities.len() {
            result.role = TriageRole::from_key(choice);
            result.role_probabilities = roles;
            result.confidence = *confidence;
        }
        result.orders_agree = *orders_agree;
    }
    if let Some(TriageAnswer::Score {
        expected,
        probabilities,
    }) = result.answers.get(MISS_QUESTION)
    {
        // The page labels the five built-in levels; a custom scale stays in `answers` only.
        if probabilities.len() != BUILT_IN_MISS_LEVELS {
            return Some(result);
        }
        result.miss_level = Some(*expected);
        result.miss_probabilities = probabilities.clone();
    }
    Some(result)
}

struct RunningGuard;

impl RunningGuard {
    fn acquire() -> Result<Self, DecisionError> {
        TRIAGE_RUNNING
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| DecisionError::Busy)?;
        TRIAGE_CANCELLED.store(false, Ordering::Release);
        Ok(Self)
    }
}

impl Drop for RunningGuard {
    fn drop(&mut self) {
        TRIAGE_RUNNING.store(false, Ordering::Release);
    }
}

pub fn cancel_triage() {
    TRIAGE_CANCELLED.store(true, Ordering::Release);
}

/// What to judge and which questions to ask.
#[derive(Debug, Clone, Default)]
pub struct TriageRequest {
    /// Only these programs; all non-core programs when `None`.
    pub program_ids: Option<Vec<String>>,
    /// Questions for this run only; the active set when `None`.
    pub questions: Option<TriageQuestionSet>,
    /// A model for this run only, to compare models on one scan; the saved model when `None`.
    pub model: Option<String>,
}

/// Triages the last scanned programs. Core components are left out: they are part of the
/// session and not candidates for triage.
pub async fn triage_programs(request: TriageRequest) -> Result<TriageReport, DecisionError> {
    let _guard = RunningGuard::acquire()?;
    let mut configuration = DecisionConfiguration::load()?.ok_or(DecisionError::NotConfigured)?;
    if let Some(model) = request.model {
        configuration.model = model.trim().to_owned();
        configuration.validate()?;
    }
    configuration.ready()?;
    let (questions, question_source) = match request.questions {
        Some(set) => {
            set.validate()?;
            (set, TriageQuestionSource::Supplied)
        }
        None => TriageQuestionSet::active()?,
    };
    let (captured_at_ms, home, programs) = last_scan().ok_or(DecisionError::NothingToJudge)?;
    let candidates: Vec<RunningProgram> = programs
        .into_iter()
        .filter(|program| program.safety != ProgramSafetyClass::Core)
        .filter(|program| {
            request
                .program_ids
                .as_ref()
                .is_none_or(|ids| ids.contains(&program.id))
        })
        .take(MAX_PROGRAMS)
        .collect();
    if candidates.is_empty() {
        return Err(DecisionError::NothingToJudge);
    }
    let started = Instant::now();
    log::info!(
        "running_programs_triage_started program_count={} question_count={} question_source={question_source:?} model={:?}",
        candidates.len(),
        questions.questions.len(),
        configuration.model
    );
    // Jobs own their data so the request futures are `Send` for any caller's runtime.
    let jobs: Vec<(String, bool, Value)> = candidates
        .iter()
        .flat_map(|program| {
            let state = program_state(program, captured_at_ms, home.as_deref());
            [false, true].map(|reversed| (program.id.clone(), reversed, state.clone()))
        })
        .collect();
    let shared = Arc::new((configuration.clone(), questions.clone()));
    type Outcome = (String, bool, Result<DecisionResponse, DecisionError>);
    let responses: Vec<Outcome> = stream::iter(jobs)
        .map(move |(id, reversed, state)| {
            let shared = Arc::clone(&shared);
            async move {
                if TRIAGE_CANCELLED.load(Ordering::Acquire) {
                    return (id, reversed, Err(DecisionError::Cancelled));
                }
                let (configuration, questions) = &*shared;
                let body = RequestBody {
                    state,
                    set: questions,
                    reversed,
                };
                let result = decide(configuration, &body).await;
                (id, reversed, result)
            }
        })
        .buffer_unordered(CONCURRENT_REQUESTS)
        .collect()
        .await;
    if TRIAGE_CANCELLED.load(Ordering::Acquire) {
        return Err(DecisionError::Cancelled);
    }

    let mut model = None;
    let mut input_tokens = 0;
    let mut cost: Option<f64> = None;
    let mut by_program: BTreeMap<String, [Option<BTreeMap<String, DecisionAnswer>>; 2]> =
        BTreeMap::new();
    let mut errors: BTreeMap<String, DecisionError> = BTreeMap::new();
    for (id, reversed, response) in responses {
        match response {
            Ok(response) => {
                input_tokens += response.input_tokens;
                if let Some(value) = response.cost_usd {
                    *cost.get_or_insert(0.0) += value;
                }
                model = model.or(response.model);
                by_program.entry(id).or_default()[usize::from(reversed)] = Some(response.answers);
            }
            Err(error) => {
                errors.entry(id).or_insert(error);
            }
        }
    }
    // An account-wide failure on every request is a failure of the triage, not of each program.
    if by_program.is_empty() {
        let error = errors
            .values()
            .next()
            .copied()
            .unwrap_or(DecisionError::InvalidResponse);
        log::warn!("running_programs_triage_failed error={error:?}");
        return Err(error);
    }
    let empty = BTreeMap::new();
    let mut results = Vec::new();
    let mut failures = Vec::new();
    for program in &candidates {
        let combined = by_program.get(&program.id).and_then(|[first, second]| {
            combine(
                &program.id,
                &questions,
                first.as_ref().unwrap_or(&empty),
                second.as_ref().unwrap_or(&empty),
            )
        });
        match combined {
            Some(result) => results.push(result),
            None => failures.push(TriageFailure {
                program_id: program.id.clone(),
                error: errors
                    .get(&program.id)
                    .copied()
                    .unwrap_or(DecisionError::InvalidResponse),
            }),
        }
    }
    let elapsed_ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    log::info!(
        "running_programs_triage_finished result_count={} failure_count={} input_tokens={input_tokens} cost_usd={cost:?} elapsed_ms={elapsed_ms}",
        results.len(),
        failures.len(),
    );
    let report = TriageReport {
        model: model.unwrap_or(configuration.model),
        questions,
        question_source,
        results,
        failures,
        input_tokens,
        cost_usd: cost,
        elapsed_ms,
    };
    if let Ok(mut last) = LAST_REPORT.lock() {
        *last = Some(report.clone());
    }
    Ok(report)
}

fn last_scan() -> Option<(u64, Option<String>, Vec<RunningProgram>)> {
    let last = LAST_SCAN.lock().ok()?;
    last.as_ref().map(|scan| {
        (
            scan.captured_at_ms,
            scan.home.clone(),
            scan.programs.clone(),
        )
    })
}

/// The last scan and triage, for exports. The report is `None` before the first triage.
/// The capture time, home folder, programs and triage of the last scan.
pub(super) type ScanAndReport = (
    u64,
    Option<String>,
    Vec<RunningProgram>,
    Option<TriageReport>,
);

pub(super) fn last_scan_and_report() -> Option<ScanAndReport> {
    let (captured_at_ms, home, programs) = last_scan()?;
    let report = LAST_REPORT.lock().ok().and_then(|report| report.clone());
    Some((captured_at_ms, home, programs, report))
}

#[cfg(test)]
#[path = "triage_tests.rs"]
mod tests;
