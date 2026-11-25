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
        Mutex,
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
use crate::decisions::{decide, DecisionAnswer, DecisionConfiguration, DecisionError};

const CONCURRENT_REQUESTS: usize = 8;
const MAX_PROGRAMS: usize = 400;
const DAY_MS: u64 = 86_400_000;

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

    fn criterion(self) -> &'static str {
        match self {
            Self::Desktop => "Part of the desktop environment or operating system that the login session or the computer itself needs",
            Self::Needed => "A service, helper or library that another program on this computer needs in order to work",
            Self::Tool => "An application, tool or service a person installed on purpose and still uses",
            Self::Leftover => "Installed for a past task, an experiment or by an install script, and not needed by anything in use now",
            Self::Unclear => "The facts given are not enough to tell which of the other answers fits",
        }
    }
}

/// How much stopping the program would be noticed, lowest first.
const MISS_LEVELS: [&str; 5] = [
    "Nothing anyone uses would change",
    "A minor or rarely used feature would stop",
    "A feature in regular use would stop working",
    "Something used every day would break",
    "The desktop session or the system would stop working",
];

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProgramTriage {
    pub program_id: String,
    pub role: TriageRole,
    pub role_probabilities: BTreeMap<TriageRole, f64>,
    /// Probability of the chosen role after averaging both option orders.
    pub confidence: f64,
    /// Expected level on the miss scale, from 0 (nothing changes) to 4 (the system stops).
    pub miss_level: f64,
    pub miss_probabilities: Vec<f64>,
    /// Both option orders picked the same role.
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

/// Choice options in a fixed order. JSON objects in this crate serialize sorted by key, which
/// would undo the order reversal, so the map is written entry by entry.
struct OrderedCriteria(Vec<TriageRole>);

impl Serialize for OrderedCriteria {
    fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        use serde::ser::SerializeMap;
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for role in &self.0 {
            map.serialize_entry(role.key(), role.criterion())?;
        }
        map.end()
    }
}

#[derive(Serialize)]
struct RoleQuestion {
    #[serde(rename = "type")]
    kind: &'static str,
    instructions: &'static str,
    criteria: OrderedCriteria,
}

#[derive(Serialize)]
struct MissQuestion {
    #[serde(rename = "type")]
    kind: &'static str,
    instructions: &'static str,
    criteria: [&'static str; 5],
}

#[derive(Serialize)]
struct Questions {
    role: RoleQuestion,
    miss: MissQuestion,
}

#[derive(Serialize)]
pub(super) struct RequestBody {
    state: Value,
    questions: Questions,
}

/// One request body. `reversed` flips the order of the role options; score levels must stay
/// listed lowest first.
pub(super) fn request_body(state: &Value, reversed: bool) -> RequestBody {
    let mut roles = TriageRole::ALL.to_vec();
    if reversed {
        roles.reverse();
    }
    RequestBody {
        state: state.clone(),
        questions: Questions {
            role: RoleQuestion {
                kind: "choice",
                instructions: "What is this program's role on this computer? Judge only from the facts given about the program.",
                criteria: OrderedCriteria(roles),
            },
            miss: MissQuestion {
                kind: "score",
                instructions: "If this program stopped and never started again, how much would the person who uses this computer notice?",
                criteria: MISS_LEVELS,
            },
        },
    }
}

struct OneOrder {
    roles: BTreeMap<TriageRole, f64>,
    chosen: Option<TriageRole>,
    miss: Vec<f64>,
}

fn role_from_key(key: &str) -> Option<TriageRole> {
    TriageRole::ALL.into_iter().find(|role| role.key() == key)
}

fn read_order(answers: &BTreeMap<String, DecisionAnswer>) -> Option<OneOrder> {
    let DecisionAnswer::Choice {
        choice,
        probabilities,
    } = answers.get("role")?
    else {
        return None;
    };
    let roles: BTreeMap<TriageRole, f64> = probabilities
        .iter()
        .filter_map(|(key, probability)| role_from_key(key).map(|role| (role, *probability)))
        .collect();
    let miss = match answers.get("miss") {
        Some(DecisionAnswer::Score { probabilities, .. }) if !probabilities.is_empty() => (0
            ..MISS_LEVELS.len())
            .map(|level| {
                probabilities
                    .get(&level.to_string())
                    .copied()
                    .unwrap_or(0.0)
            })
            .collect(),
        _ => Vec::new(),
    };
    Some(OneOrder {
        roles,
        chosen: role_from_key(choice),
        miss,
    })
}

fn normalized(values: impl Iterator<Item = f64>) -> Vec<f64> {
    let values: Vec<f64> = values.collect();
    let total: f64 = values.iter().sum();
    if total > 0.0 {
        values.iter().map(|value| value / total).collect()
    } else {
        values
    }
}

/// Averages the two option orders into one result.
pub(super) fn combine(
    program_id: &str,
    first: &BTreeMap<String, DecisionAnswer>,
    second: &BTreeMap<String, DecisionAnswer>,
) -> Option<ProgramTriage> {
    let orders: Vec<OneOrder> = [first, second].into_iter().filter_map(read_order).collect();
    if orders.is_empty() {
        return None;
    }
    let averaged = normalized(TriageRole::ALL.iter().map(|role| {
        orders
            .iter()
            .map(|order| order.roles.get(role).copied().unwrap_or(0.0))
            .sum::<f64>()
            / orders.len() as f64
    }));
    let role_probabilities: BTreeMap<TriageRole, f64> = TriageRole::ALL
        .into_iter()
        .zip(averaged.iter().copied())
        .collect();
    let (role, confidence) = role_probabilities
        .iter()
        .max_by(|left, right| left.1.total_cmp(right.1))
        .map(|(role, probability)| (*role, *probability))?;
    let miss_orders: Vec<&Vec<f64>> = orders
        .iter()
        .map(|order| &order.miss)
        .filter(|miss| !miss.is_empty())
        .collect();
    let miss_probabilities = if miss_orders.is_empty() {
        Vec::new()
    } else {
        normalized((0..MISS_LEVELS.len()).map(|level| {
            miss_orders.iter().map(|miss| miss[level]).sum::<f64>() / miss_orders.len() as f64
        }))
    };
    let miss_level = miss_probabilities
        .iter()
        .enumerate()
        .map(|(level, probability)| level as f64 * probability)
        .sum();
    let orders_agree =
        orders.len() == 2 && orders[0].chosen.is_some() && orders[0].chosen == orders[1].chosen;
    Some(ProgramTriage {
        program_id: program_id.to_owned(),
        role,
        role_probabilities,
        confidence,
        miss_level,
        miss_probabilities,
        orders_agree,
    })
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

/// Triages the last scanned programs, or only `program_ids` when given. Core components are
/// left out: they are part of the session and not candidates for triage.
pub async fn triage_programs(
    program_ids: Option<Vec<String>>,
) -> Result<TriageReport, DecisionError> {
    let _guard = RunningGuard::acquire()?;
    let configuration = DecisionConfiguration::load()?.ok_or(DecisionError::NotConfigured)?;
    configuration.ready()?;
    let (captured_at_ms, home, programs) = LAST_SCAN
        .lock()
        .ok()
        .and_then(|last| {
            last.as_ref().map(|scan| {
                (
                    scan.captured_at_ms,
                    scan.home.clone(),
                    scan.programs.clone(),
                )
            })
        })
        .ok_or(DecisionError::NothingToJudge)?;
    let candidates: Vec<RunningProgram> = programs
        .into_iter()
        .filter(|program| program.safety != ProgramSafetyClass::Core)
        .filter(|program| {
            program_ids
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
        "running_programs_triage_started program_count={} model={:?}",
        candidates.len(),
        configuration.model
    );
    let jobs = candidates.iter().flat_map(|program| {
        let state = program_state(program, captured_at_ms, home.as_deref());
        [false, true].map(|reversed| (program.id.clone(), reversed, request_body(&state, reversed)))
    });
    let configuration_ref = &configuration;
    let responses: Vec<(
        String,
        bool,
        Result<crate::decisions::DecisionResponse, DecisionError>,
    )> = stream::iter(jobs)
        .map(|(id, reversed, body)| async move {
            if TRIAGE_CANCELLED.load(Ordering::Acquire) {
                return (id, reversed, Err(DecisionError::Cancelled));
            }
            (id, reversed, decide(configuration_ref, &body).await)
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
    Ok(TriageReport {
        model: model.unwrap_or(configuration.model),
        results,
        failures,
        input_tokens,
        cost_usd: cost,
        elapsed_ms,
    })
}

#[cfg(test)]
#[path = "triage_tests.rs"]
mod tests;
