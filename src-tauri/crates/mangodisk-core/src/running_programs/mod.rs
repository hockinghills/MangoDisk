//! Running programs: every process grouped into the program it belongs to, with how that program
//! was installed, what started it and what it costs. Read-only.

mod conversion;
mod grouping;
mod launch;
mod models;
mod redaction;
mod service;
mod triage;
mod triage_export;
mod triage_questions;

pub use models::{
    ProgramContainer, ProgramContainerEngine, ProgramDateSource, ProgramLaunch, ProgramLaunchKind,
    ProgramOrigin, ProgramOriginFact, ProgramOriginKind, ProgramPackageManager,
    ProgramPackageRequest, ProgramProcess, ProgramProcessRole, ProgramSafetyClass,
    ProgramUnitFileOrigin, ProgramUnitScope, RunningProgram, RunningProgramsMemory,
    RunningProgramsSnapshot, RunningProgramsSummary, RUNNING_PROGRAMS_SCHEMA_VERSION,
};
pub use service::RunningProgramsService;
pub use triage::{
    cancel_triage, triage_programs, ProgramTriage, TriageAnswer, TriageFailure, TriageReport,
    TriageRequest, TriageRole,
};
pub use triage_export::{
    export_triage, suggested_export_file_name, write_triage_export, TriageExportFormat,
};
pub use triage_questions::{
    questions_path, TriageOption, TriageQuestion, TriageQuestionKind, TriageQuestionSet,
    TriageQuestionSource,
};
