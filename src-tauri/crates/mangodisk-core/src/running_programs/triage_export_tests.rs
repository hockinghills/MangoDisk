use std::collections::BTreeMap;

use super::*;
use crate::running_programs::{
    models::{ProgramOrigin, ProgramOriginKind},
    triage::{ProgramTriage, TriageFailure, TriageReport},
};

fn program(id: &str, name: &str, safety: ProgramSafetyClass, memory_kb: u64) -> RunningProgram {
    RunningProgram {
        id: id.into(),
        name: name.into(),
        package_name: None,
        origin: ProgramOrigin {
            kind: ProgramOriginKind::NpmGlobal,
            name: name.into(),
            version: None,
            installed_at_ms: None,
            date_source: None,
            source_url: None,
            location: Some("/home/a/.npm-global/lib/node_modules/x".into()),
            package_manager: None,
            package_request: None,
            install_command: None,
            install_burst: false,
            container: None,
            description: Some("Does | things".into()),
            required_by_count: None,
            facts: vec![],
        },
        safety,
        launches: vec![],
        processes: vec![],
        memory_kb,
        memory_is_proportional: true,
        swap_kb: 0,
        cpu_percent_now: 0.0,
        cpu_percent_average: 0.5,
        cpu_seconds: 0.0,
        started_at_ms: 0,
        quiet_since_start: false,
        executable_replaced: false,
    }
}

fn judged(id: &str, leftover: f64) -> ProgramTriage {
    let probabilities: BTreeMap<String, f64> = [
        ("leftover".to_owned(), leftover),
        ("tool".to_owned(), 1.0 - leftover),
    ]
    .into_iter()
    .collect();
    ProgramTriage {
        program_id: id.into(),
        answers: [(
            "role".to_owned(),
            TriageAnswer::Choice {
                choice: if leftover > 0.5 { "leftover" } else { "tool" }.into(),
                probabilities,
                confidence: leftover.max(1.0 - leftover),
                orders_agree: leftover != 0.6,
            },
        )]
        .into_iter()
        .collect(),
        role: None,
        role_probabilities: BTreeMap::new(),
        confidence: 0.0,
        miss_level: None,
        miss_probabilities: vec![],
        orders_agree: true,
    }
}

fn report() -> TriageReport {
    TriageReport {
        model: "vendor/decider-1".into(),
        questions: TriageQuestionSet::built_in(),
        question_source: TriageQuestionSource::BuiltIn,
        results: vec![judged("small", 0.9), judged("big", 0.6)],
        failures: vec![TriageFailure {
            program_id: "broken".into(),
            error: DecisionError::RateLimited,
        }],
        input_tokens: 1234,
        cost_usd: Some(0.0001),
        elapsed_ms: 10,
    }
}

fn programs() -> Vec<RunningProgram> {
    vec![
        program("core", "plasmashell", ProgramSafetyClass::Core, 900_000),
        program("small", "old-cli", ProgramSafetyClass::Yours, 10_000),
        program("big", "dev-server", ProgramSafetyClass::Yours, 400_000),
        program("broken", "mystery", ProgramSafetyClass::Yours, 5_000),
    ]
}

#[test]
fn json_exports_sort_by_leftover_weight_and_keep_the_model_facts() {
    let programs = programs();
    let report = report();
    let document = build(1_800_000_000_000, Some("/home/a"), &programs, Some(&report));
    let value = serde_json::to_value(&document).unwrap();
    let ids: Vec<&str> = value["programs"]
        .as_array()
        .unwrap()
        .iter()
        .map(|entry| entry["id"].as_str().unwrap())
        .collect();
    assert_eq!(ids, ["big", "small", "core", "broken"]);
    assert_eq!(value["schemaVersion"], 1);
    assert_eq!(value["capturedAt"], "2027-01-15T08:00:00Z");
    assert_eq!(value["triage"]["model"], "vendor/decider-1");
    assert_eq!(
        value["programs"][0]["facts"]["location"],
        "~/.npm-global/lib/node_modules/x"
    );
    assert_eq!(
        value["programs"][0]["answers"]["role"]["ordersAgree"],
        false
    );
    assert_eq!(value["programs"][2]["judged"], false);
    assert_eq!(value["programs"][3]["error"], "rateLimited");
    assert!(
        !value.to_string().contains("/home/a/"),
        "home paths are shortened"
    );
}

#[test]
fn markdown_exports_escape_cells_and_list_the_questions() {
    let programs = programs();
    let report = report();
    let text = markdown(&build(
        1_800_000_000_000,
        Some("/home/a"),
        &programs,
        Some(&report),
    ));
    assert!(
        text.contains("| dev-server | 391 MB | 0.5% | leftover 60% (orders disagree) | — |"),
        "{text}"
    );
    assert!(text.contains("Does \\| things"));
    assert!(text.contains("## Not judged"));
    assert!(text.contains("| core component |"));
    assert!(text.contains("request failed: RateLimited"));
    assert!(text.contains("```json"));
    let unjudged = markdown(&build(0, None, &programs, None));
    assert!(unjudged.contains("No triage has run yet"));
    assert!(!unjudged.contains("## Judged programs"));
    assert!(unjudged.contains("| no triage ran |"));
}

#[test]
fn exports_only_go_to_json_or_markdown_files() {
    let directory = tempfile::tempdir().unwrap();
    for (name, format) in [
        ("x.txt", TriageExportFormat::Json),
        ("x.json", TriageExportFormat::Markdown),
    ] {
        assert_eq!(
            write_triage_export(&directory.path().join(name), format, "{}"),
            Err(DecisionError::InvalidExportPath)
        );
    }
    assert_eq!(
        write_triage_export(Path::new("relative.json"), TriageExportFormat::Json, "{}"),
        Err(DecisionError::InvalidExportPath)
    );
    #[cfg(unix)]
    {
        let target = directory.path().join("target.json");
        fs::write(&target, "keep").unwrap();
        let link = directory.path().join("link.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert_eq!(
            write_triage_export(&link, TriageExportFormat::Json, "{}"),
            Err(DecisionError::InvalidExportPath)
        );
        assert_eq!(fs::read_to_string(target).unwrap(), "keep");
    }
    let path = directory.path().join("out.MD");
    write_triage_export(&path, TriageExportFormat::Markdown, "# hi\n").unwrap();
    assert_eq!(fs::read_to_string(path).unwrap(), "# hi\n");
}
