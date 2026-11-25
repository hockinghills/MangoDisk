use super::*;
use crate::running_programs::models::{ProgramOrigin, ProgramProcess};

const NOW: u64 = 1_800_000_000_000;

fn program(name: &str) -> RunningProgram {
    RunningProgram {
        id: format!("Pipx::{name}"),
        name: name.into(),
        package_name: None,
        origin: ProgramOrigin {
            kind: ProgramOriginKind::Pipx,
            name: name.into(),
            version: Some("1.0".into()),
            installed_at_ms: Some(NOW - 400 * DAY_MS),
            date_source: None,
            source_url: Some("https://example.test/secret-repo".into()),
            location: Some("/home/a/.local/share/pipx/venvs/media-sync".into()),
            package_manager: None,
            package_request: None,
            install_command: Some("pip install --token=abc".into()),
            install_burst: false,
            container: None,
            description: Some("Syncs photos to a NAS".into()),
            required_by_count: None,
            facts: vec![],
        },
        safety: ProgramSafetyClass::Yours,
        launches: vec![ProgramLaunch {
            kind: ProgramLaunchKind::Autostart,
            unit: Some("app-media\\x2dsync@autostart.service".into()),
            scope: None,
            desktop_name: Some("media-sync".into()),
            background_slice: false,
            terminal: None,
            multiplexer: None,
            spawned_by: None,
            spawned_by_editor: false,
        }],
        processes: vec![ProgramProcess {
            pid: 1,
            parent_pid: 0,
            uid: 1000,
            name: "media-sync".into(),
            command_line: vec!["media-sync".into(), "--password".into(), "***".into()],
            executable_path: None,
            working_directory: None,
            started_at_ms: 0,
            cpu_percent_now: 0.0,
            memory_kb: 50_000,
            memory_is_proportional: true,
            swap_kb: 0,
            folded_from: None,
            inline_code: false,
            role: None,
            role_detail: None,
        }],
        memory_kb: 50_000,
        memory_is_proportional: true,
        swap_kb: 0,
        cpu_percent_now: 0.0,
        cpu_percent_average: 0.0,
        cpu_seconds: 1.0,
        started_at_ms: 0,
        quiet_since_start: true,
        executable_replaced: false,
    }
}

#[test]
fn the_state_holds_facts_but_no_commands_costs_dates_or_home_path() {
    let state = program_state(&program("media-sync"), NOW, Some("/home/a"));
    let text = state.to_string();
    assert_eq!(state["description"], "Syncs photos to a NAS");
    assert_eq!(state["installed_with"], "pipx");
    assert_eq!(state["installed"], "one to three years ago");
    assert_eq!(state["location"], "~/.local/share/pipx/venvs/media-sync");
    assert_eq!(
        state["started_by"][0],
        "started automatically at login by the autostart entry media-sync"
    );
    assert_eq!(state["almost_idle_since_it_started"], true);
    for absent in [
        "/home/a",
        "--password",
        "token",
        "secret-repo",
        "50000",
        "1800000000000",
    ] {
        assert!(
            !text.contains(absent),
            "state must not contain {absent}: {text}"
        );
    }
}

#[test]
fn request_bodies_reverse_only_the_choice_options() {
    let state = json!({"name": "x"});
    let order = |reversed: bool| -> Vec<usize> {
        let text = serde_json::to_string(&request_body(&state, reversed)).unwrap();
        [
            "\"desktop\"",
            "\"needed\"",
            "\"tool\"",
            "\"leftover\"",
            "\"unclear\"",
        ]
        .iter()
        .map(|key| text.find(key).expect("every option is sent"))
        .collect()
    };
    let forward = order(false);
    assert!(
        forward.windows(2).all(|pair| pair[0] < pair[1]),
        "{forward:?}"
    );
    let backward = order(true);
    assert!(
        backward.windows(2).all(|pair| pair[0] > pair[1]),
        "{backward:?}"
    );
    let text = serde_json::to_string(&request_body(&state, true)).unwrap();
    assert!(text.contains("\"type\":\"score\""));
    assert!(text.find("Nothing anyone uses").unwrap() < text.find("The desktop session").unwrap());
}

fn answers(
    role: &str,
    probabilities: &[(&str, f64)],
    miss: &[f64],
) -> BTreeMap<String, DecisionAnswer> {
    let mut map = BTreeMap::new();
    map.insert(
        "role".to_owned(),
        DecisionAnswer::Choice {
            choice: role.into(),
            probabilities: probabilities
                .iter()
                .map(|(key, value)| ((*key).to_owned(), *value))
                .collect(),
        },
    );
    map.insert(
        "miss".to_owned(),
        DecisionAnswer::Score {
            score: 0.0,
            probabilities: miss
                .iter()
                .enumerate()
                .map(|(level, value)| (level.to_string(), *value))
                .collect(),
        },
    );
    map
}

#[test]
fn both_orders_are_averaged() {
    let first = answers(
        "leftover",
        &[("leftover", 0.8), ("tool", 0.2)],
        &[0.6, 0.4, 0.0, 0.0, 0.0],
    );
    let second = answers(
        "tool",
        &[("leftover", 0.4), ("tool", 0.6)],
        &[0.2, 0.8, 0.0, 0.0, 0.0],
    );
    let result = combine("p", &first, &second).expect("answers");
    assert_eq!(result.role, TriageRole::Leftover);
    assert!((result.confidence - 0.6).abs() < 1e-9);
    assert!(!result.orders_agree);
    assert!((result.miss_probabilities[1] - 0.6).abs() < 1e-9);
    assert!((result.miss_level - 0.6).abs() < 1e-9);
}

#[test]
fn one_usable_order_still_gives_a_result_and_none_gives_nothing() {
    let first = answers("needed", &[("needed", 0.9), ("unclear", 0.1)], &[]);
    let refusal: BTreeMap<String, DecisionAnswer> = [("role".to_owned(), DecisionAnswer::Refusal)]
        .into_iter()
        .collect();
    let result = combine("p", &first, &refusal).expect("one order");
    assert_eq!(result.role, TriageRole::Needed);
    assert!(result.miss_probabilities.is_empty());
    assert!(!result.orders_agree);
    assert!(combine("p", &refusal, &BTreeMap::new()).is_none());
}

#[test]
fn unknown_option_keys_are_ignored() {
    let first = answers(
        "leftover",
        &[("leftover", 0.5), ("surprise", 0.5)],
        &[1.0, 0.0, 0.0, 0.0, 0.0],
    );
    let result = combine("p", &first, &first).expect("answers");
    assert_eq!(result.role, TriageRole::Leftover);
    assert!(
        (result.confidence - 1.0).abs() < 1e-9,
        "probabilities renormalize over known roles"
    );
    assert!(result.orders_agree);
}
