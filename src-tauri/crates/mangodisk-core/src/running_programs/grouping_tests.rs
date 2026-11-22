use std::path::PathBuf;

use mangodisk_platform::{
    PlatformProcessRecord, PlatformProgramOrigin, PlatformProgramOriginKind, PlatformProgramTarget,
    PlatformServiceUnitFacts, PlatformServiceUnitScope, PlatformUnitFileOrigin,
};

use super::*;

const NOW: u64 = 1_800_000_000_000;
const HOUR: u64 = 3_600_000;
const USER_APPS: &str = "/user.slice/user-1000.slice/user@1000.service/app.slice";

fn package(name: &str) -> PlatformProgramOrigin {
    let mut origin = PlatformProgramOrigin::new(PlatformProgramOriginKind::SystemPackage, name);
    origin.location = Some(name.to_owned());
    origin
}

fn process(
    pid: u32,
    parent_pid: u32,
    name: &str,
    exe: &str,
    cgroup: &str,
    origin: PlatformProgramOrigin,
) -> PlatformProcessRecord {
    PlatformProcessRecord {
        pid,
        parent_pid,
        uid: 1000,
        name: name.to_owned(),
        command_line: vec![exe.to_owned()],
        executable_path: Some(PathBuf::from(exe)),
        executable_replaced: false,
        working_directory: None,
        cgroup: Some(cgroup.to_owned()),
        started_at_ms: NOW - HOUR + u64::from(pid),
        cpu_seconds: 1.0,
        cpu_percent_now: 0.0,
        resident_kb: 2_000,
        proportional_kb: Some(1_000),
        swap_kb: 100,
        target: PlatformProgramTarget {
            path: Some(PathBuf::from(exe)),
            ..Default::default()
        },
        origin,
    }
}

fn group(
    processes: Vec<PlatformProcessRecord>,
    units: Vec<PlatformServiceUnitFacts>,
) -> Vec<RunningProgram> {
    group_programs(GroupingInput {
        processes,
        units,
        home: Some(PathBuf::from("/home/a")),
        now_ms: NOW,
    })
}

fn find<'a>(programs: &'a [RunningProgram], name: &str) -> &'a RunningProgram {
    programs
        .iter()
        .find(|program| program.name == name)
        .unwrap_or_else(|| panic!("no program named {name}"))
}

#[test]
fn a_service_counts_its_plugins_and_they_do_not_make_it_core() {
    let cgroup = "/system.slice/netdata.service";
    let programs = group(
        vec![
            process(
                1,
                0,
                "systemd",
                "/usr/lib/systemd/systemd",
                "/init.scope",
                package("systemd"),
            ),
            process(
                10,
                1,
                "netdata",
                "/usr/sbin/netdata",
                cgroup,
                package("netdata"),
            ),
            process(
                11,
                10,
                "systemd-journal",
                "/usr/libexec/netdata/plugins.d/systemd-journal.plugin",
                cgroup,
                package("netdata-plugin-systemd-journal"),
            ),
            process(
                12,
                10,
                "apps.plugin",
                "/usr/libexec/netdata/plugins.d/apps.plugin",
                cgroup,
                package("netdata-plugin-apps"),
            ),
        ],
        Vec::new(),
    );
    let netdata = find(&programs, "netdata");
    assert_eq!(netdata.processes.len(), 3);
    assert_eq!(netdata.memory_kb, 3_000);
    assert_eq!(netdata.swap_kb, 300);
    assert_eq!(netdata.safety, ProgramSafetyClass::System);
    assert!(netdata
        .processes
        .iter()
        .any(|process| process.folded_from.as_deref() == Some("netdata-plugin-apps")));
    assert_eq!(netdata.launches[0].kind, ProgramLaunchKind::SystemService);
    assert_eq!(find(&programs, "systemd").safety, ProgramSafetyClass::Core);
}

#[test]
fn distro_tools_started_by_a_side_install_belong_to_it() {
    let mut tool = PlatformProgramOrigin::new(PlatformProgramOriginKind::Pipx, "media-sync");
    tool.location = Some("/home/a/.local/share/pipx/venvs/media-sync".into());
    let scope = format!("{USER_APPS}/app-media\\x2dsync@autostart.service");
    let programs = group(
        vec![
            process(20, 1, "media-sync", "/usr/bin/python3.12", &scope, tool),
            process(
                21,
                20,
                "ffmpeg",
                "/usr/bin/ffmpeg",
                &scope,
                package("ffmpeg"),
            ),
        ],
        Vec::new(),
    );
    assert_eq!(programs.len(), 1);
    let program = &programs[0];
    assert_eq!(program.origin.kind, ProgramOriginKind::Pipx);
    assert_eq!(program.safety, ProgramSafetyClass::Yours);
    assert_eq!(program.launches[0].kind, ProgramLaunchKind::Autostart);
    assert_eq!(
        program.launches[0].desktop_name.as_deref(),
        Some("media-sync")
    );
}

#[test]
fn a_distro_program_run_by_an_added_service_is_named_after_the_service() {
    let unit = PlatformServiceUnitFacts {
        scope: PlatformServiceUnitScope::System,
        name: "chat-bot.service".into(),
        fragment_path: Some(PathBuf::from("/etc/systemd/system/chat-bot.service")),
        fragment_origin: PlatformUnitFileOrigin::AddedToEtc,
        fragment_modified_ms: Some(NOW - 30 * 24 * HOUR),
        unit_file_state: Some("enabled".into()),
    };
    let programs = group(
        vec![
            process(
                30,
                1,
                "python3",
                "/usr/bin/python3.12",
                "/system.slice/chat-bot.service",
                package("python3.12-minimal"),
            ),
            process(
                31,
                1,
                "python3",
                "/usr/bin/python3.12",
                &format!("{USER_APPS}/app-org.kde.konsole-1.scope"),
                package("python3.12-minimal"),
            ),
        ],
        vec![unit],
    );
    let service = find(&programs, "chat-bot");
    assert_eq!(service.origin.kind, ProgramOriginKind::AddedService);
    assert_eq!(
        service.origin.date_source,
        Some(ProgramDateSource::UnitFileDate)
    );
    assert_eq!(service.safety, ProgramSafetyClass::Yours);
    assert!(service
        .origin
        .facts
        .contains(&ProgramOriginFact::ServiceRunsProgram {
            program: "python3".into(),
            package: Some("python3.12-minimal".into()),
        }));
    let other = find(&programs, "python3");
    assert_eq!(other.package_name.as_deref(), Some("python3.12-minimal"));
    assert_eq!(other.processes.len(), 1);
}

#[test]
fn packaged_units_are_not_renamed() {
    let unit = PlatformServiceUnitFacts {
        scope: PlatformServiceUnitScope::System,
        name: "ssh.service".into(),
        fragment_path: Some(PathBuf::from("/usr/lib/systemd/system/ssh.service")),
        fragment_origin: PlatformUnitFileOrigin::Package("openssh-server".into()),
        fragment_modified_ms: None,
        unit_file_state: Some("enabled".into()),
    };
    let programs = group(
        vec![process(
            40,
            1,
            "sshd",
            "/usr/sbin/sshd",
            "/system.slice/ssh.service",
            package("openssh-server"),
        )],
        vec![unit],
    );
    let sshd = find(&programs, "sshd");
    assert_eq!(sshd.package_name.as_deref(), Some("openssh-server"));
    assert_eq!(sshd.safety, ProgramSafetyClass::Core);
}

#[test]
fn terminal_scopes_keep_what_runs_inside_them_separate() {
    let scope = format!("{USER_APPS}/app-org.kde.konsole-1.scope");
    let programs = group(
        vec![
            process(
                50,
                1,
                "konsole",
                "/usr/bin/konsole",
                &scope,
                package("konsole"),
            ),
            process(51, 50, "zsh", "/usr/bin/zsh", &scope, package("zsh")),
            process(52, 51, "htop", "/usr/bin/htop", &scope, package("htop")),
        ],
        Vec::new(),
    );
    assert_eq!(programs.len(), 3);
    let htop = find(&programs, "htop");
    assert_eq!(htop.launches[0].kind, ProgramLaunchKind::Terminal);
    assert_eq!(htop.launches[0].terminal.as_deref(), Some("konsole"));
}

#[test]
fn command_lines_are_redacted_and_quiet_programs_are_marked() {
    let mut record = process(
        60,
        1,
        "agent",
        "/opt/agent/bin/agent",
        "/system.slice/agent.service",
        {
            let mut origin =
                PlatformProgramOrigin::new(PlatformProgramOriginKind::ManualOpt, "agent");
            origin.location = Some("/opt/agent".into());
            origin
        },
    );
    record.command_line = vec![
        "/opt/agent/bin/agent".into(),
        "--token".into(),
        "s3cret".into(),
    ];
    record.started_at_ms = NOW - 48 * HOUR;
    record.cpu_seconds = 10.0;
    let programs = group(vec![record], Vec::new());
    let agent = &programs[0];
    assert_eq!(
        agent.processes[0].command_line,
        ["/opt/agent/bin/agent", "--token", "***"]
    );
    assert!(agent.quiet_since_start);
    assert_eq!(agent.safety, ProgramSafetyClass::Yours);
}

#[test]
fn programs_are_sorted_by_memory_and_swap() {
    let mut big = process(
        70,
        1,
        "big",
        "/usr/bin/big",
        "/system.slice/big.service",
        package("big"),
    );
    big.proportional_kb = Some(50_000);
    let programs = group(
        vec![
            process(
                71,
                1,
                "small",
                "/usr/bin/small",
                "/system.slice/small.service",
                package("small"),
            ),
            big,
        ],
        Vec::new(),
    );
    assert_eq!(programs[0].name, "big");
}
