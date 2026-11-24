//! Resolves an interpreter process to the script or module it runs.
//!
//! `python3 /home/me/tools/x.py` is the program `x.py`, not Python. For launches whose script is
//! not on the command line (`npm run dev`, a dev server that rewrote its process title) the
//! project folder is the best identity available.

use std::path::{Component, Path, PathBuf};

use super::{
    file_facts::{canonical, find_upwards, is_system_path},
    proc_reader::RawProcess,
};
use crate::{PlatformInterpreterFamily, PlatformProgramTarget};

const SHELLS: &[&str] = &[
    "bash", "sh", "dash", "zsh", "fish", "ksh", "mksh", "tcsh", "csh", "nu",
];
const RUNNER_WORDS: &[&str] = &["run", "x", "exec", "start", "serve"];
const RUNNER_FILES: &[&str] = &[
    "npm-cli.js",
    "npx-cli.js",
    "pnpm.cjs",
    "pnpm.mjs",
    "pnpm.js",
    "yarn.js",
    "yarn.cjs",
    "corepack.js",
    "npm",
    "npx",
    "pnpm",
    "yarn",
];
/// Build output folders often carry their own `package.json`; the project is above them.
const BUILD_DIRS: &[&str] = &[
    "dist",
    "build",
    "out",
    "standalone",
    ".next",
    ".output",
    "server",
    "lib",
    "bundle",
];
const PROJECT_MARKERS: &[&str] = &[
    "package.json",
    "pyproject.toml",
    "Cargo.toml",
    "go.mod",
    "Gemfile",
    "composer.json",
    ".git",
];
pub(super) const SYSTEM_BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/usr/sbin",
    "/bin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

pub(super) fn interpreter_family(name: &str) -> Option<PlatformInterpreterFamily> {
    let versioned = |prefix: &str| {
        name.strip_prefix(prefix)
            .is_some_and(|rest| rest.chars().all(|ch| ch.is_ascii_digit() || ch == '.'))
    };
    let python = name
        .strip_prefix("python")
        .map(|rest| rest.split_once('-').map_or(rest, |(version, _)| version))
        .is_some_and(|version| version.chars().all(|ch| ch.is_ascii_digit() || ch == '.'));
    if python || versioned("pypy") {
        Some(PlatformInterpreterFamily::Python)
    } else if matches!(name, "node" | "nodejs" | "bun" | "deno") {
        Some(PlatformInterpreterFamily::Node)
    } else if matches!(name, "gjs" | "gjs-console" | "cjs") {
        Some(PlatformInterpreterFamily::Gjs)
    } else if versioned("ruby") {
        Some(PlatformInterpreterFamily::Ruby)
    } else if versioned("perl") {
        Some(PlatformInterpreterFamily::Perl)
    } else if versioned("php") {
        Some(PlatformInterpreterFamily::Php)
    } else if SHELLS.contains(&name) {
        Some(PlatformInterpreterFamily::Shell)
    } else if name == "java" {
        Some(PlatformInterpreterFamily::Java)
    } else if name == "luajit" || versioned("lua") {
        Some(PlatformInterpreterFamily::Lua)
    } else {
        None
    }
}

/// Options that consume the following argument, per interpreter family.
fn option_takes_value(family: PlatformInterpreterFamily, arg: &str) -> bool {
    use PlatformInterpreterFamily as F;
    let options: &[&str] = match family {
        F::Python => &["-W", "-X", "--check-hash-based-pycs"],
        F::Node => &[
            "-r",
            "--require",
            "--loader",
            "--experimental-loader",
            "--import",
            "--env-file",
            "--conditions",
            "-C",
            "--inspect-port",
            "--title",
        ],
        F::Ruby => &["-I", "-r", "-C", "-E", "--encoding"],
        F::Perl => &["-I", "-M", "-m"],
        F::Php => &["-c", "-d", "-z"],
        F::Shell => &["-o", "+o", "-O", "+O", "--rcfile", "--init-file"],
        F::Java => &[
            "-cp",
            "-classpath",
            "--class-path",
            "-p",
            "--module-path",
            "--add-modules",
            "--add-opens",
            "--add-exports",
        ],
        F::Lua => &["-l"],
        F::Gjs => &["-I", "--include-path", "--profile", "--debugger"],
    };
    options.contains(&arg)
}

fn is_inline_flag(family: PlatformInterpreterFamily, arg: &str) -> bool {
    use PlatformInterpreterFamily as F;
    let flags: &[&str] = match family {
        F::Python => &["-c"],
        F::Node => &["-e", "--eval", "-p", "--print"],
        F::Ruby | F::Lua => &["-e"],
        F::Perl => &["-e", "-E"],
        F::Php => &["-r"],
        F::Gjs => &["-c", "--command"],
        F::Shell | F::Java => &[],
    };
    flags.contains(&arg)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum ScriptArgument {
    Path(Option<PathBuf>),
    Module(String),
    Inline,
    None,
}

/// Splits a `sh -c` command into words. Only plain and quoted words are recognized, which is
/// enough to find the program a wrapper script starts.
fn shell_words(command: &str) -> Option<Vec<String>> {
    let mut words = Vec::new();
    let mut current = String::new();
    let mut quote: Option<char> = None;
    let mut in_word = false;
    let mut chars = command.chars();
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(open), _) if ch == open => quote = None,
            (Some('"'), '\\') => current.push(chars.next()?),
            (Some(_), _) => current.push(ch),
            (None, '\'' | '"') => {
                quote = Some(ch);
                in_word = true;
            }
            (None, '\\') => {
                current.push(chars.next()?);
                in_word = true;
            }
            (None, _) if ch.is_whitespace() => {
                if in_word {
                    words.push(std::mem::take(&mut current));
                    in_word = false;
                }
            }
            (None, ';' | '&' | '|') => break,
            (None, _) => {
                current.push(ch);
                in_word = true;
            }
        }
    }
    if quote.is_some() {
        return None;
    }
    if in_word {
        words.push(current);
    }
    Some(words)
}

pub(super) fn absolute(path: &str, cwd: Option<&Path>) -> Option<PathBuf> {
    let path = Path::new(path);
    if path.is_absolute() {
        return Some(normalize(path));
    }
    cwd.map(|cwd| normalize(&cwd.join(path)))
}

/// Lexical normalization; symlinks are resolved separately when the file exists.
fn normalize(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

pub(super) fn find_script(
    family: PlatformInterpreterFamily,
    args: &[String],
    cwd: Option<&Path>,
) -> ScriptArgument {
    use PlatformInterpreterFamily as F;
    let mut skip = false;
    for (index, arg) in args.iter().enumerate() {
        if skip {
            skip = false;
            continue;
        }
        let next = args.get(index + 1);
        if arg == "--" {
            continue;
        }
        if family == F::Python && arg == "-m" {
            if let Some(module) = next {
                return ScriptArgument::Module(module.clone());
            }
        }
        if family == F::Java && arg == "-jar" {
            if let Some(jar) = next {
                return ScriptArgument::Path(absolute(jar, cwd));
            }
        }
        if family == F::Shell && arg == "-c" {
            let words: Vec<String> = next
                .and_then(|command| shell_words(command))
                .unwrap_or_default()
                .into_iter()
                .filter(|word| !matches!(word.as_str(), "exec" | "nohup" | "env"))
                .collect();
            return match words.first() {
                Some(first) if first.contains('/') => ScriptArgument::Path(absolute(first, cwd)),
                _ => ScriptArgument::Inline,
            };
        }
        if is_inline_flag(family, arg) {
            return ScriptArgument::Inline;
        }
        if option_takes_value(family, arg) {
            skip = true;
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            continue;
        }
        if family == F::Node && RUNNER_WORDS.contains(&arg.as_str()) {
            continue;
        }
        if family == F::Java {
            return ScriptArgument::Module(arg.clone());
        }
        return ScriptArgument::Path(absolute(arg, cwd));
    }
    ScriptArgument::None
}

/// Names the package-manager runner a node script belongs to.
pub(super) fn runner_name(path: &Path) -> Option<String> {
    let text = path.to_string_lossy();
    const PACKAGES: &[(&str, &str)] = &[
        ("/node_modules/npm/", "npm"),
        ("/node_modules/pnpm/", "pnpm"),
        ("/node_modules/@pnpm/exe/", "pnpm"),
        ("/node_modules/yarn/", "yarn"),
        ("/node_modules/@yarnpkg/cli-dist/", "yarn"),
        ("/node_modules/corepack/", "corepack"),
        ("/Cellar/pnpm/", "pnpm"),
        ("/Cellar/yarn/", "yarn"),
    ];
    if let Some((_, name)) = PACKAGES.iter().find(|(marker, _)| text.contains(marker)) {
        return Some((*name).to_owned());
    }
    let base = path.file_name()?.to_str()?;
    RUNNER_FILES
        .contains(&base)
        .then(|| base.split(['-', '.']).next().unwrap_or(base).to_owned())
}

fn project_dir(process: &RawProcess, home: Option<&Path>) -> Option<PathBuf> {
    if let Some(manifest) = process
        .environment
        .get("npm_package_json")
        .map(PathBuf::from)
    {
        if manifest.exists() {
            return manifest.parent().map(Path::to_path_buf);
        }
    }
    let cwd = process.working_directory.as_deref()?;
    if cwd == Path::new("/") || Some(cwd) == home || is_system_path(cwd) {
        return None;
    }
    let inside_home = home.is_some_and(|home| cwd.starts_with(home));
    if !inside_home
        && ["/tmp", "/proc", "/run", "/dev"]
            .iter()
            .any(|root| cwd.starts_with(root))
    {
        return None;
    }
    let stops: Vec<&Path> = home.into_iter().collect();
    for marker in PROJECT_MARKERS {
        let mut found = find_upwards(cwd, marker, &stops);
        while let Some(folder) = found.clone() {
            let is_build_dir = folder
                .file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| BUILD_DIRS.contains(&name));
            let above = folder
                .parent()
                .and_then(|parent| find_upwards(parent, marker, &stops));
            match above {
                Some(above) if is_build_dir => found = Some(above),
                _ => break,
            }
        }
        if let Some(folder) = found.filter(|folder| Some(folder.as_path()) != home) {
            return Some(folder);
        }
    }
    Some(cwd.to_path_buf())
}

/// Finds a command in the system directories first: other users' daemons rarely run from the
/// current user's `PATH`.
pub(super) fn system_which(name: &str) -> Option<PathBuf> {
    if name.is_empty() || name.contains('/') {
        return None;
    }
    let path_dirs: Vec<PathBuf> = std::env::var_os("PATH")
        .map(|value| std::env::split_paths(&value).collect())
        .unwrap_or_default();
    SYSTEM_BIN_DIRS
        .iter()
        .map(PathBuf::from)
        .chain(path_dirs)
        .map(|dir| dir.join(name))
        .find(|candidate| candidate.is_file())
        .map(|candidate| canonical(&candidate))
}

fn file_name(path: &Path) -> &str {
    path.file_name()
        .and_then(|name| name.to_str())
        .unwrap_or("")
}

/// The program file and how the process was started. `executable` is the binary to classify
/// when the process is not an interpreter.
pub(super) struct ResolvedTarget {
    pub target: PlatformProgramTarget,
    pub executable: Option<PathBuf>,
    /// Interpreter binary and the absolute argv[0] when it differs (a virtualenv's symlink).
    pub interpreter_paths: Vec<PathBuf>,
}

pub(super) fn resolve_target(process: &RawProcess, home: Option<&Path>) -> ResolvedTarget {
    let argv0 = process
        .command_line
        .first()
        .map(String::as_str)
        .unwrap_or("");
    let first = argv0
        .split_whitespace()
        .next()
        .unwrap_or("")
        .trim_end_matches(':');
    let mut executable = process.executable.clone();
    if executable.is_none() && first.starts_with('/') {
        // Another user's process hides its program file, but argv[0] usually names it.
        let path = Path::new(first);
        executable = Some(if path.exists() {
            canonical(path)
        } else {
            path.to_path_buf()
        });
    }
    if executable.is_none() && !first.is_empty() {
        executable = system_which(first);
    }
    let names = [
        executable.as_deref().map(file_name).unwrap_or(""),
        file_name(Path::new(argv0)),
        process.name.as_str(),
    ];
    let Some(family) = names
        .iter()
        .filter(|name| !name.is_empty())
        .find_map(|name| interpreter_family(name))
    else {
        return ResolvedTarget {
            target: PlatformProgramTarget {
                path: executable.clone(),
                ..Default::default()
            },
            executable,
            interpreter_paths: Vec::new(),
        };
    };
    let mut interpreter_paths: Vec<PathBuf> = executable.iter().cloned().collect();
    if argv0.starts_with('/') && executable.as_deref() != Some(Path::new(argv0)) {
        interpreter_paths.push(PathBuf::from(argv0));
    }
    let cwd = process.working_directory.as_deref();
    let script = find_script(family, process.command_line.get(1..).unwrap_or(&[]), cwd);
    let mut target = PlatformProgramTarget {
        interpreter: Some(family),
        ..Default::default()
    };
    match &script {
        ScriptArgument::Path(Some(path)) if path.exists() => target.path = Some(canonical(path)),
        ScriptArgument::Module(module) => target.module = Some(module.clone()),
        ScriptArgument::Inline => target.inline = true,
        _ => {}
    }
    let exe_name = executable.as_deref().map(file_name).unwrap_or("");
    if target.path.is_none()
        && script == ScriptArgument::None
        && !first.is_empty()
        && !first.contains('/')
        && executable.is_some()
        && first != exe_name
    {
        // Node and Perl daemons often overwrite argv with a process title; look the title up.
        target.path = title_command(process, first, executable.as_deref(), home);
    }
    if target.path.is_none() {
        // Interactive shells, REPLs and inline code are identified by the interpreter itself.
        target.path = executable.clone();
    }
    if family == PlatformInterpreterFamily::Node {
        target.runner = target.path.as_deref().and_then(runner_name);
    }
    let project_family = !matches!(
        family,
        PlatformInterpreterFamily::Shell | PlatformInterpreterFamily::Gjs
    );
    if project_family
        && !target.inline
        && (target.runner.is_some() || (target.path == executable && target.module.is_none()))
    {
        target.project_dir = project_dir(process, home);
    }
    ResolvedTarget {
        target,
        executable,
        interpreter_paths,
    }
}

fn title_command(
    process: &RawProcess,
    title: &str,
    executable: Option<&Path>,
    home: Option<&Path>,
) -> Option<PathBuf> {
    if let Some(launched) = process.environment.get("_").map(PathBuf::from) {
        if file_name(&launched) == title && launched.exists() {
            return Some(canonical(&launched));
        }
    }
    let mut search: Vec<PathBuf> = executable
        .and_then(Path::parent)
        .map(Path::to_path_buf)
        .into_iter()
        .collect();
    if let Some(home) = home {
        for dir in [
            ".local/bin",
            ".npm-global/bin",
            ".bun/bin",
            ".local/share/pnpm",
        ] {
            search.push(home.join(dir));
        }
    }
    search.extend(SYSTEM_BIN_DIRS.iter().map(PathBuf::from));
    search
        .into_iter()
        .map(|dir| dir.join(title))
        .find(|candidate| candidate.is_file())
        .map(|candidate| canonical(&candidate))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_owned()).collect()
    }

    #[test]
    fn interpreter_names_are_recognized_with_versions() {
        use PlatformInterpreterFamily as F;
        assert_eq!(interpreter_family("python3.12"), Some(F::Python));
        assert_eq!(interpreter_family("python3-dbg"), Some(F::Python));
        assert_eq!(interpreter_family("node"), Some(F::Node));
        assert_eq!(interpreter_family("perl5.38"), Some(F::Perl));
        assert_eq!(interpreter_family("bash"), Some(F::Shell));
        assert_eq!(interpreter_family("luajit"), Some(F::Lua));
        assert_eq!(interpreter_family("pythonista"), None);
        assert_eq!(interpreter_family("rustc"), None);
    }

    #[test]
    fn python_module_and_inline_code_are_distinguished() {
        let cwd = Path::new("/srv");
        assert_eq!(
            find_script(
                PlatformInterpreterFamily::Python,
                &args(&["-u", "-m", "http.server"]),
                Some(cwd)
            ),
            ScriptArgument::Module("http.server".into())
        );
        assert_eq!(
            find_script(
                PlatformInterpreterFamily::Python,
                &args(&["-c", "print(1)"]),
                Some(cwd)
            ),
            ScriptArgument::Inline
        );
        assert_eq!(
            find_script(
                PlatformInterpreterFamily::Python,
                &args(&["-W", "ignore", "tool.py"]),
                Some(cwd)
            ),
            ScriptArgument::Path(Some(PathBuf::from("/srv/tool.py")))
        );
    }

    #[test]
    fn node_runner_words_and_value_options_are_skipped() {
        assert_eq!(
            find_script(
                PlatformInterpreterFamily::Node,
                &args(&["--require", "x.js", "run", "../app/server.js"]),
                Some(Path::new("/srv/web"))
            ),
            ScriptArgument::Path(Some(PathBuf::from("/srv/app/server.js")))
        );
    }

    #[test]
    fn shell_wrappers_point_at_the_program_they_start() {
        assert_eq!(
            find_script(
                PlatformInterpreterFamily::Shell,
                &args(&["-c", "exec '/opt/my tool/run' --flag"]),
                None
            ),
            ScriptArgument::Path(Some(PathBuf::from("/opt/my tool/run")))
        );
        assert_eq!(
            find_script(
                PlatformInterpreterFamily::Shell,
                &args(&["-c", "echo hi; sleep 1"]),
                None
            ),
            ScriptArgument::Inline
        );
    }

    #[test]
    fn java_jar_and_main_class() {
        assert_eq!(
            find_script(
                PlatformInterpreterFamily::Java,
                &args(&["-Xmx1g", "-cp", "lib/*", "org.example.Main"]),
                None
            ),
            ScriptArgument::Module("org.example.Main".into())
        );
        assert_eq!(
            find_script(
                PlatformInterpreterFamily::Java,
                &args(&["-jar", "/opt/app.jar"]),
                None
            ),
            ScriptArgument::Path(Some(PathBuf::from("/opt/app.jar")))
        );
    }

    #[test]
    fn package_manager_runners_are_named() {
        assert_eq!(
            runner_name(Path::new("/usr/lib/node_modules/npm/bin/npm-cli.js")).as_deref(),
            Some("npm")
        );
        assert_eq!(
            runner_name(Path::new("/home/a/.local/share/pnpm/pnpm.cjs")).as_deref(),
            Some("pnpm")
        );
        assert_eq!(runner_name(Path::new("/srv/app/server.js")), None);
    }
}
