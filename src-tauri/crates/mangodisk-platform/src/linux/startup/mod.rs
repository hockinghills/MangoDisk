//! Linux startup sources: XDG autostart entries and systemd user and system services.
//!
//! Each source reports the effective configured state the session will use at the next login or
//! boot. Mutations re-read the item, reject drift from the preflight snapshot, make the smallest
//! source-specific change, and read the item again to verify it.

mod systemd;
mod xdg;

use std::{fs, io::Read, path::Path, time::UNIX_EPOCH};

use crate::{
    PlatformCancellation, PlatformError, PlatformErrorCode, PlatformResult,
    PlatformStartupArtifact, PlatformStartupChangeRequest, PlatformStartupChangeResult,
    PlatformStartupCoverageStatus, PlatformStartupSourceResult,
};

const MAX_STARTUP_FILE_BYTES: u64 = 1024 * 1024;

pub(crate) fn scan_startup(
    cancellation: &PlatformCancellation,
) -> PlatformResult<Vec<PlatformStartupSourceResult>> {
    let started = std::time::Instant::now();
    ensure_not_cancelled(cancellation)?;
    let mut results = vec![xdg::scan(cancellation)?];
    ensure_not_cancelled(cancellation)?;
    results.push(systemd::scan(systemd::UnitScope::User, cancellation)?);
    ensure_not_cancelled(cancellation)?;
    results.push(systemd::scan(systemd::UnitScope::System, cancellation)?);

    log::info!(
        "linux_startup_scan_ready source_count={} item_count={} partial_source_count={} elapsed_ms={}",
        results.len(),
        results.iter().map(|source| source.items.len()).sum::<usize>(),
        results
            .iter()
            .filter(|source| source.status != PlatformStartupCoverageStatus::Complete)
            .count(),
        started.elapsed().as_millis()
    );
    Ok(results)
}

pub(crate) fn change_startup_item(
    request: &PlatformStartupChangeRequest,
    _authorization_prompt: Option<&str>,
) -> PlatformResult<PlatformStartupChangeResult> {
    log::info!(
        "linux_startup_change_requested source_id={} provider_item_id={} display_name={} desired_state={:?}",
        crate::diagnostics::text(&request.source_id),
        crate::diagnostics::text(&request.provider_item_id),
        crate::diagnostics::text(&request.expected_artifact.display_name),
        request.desired_state
    );
    match request.source_id.as_str() {
        xdg::SOURCE_ID => xdg::change(request),
        systemd::USER_SOURCE_ID => systemd::change(systemd::UnitScope::User, request),
        systemd::SYSTEM_SOURCE_ID => systemd::change(systemd::UnitScope::System, request),
        _ => Err(PlatformError::new(
            PlatformErrorCode::Unsupported,
            "unknown Linux startup source",
        )),
    }
}

/// Compares the facts a mutation depends on. Whether a program is running right now may change
/// between preflight and execution without making the change unsafe.
fn same_mutation_facts(
    current: &PlatformStartupArtifact,
    expected: &PlatformStartupArtifact,
) -> bool {
    let mut current = current.clone();
    current.runtime_state = expected.runtime_state;
    &current == expected
}

fn ensure_not_cancelled(cancellation: &PlatformCancellation) -> PlatformResult<()> {
    if cancellation.is_cancelled() {
        return Err(PlatformError::new(
            PlatformErrorCode::UserCancelled,
            "startup scan was cancelled",
        ));
    }
    Ok(())
}

fn read_bounded_text(path: &Path) -> Option<String> {
    let file = fs::File::open(path).ok()?;
    if file.metadata().ok()?.len() > MAX_STARTUP_FILE_BYTES {
        return None;
    }
    let mut content = String::new();
    file.take(MAX_STARTUP_FILE_BYTES.saturating_add(1))
        .read_to_string(&mut content)
        .ok()?;
    (content.len() as u64 <= MAX_STARTUP_FILE_BYTES).then_some(content)
}

fn modified_at_ms(path: &Path) -> Option<u64> {
    fs::metadata(path)
        .ok()
        .and_then(|metadata| metadata.modified().ok())
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_millis() as u64)
}

/// Resolves a command word from a desktop entry or unit to an executable path. Bare names use
/// `PATH`, like the session that would start them.
fn resolve_program(program: &str) -> Option<std::path::PathBuf> {
    if program.is_empty() {
        return None;
    }
    let path = Path::new(program);
    if path.is_absolute() {
        return path.is_file().then(|| path.to_path_buf());
    }
    if program.contains('/') {
        return None;
    }
    let path_value = std::env::var_os("PATH")?;
    std::env::split_paths(&path_value)
        .map(|directory| directory.join(program))
        .find(|candidate| candidate.is_file())
}

fn matches_any_prefix(name: &str, prefixes: &[&str]) -> bool {
    prefixes.iter().any(|prefix| name.starts_with(prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cancellation_uses_the_stable_user_cancelled_code() {
        let cancellation = PlatformCancellation::new(|| true);
        let error = ensure_not_cancelled(&cancellation).unwrap_err();
        assert_eq!(error.code(), PlatformErrorCode::UserCancelled);
    }

    #[test]
    fn oversized_startup_files_are_ignored() {
        let path = std::env::temp_dir().join(format!(
            "mangodisk-linux-startup-big-{}",
            std::process::id()
        ));
        fs::write(&path, vec![b'x'; MAX_STARTUP_FILE_BYTES as usize + 1]).unwrap();
        assert!(read_bounded_text(&path).is_none());
        fs::remove_file(path).unwrap();
    }

    #[test]
    fn absolute_programs_must_exist_and_relative_paths_are_rejected() {
        assert!(resolve_program("/bin/sh").is_some());
        assert!(resolve_program("/nonexistent/mangodisk-test").is_none());
        assert!(resolve_program("bin/sh").is_none());
        assert!(resolve_program("").is_none());
    }
}
