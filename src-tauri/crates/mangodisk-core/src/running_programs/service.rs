use std::{sync::atomic::Ordering, time::Instant};

use mangodisk_platform::{
    current_platform, PlatformCancellation, PlatformRunningProgramsRequest, RunningProgramsPlatform,
};

use super::{
    grouping::{group_programs, GroupingInput},
    models::{
        RunningProgramsMemory, RunningProgramsSnapshot, RunningProgramsSummary,
        RUNNING_PROGRAMS_SCHEMA_VERSION,
    },
};
use crate::shared::{
    operation::{CoordinatedOperationKind, OperationCancellationToken, OperationGuard},
    CoreResult,
};

/// Long enough to tell a busy process from an idle one without making the page wait.
const CPU_SAMPLE_MS: u64 = 1_000;

pub struct RunningProgramsService;

impl RunningProgramsService {
    pub fn cancel_scan() {
        OperationCancellationToken::running_programs_scan().cancel();
    }

    pub fn scan() -> CoreResult<RunningProgramsSnapshot> {
        let operation = OperationGuard::start(CoordinatedOperationKind::RunningProgramsScan)?;
        let started = Instant::now();
        let flag = operation.cancellation_flag();
        let cancellation = PlatformCancellation::new(move || flag.load(Ordering::Relaxed));
        let capture = current_platform().capture_running_programs(
            &PlatformRunningProgramsRequest {
                cpu_sample_ms: CPU_SAMPLE_MS,
            },
            &cancellation,
        )?;
        operation.ensure_not_cancelled()?;
        let memory = RunningProgramsMemory {
            total_kb: capture.memory.total_kb,
            available_kb: capture.memory.available_kb,
            swap_total_kb: capture.memory.swap_total_kb,
            swap_used_kb: capture
                .memory
                .swap_total_kb
                .saturating_sub(capture.memory.swap_free_kb),
            compressed_swap_used_kb: capture.memory.compressed_swap_used_kb,
            compressed_swap_ram_kb: capture.memory.compressed_swap_ram_kb,
        };
        let process_count = capture.processes.len();
        let unit_count = capture.units.len();
        let programs = group_programs(GroupingInput {
            processes: capture.processes,
            units: capture.units,
            home: capture.home_directory,
            now_ms: capture.captured_at_ms,
        });
        let summary = RunningProgramsSummary {
            process_count,
            program_count: programs.len(),
            side_installed_count: programs
                .iter()
                .filter(|program| program.origin.kind.is_side_install())
                .count(),
            memory_kb: programs.iter().map(|program| program.memory_kb).sum(),
            swap_kb: programs.iter().map(|program| program.swap_kb).sum(),
        };
        let elapsed_ms = started.elapsed().as_millis() as u64;
        log::info!(
            "running_programs_scanned operation_id={} process_count={} program_count={} side_installed_count={} unit_count={} elevated={} elapsed_ms={}",
            operation.id(),
            summary.process_count,
            summary.program_count,
            summary.side_installed_count,
            unit_count,
            capture.elevated,
            elapsed_ms,
        );
        operation.complete();
        Ok(RunningProgramsSnapshot {
            schema_version: RUNNING_PROGRAMS_SCHEMA_VERSION,
            captured_at_ms: capture.captured_at_ms,
            elapsed_ms,
            elevated: capture.elevated,
            memory,
            programs,
            summary,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[ignore = "captures the live process table of the machine running the tests"]
    fn live_scan_groups_this_machine() {
        let snapshot = RunningProgramsService::scan().expect("scan succeeds");
        for program in snapshot.programs.iter().take(40) {
            println!(
                "{:>8} KB {:>6.1}% {:<28} {:?} {:?} {:?}",
                program.memory_kb,
                program.cpu_percent_average,
                program.name,
                program.origin.kind,
                program.safety,
                program.launches.first().map(|launch| launch.kind),
            );
        }
        assert!(snapshot.summary.process_count > 0);
    }
}
