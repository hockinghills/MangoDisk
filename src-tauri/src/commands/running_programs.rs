use mangodisk_core::{RunningProgramsService, RunningProgramsSnapshot};

use super::error::{run_blocking, CommandResult};

#[tauri::command]
pub async fn scan_running_programs(
    use_administrator_rights: bool,
) -> CommandResult<RunningProgramsSnapshot> {
    run_blocking("scan_running_programs", move || {
        RunningProgramsService::scan(use_administrator_rights)
    })
    .await
}

#[tauri::command]
pub fn cancel_running_programs_scan() {
    RunningProgramsService::cancel_scan();
}
