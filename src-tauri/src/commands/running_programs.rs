use mangodisk_core::{RunningProgramsService, RunningProgramsSnapshot};

use super::error::{run_blocking, CommandResult};

#[tauri::command]
pub async fn scan_running_programs() -> CommandResult<RunningProgramsSnapshot> {
    run_blocking("scan_running_programs", RunningProgramsService::scan).await
}

#[tauri::command]
pub fn cancel_running_programs_scan() {
    RunningProgramsService::cancel_scan();
}
