use mangodisk_core::decisions::{
    list_decision_models, DecisionConfiguration, DecisionConfigurationUpdate, DecisionError,
    DecisionModel, DecisionSettings,
};
use mangodisk_core::{cancel_triage, triage_programs, TriageReport};

async fn blocking<T: Send + 'static>(
    work: impl FnOnce() -> Result<T, DecisionError> + Send + 'static,
) -> Result<T, DecisionError> {
    tauri::async_runtime::spawn_blocking(work)
        .await
        .map_err(|_| DecisionError::ConfigurationUnavailable)?
}

#[tauri::command]
pub(crate) async fn decisions_get_settings() -> Result<Option<DecisionSettings>, DecisionError> {
    blocking(|| Ok(DecisionConfiguration::load()?.map(|value| value.settings()))).await
}

#[tauri::command]
pub(crate) async fn decisions_save_settings(
    update: DecisionConfigurationUpdate,
) -> Result<DecisionSettings, DecisionError> {
    blocking(move || DecisionConfiguration::save(update)).await
}

#[tauri::command]
pub(crate) async fn decisions_delete_settings() -> Result<(), DecisionError> {
    blocking(DecisionConfiguration::delete).await
}

#[tauri::command]
pub(crate) async fn decisions_list_models(
    endpoint: Option<String>,
) -> Result<Vec<DecisionModel>, DecisionError> {
    list_decision_models(endpoint).await
}

#[tauri::command]
pub(crate) async fn running_programs_triage(
    program_ids: Option<Vec<String>>,
) -> Result<TriageReport, DecisionError> {
    triage_programs(program_ids).await
}

#[tauri::command]
pub(crate) fn running_programs_cancel_triage() {
    cancel_triage();
}
