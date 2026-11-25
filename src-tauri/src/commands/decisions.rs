use mangodisk_core::decisions::{
    list_decision_models, DecisionConfiguration, DecisionConfigurationUpdate, DecisionError,
    DecisionModel, DecisionSettings,
};
use mangodisk_core::{
    cancel_triage, export_triage, questions_path, suggested_export_file_name, triage_programs,
    write_triage_export, TriageExportFormat, TriageQuestionSet, TriageQuestionSource, TriageReport,
    TriageRequest,
};
use serde::Serialize;
use tauri_plugin_dialog::DialogExt;

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
    triage_programs(TriageRequest {
        program_ids,
        questions: None,
        model: None,
    })
    .await
}

#[tauri::command]
pub(crate) fn running_programs_cancel_triage() {
    cancel_triage();
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub(crate) struct TriageQuestionsInfo {
    path: String,
    /// `None` when the file exists but is not valid; `problem` then says why.
    source: Option<TriageQuestionSource>,
    question_count: usize,
    /// The first rule the file breaks, in English. It quotes only the user's own file.
    problem: Option<String>,
}

/// Where the questions live and whether the file is in use, so the page can flag a broken
/// file before the next triage fails on it.
#[tauri::command]
pub(crate) async fn running_programs_triage_questions() -> Result<TriageQuestionsInfo, DecisionError>
{
    blocking(|| {
        let path = questions_path()?;
        let path_text = path.to_string_lossy().into_owned();
        match TriageQuestionSet::active() {
            Ok((set, source)) => Ok(TriageQuestionsInfo {
                path: path_text,
                source: Some(source),
                question_count: set.questions.len(),
                problem: None,
            }),
            Err(DecisionError::InvalidQuestions) => {
                let text = std::fs::read_to_string(&path).unwrap_or_default();
                Ok(TriageQuestionsInfo {
                    path: path_text,
                    source: None,
                    question_count: 0,
                    problem: TriageQuestionSet::check(&text).err(),
                })
            }
            Err(error) => Err(error),
        }
    })
    .await
}

/// Writes the built-in questions to the questions file unless one exists, and returns its path.
#[tauri::command]
pub(crate) async fn running_programs_create_triage_questions() -> Result<String, DecisionError> {
    blocking(|| {
        Ok(TriageQuestionSet::write_template()?
            .to_string_lossy()
            .into_owned())
    })
    .await
}

/// Renders the last scan and triage, asks where to save it with the native picker, and writes
/// it. No write path comes from the WebView. Returns the saved path, or `None` when cancelled.
#[tauri::command]
pub(crate) async fn running_programs_export_triage(
    window: tauri::WebviewWindow,
    format: TriageExportFormat,
    dialog_title: String,
) -> Result<Option<String>, DecisionError> {
    // Rendered before the picker opens, so a scan finishing meanwhile cannot change the file.
    let text = blocking(move || export_triage(format)).await?;
    let (sender, receiver) = tokio::sync::oneshot::channel();
    window
        .dialog()
        .file()
        .set_parent(&window)
        .set_title(dialog_title)
        .set_file_name(suggested_export_file_name(format))
        .add_filter(
            match format {
                TriageExportFormat::Json => "JSON",
                TriageExportFormat::Markdown => "Markdown",
            },
            match format {
                TriageExportFormat::Json => &["json"],
                TriageExportFormat::Markdown => &["md"],
            },
        )
        .save_file(move |path| {
            let _ = sender.send(path);
        });
    let Some(selected) = receiver.await.map_err(|_| DecisionError::ExportFailed)? else {
        log::info!("triage_export_cancelled stage=file_dialog");
        return Ok(None);
    };
    let path = selected
        .into_path()
        .map_err(|_| DecisionError::InvalidExportPath)?;
    blocking(move || {
        write_triage_export(&path, format, &text)?;
        Ok(Some(path.to_string_lossy().into_owned()))
    })
    .await
}
