//! Decision provider settings, stored as plain JSON beside the AI provider settings.
//!
//! The file holds the API key, so it is written with owner-only permissions and never logged.
//! Unsupported or invalid documents are rejected without being rewritten.

use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

use super::DecisionError;

const SCHEMA_VERSION: u8 = 1;
const MAX_DOCUMENT_BYTES: u64 = 8 * 1024;
const MAX_KEY_CHARS: usize = 512;
const MAX_MODEL_CHARS: usize = 200;
pub(crate) const DEFAULT_ENDPOINT: &str = "https://openrouter.ai/api";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DecisionConfiguration {
    pub schema_version: u8,
    pub endpoint: String,
    pub api_key: String,
    pub model: String,
}

/// What the frontend may see: never the key itself.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionSettings {
    pub endpoint: String,
    pub model: String,
    pub has_api_key: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionConfigurationUpdate {
    pub endpoint: Option<String>,
    pub model: String,
    /// `None` keeps the saved key.
    pub api_key: Option<String>,
}

fn path() -> Result<PathBuf, DecisionError> {
    crate::shared::application_paths()
        .map(|paths| paths.data_directory().join("decisions.json"))
        .map_err(|_| DecisionError::ConfigurationUnavailable)
}

fn io_failure(stage: &'static str, error: &std::io::Error) -> DecisionError {
    log::warn!(
        "decision_configuration_io_failed stage={stage} kind={:?} os_code={:?}",
        error.kind(),
        error.raw_os_error()
    );
    DecisionError::ConfigurationUnavailable
}

fn valid_endpoint(endpoint: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(endpoint) else {
        return false;
    };
    let local = matches!(url.host_str(), Some("localhost" | "127.0.0.1" | "::1"));
    (url.scheme() == "https" || (url.scheme() == "http" && local))
        && url.query().is_none()
        && url.fragment().is_none()
        && url.username().is_empty()
        && url.password().is_none()
}

impl DecisionConfiguration {
    pub fn settings(&self) -> DecisionSettings {
        DecisionSettings {
            endpoint: self.endpoint.clone(),
            model: self.model.clone(),
            has_api_key: !self.api_key.is_empty(),
        }
    }

    pub fn validate(&self) -> Result<(), DecisionError> {
        let printable = |text: &str| !text.chars().any(char::is_control);
        let valid = self.schema_version == SCHEMA_VERSION
            && valid_endpoint(&self.endpoint)
            && !self.model.trim().is_empty()
            && self.model.chars().count() <= MAX_MODEL_CHARS
            && printable(&self.model)
            && self.api_key.chars().count() <= MAX_KEY_CHARS
            && printable(&self.api_key);
        if valid {
            Ok(())
        } else {
            Err(DecisionError::InvalidConfiguration)
        }
    }

    /// A configuration that can actually be used for a request.
    pub(crate) fn ready(&self) -> Result<(), DecisionError> {
        self.validate()?;
        if self.api_key.is_empty() {
            return Err(DecisionError::NotConfigured);
        }
        Ok(())
    }

    pub fn load() -> Result<Option<Self>, DecisionError> {
        load_from(&path()?)
    }

    pub fn save(update: DecisionConfigurationUpdate) -> Result<DecisionSettings, DecisionError> {
        let path = path()?;
        let previous = load_from(&path).unwrap_or(None);
        let configuration = apply_update(previous, update);
        configuration.validate()?;
        save_to(&path, &configuration)?;
        log::info!(
            "decision_configuration_saved model={:?} endpoint_default={} has_api_key={}",
            configuration.model,
            configuration.endpoint == DEFAULT_ENDPOINT,
            !configuration.api_key.is_empty()
        );
        Ok(configuration.settings())
    }

    pub fn delete() -> Result<(), DecisionError> {
        match fs::remove_file(path()?) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(io_failure("delete", &error)),
        }
    }
}

fn apply_update(
    previous: Option<DecisionConfiguration>,
    update: DecisionConfigurationUpdate,
) -> DecisionConfiguration {
    let previous_key = previous
        .map(|configuration| configuration.api_key)
        .unwrap_or_default();
    DecisionConfiguration {
        schema_version: SCHEMA_VERSION,
        endpoint: update
            .endpoint
            .map(|endpoint| endpoint.trim().trim_end_matches('/').to_owned())
            .filter(|endpoint| !endpoint.is_empty())
            .unwrap_or_else(|| DEFAULT_ENDPOINT.to_owned()),
        model: update.model.trim().to_owned(),
        api_key: update
            .api_key
            .map(|key| key.trim().to_owned())
            .unwrap_or(previous_key),
    }
}

fn load_from(path: &Path) -> Result<Option<DecisionConfiguration>, DecisionError> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(io_failure("open", &error)),
    };
    let mut text = String::new();
    file.take(MAX_DOCUMENT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|error| io_failure("read", &error))?;
    if text.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(DecisionError::InvalidConfiguration);
    }
    let configuration: DecisionConfiguration =
        serde_json::from_str(&text).map_err(|_| DecisionError::InvalidConfiguration)?;
    configuration.validate()?;
    Ok(Some(configuration))
}

fn save_to(path: &Path, configuration: &DecisionConfiguration) -> Result<(), DecisionError> {
    let directory = path
        .parent()
        .ok_or(DecisionError::ConfigurationUnavailable)?;
    fs::create_dir_all(directory).map_err(|error| io_failure("create_directory", &error))?;
    let document = serde_json::to_vec_pretty(configuration)
        .map_err(|_| DecisionError::InvalidConfiguration)?;
    let mut temporary = tempfile::NamedTempFile::new_in(directory)
        .map_err(|error| io_failure("create_temporary", &error))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o600))
            .map_err(|error| io_failure("permissions", &error))?;
    }
    temporary
        .write_all(&document)
        .map_err(|error| io_failure("write", &error))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| io_failure("sync", &error))?;
    temporary
        .persist(path)
        .map_err(|error| io_failure("persist", &error.error))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(model: &str, key: Option<&str>) -> DecisionConfigurationUpdate {
        DecisionConfigurationUpdate {
            endpoint: None,
            model: model.into(),
            api_key: key.map(str::to_owned),
        }
    }

    #[test]
    fn saving_without_a_key_keeps_the_previous_key() {
        let first = apply_update(None, update(" vendor/model-1 ", Some(" sk-test ")));
        assert_eq!(first.endpoint, DEFAULT_ENDPOINT);
        assert_eq!(first.model, "vendor/model-1");
        assert_eq!(first.api_key, "sk-test");
        let second = apply_update(Some(first), update("vendor/model-2", None));
        assert_eq!(second.api_key, "sk-test");
        assert_eq!(second.model, "vendor/model-2");
        assert!(second.settings().has_api_key);
    }

    #[test]
    fn endpoints_must_be_https_or_local() {
        let mut configuration = apply_update(None, update("m", Some("k")));
        assert!(configuration.validate().is_ok());
        for endpoint in [
            "http://example.test/api",
            "https://user:pw@example.test",
            "ftp://x",
            "https://x/api?a=1",
        ] {
            configuration.endpoint = endpoint.into();
            assert_eq!(
                configuration.validate(),
                Err(DecisionError::InvalidConfiguration),
                "{endpoint}"
            );
        }
        configuration.endpoint = "http://127.0.0.1:8080".into();
        assert!(configuration.validate().is_ok());
    }

    #[test]
    fn a_missing_key_is_not_ready() {
        let configuration = apply_update(None, update("m", None));
        assert_eq!(configuration.ready(), Err(DecisionError::NotConfigured));
    }

    #[test]
    fn documents_round_trip_with_owner_only_permissions() {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("decisions.json");
        assert_eq!(load_from(&path), Ok(None));
        let configuration = apply_update(None, update("vendor/model", Some("sk")));
        save_to(&path, &configuration).unwrap();
        assert_eq!(load_from(&path), Ok(Some(configuration)));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }
        fs::write(
            &path,
            r#"{"schemaVersion":9,"endpoint":"https://x","apiKey":"","model":"m"}"#,
        )
        .unwrap();
        assert_eq!(load_from(&path), Err(DecisionError::InvalidConfiguration));
    }
}
