//! HTTP exchange with an OpenRouter-compatible Decisions API.

use std::{collections::BTreeMap, time::Duration};

use reqwest::header::AUTHORIZATION;
use serde::Serialize;
use serde_json::Value;

use super::{DecisionConfiguration, DecisionError};

const REQUEST_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_RESPONSE_BYTES: usize = 1024 * 1024;
const MAX_CATALOG_BYTES: usize = 8 * 1024 * 1024;

/// One scored answer. Unknown answer types are kept as `Unknown` so a new API field never
/// breaks the other answers in the same response.
#[derive(Debug, Clone, PartialEq)]
pub(crate) enum DecisionAnswer {
    Choice {
        choice: String,
        probabilities: BTreeMap<String, f64>,
    },
    Score {
        score: f64,
        probabilities: BTreeMap<String, f64>,
    },
    Noul {
        probability: f64,
    },
    Refusal,
    Unknown,
}

#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DecisionResponse {
    pub model: Option<String>,
    pub answers: BTreeMap<String, DecisionAnswer>,
    pub cost_usd: Option<f64>,
    pub input_tokens: u64,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DecisionModel {
    pub id: String,
    pub name: String,
    pub context_length: Option<u64>,
    /// USD per million input tokens; decision models do not charge for output.
    pub input_price_per_million: Option<f64>,
}

fn client() -> Result<reqwest::Client, DecisionError> {
    crate::http_client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .retry(reqwest::retry::never())
        .connect_timeout(Duration::from_secs(10))
        .timeout(REQUEST_TIMEOUT)
        .build()
        .map_err(|_| DecisionError::ConnectionFailed)
}

fn network_error(error: &reqwest::Error) -> DecisionError {
    if error.is_timeout() {
        DecisionError::Timeout
    } else {
        DecisionError::ConnectionFailed
    }
}

pub(super) fn status_error(status: u16) -> DecisionError {
    match status {
        401 | 403 => DecisionError::Unauthorized,
        402 => DecisionError::InsufficientCredits,
        429 => DecisionError::RateLimited,
        404 => DecisionError::ModelUnavailable,
        400 | 413 | 422 => DecisionError::RequestRejected,
        _ => DecisionError::ProviderUnavailable,
    }
}

async fn read_bounded(
    mut response: reqwest::Response,
    limit: usize,
) -> Result<Vec<u8>, DecisionError> {
    let mut body = Vec::new();
    while let Some(chunk) = response
        .chunk()
        .await
        .map_err(|error| network_error(&error))?
    {
        if body.len() + chunk.len() > limit {
            return Err(DecisionError::InvalidResponse);
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

fn probability_map(value: Option<&Value>) -> BTreeMap<String, f64> {
    value
        .and_then(Value::as_object)
        .map(|map| {
            map.iter()
                .filter_map(|(key, value)| {
                    value
                        .as_f64()
                        .filter(|p| (0.0..=1.0).contains(p))
                        .map(|p| (key.clone(), p))
                })
                .collect()
        })
        .unwrap_or_default()
}

fn parse_answer(value: &Value) -> DecisionAnswer {
    match value.get("type").and_then(Value::as_str) {
        Some("choice") => match value.get("choice").and_then(Value::as_str) {
            Some(choice) => DecisionAnswer::Choice {
                choice: choice.to_owned(),
                probabilities: probability_map(value.get("probabilities")),
            },
            None => DecisionAnswer::Unknown,
        },
        Some("score") => match value.get("score").and_then(Value::as_f64) {
            Some(score) => DecisionAnswer::Score {
                score,
                probabilities: probability_map(value.get("probabilities")),
            },
            None => DecisionAnswer::Unknown,
        },
        Some("noul") => match value
            .get("noul")
            .and_then(Value::as_f64)
            .filter(|p| (0.0..=1.0).contains(p))
        {
            Some(probability) => DecisionAnswer::Noul { probability },
            None => DecisionAnswer::Unknown,
        },
        Some("refusal") => DecisionAnswer::Refusal,
        _ => DecisionAnswer::Unknown,
    }
}

pub(super) fn parse_response(body: &[u8]) -> Result<DecisionResponse, DecisionError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| DecisionError::InvalidResponse)?;
    let answers = value
        .get("answers")
        .and_then(Value::as_object)
        .ok_or(DecisionError::InvalidResponse)?;
    let usage = value.get("usage");
    Ok(DecisionResponse {
        model: value
            .get("model")
            .and_then(Value::as_str)
            .map(str::to_owned),
        answers: answers
            .iter()
            .map(|(key, answer)| (key.clone(), parse_answer(answer)))
            .collect(),
        cost_usd: usage
            .and_then(|usage| usage.get("cost"))
            .and_then(Value::as_f64),
        input_tokens: usage
            .and_then(|usage| usage.get("input_tokens"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
    })
}

#[derive(Serialize)]
struct WithModel<'a, B: Serialize> {
    model: &'a str,
    #[serde(flatten)]
    body: &'a B,
}

/// Sends one Decisions request. `body` serializes to `state` and `questions`; the configured
/// model is added here. Option order inside `body` is kept as the caller serialized it.
pub(crate) async fn decide<B: Serialize>(
    configuration: &DecisionConfiguration,
    body: &B,
) -> Result<DecisionResponse, DecisionError> {
    configuration.ready()?;
    let body = WithModel {
        model: &configuration.model,
        body,
    };
    let url = format!(
        "{}/alpha/decisions",
        configuration.endpoint.trim_end_matches('/')
    );
    let response = client()?
        .post(url)
        .header(AUTHORIZATION, format!("Bearer {}", configuration.api_key))
        .json(&body)
        .send()
        .await
        .map_err(|error| network_error(&error))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        // The provider's own message is the only explanation of a rejected request; keep a
        // bounded, escaped excerpt. It never contains the key, which is sent only as a header.
        let reason = read_bounded(response, 16 * 1024)
            .await
            .ok()
            .and_then(|body| serde_json::from_slice::<Value>(&body).ok())
            .and_then(|value| {
                value
                    .pointer("/error/message")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .map(|message| {
                message
                    .chars()
                    .take(300)
                    .flat_map(char::escape_debug)
                    .collect::<String>()
            })
            .unwrap_or_default();
        log::warn!(
            "decision_request_failed status={status} model={:?} reason=\"{reason}\"",
            configuration.model
        );
        return Err(status_error(status));
    }
    parse_response(&read_bounded(response, MAX_RESPONSE_BYTES).await?)
}

fn price_per_million(value: Option<&Value>) -> Option<f64> {
    let per_token = match value? {
        Value::String(text) => text.parse::<f64>().ok()?,
        Value::Number(number) => number.as_f64()?,
        _ => return None,
    };
    (per_token >= 0.0).then_some(per_token * 1_000_000.0)
}

pub(super) fn parse_catalog(body: &[u8]) -> Result<Vec<DecisionModel>, DecisionError> {
    let value: Value = serde_json::from_slice(body).map_err(|_| DecisionError::InvalidResponse)?;
    let entries = value
        .get("data")
        .and_then(Value::as_array)
        .ok_or(DecisionError::InvalidResponse)?;
    let mut models: Vec<DecisionModel> = entries
        .iter()
        .filter_map(|entry| {
            let id = entry.get("id").and_then(Value::as_str)?.to_owned();
            Some(DecisionModel {
                name: entry
                    .get("name")
                    .and_then(Value::as_str)
                    .unwrap_or(&id)
                    .to_owned(),
                context_length: entry.get("context_length").and_then(Value::as_u64),
                input_price_per_million: price_per_million(entry.pointer("/pricing/prompt")),
                id,
            })
        })
        .collect();
    models.sort_by_key(|model| model.name.to_lowercase());
    Ok(models)
}

/// Lists the decision models the endpoint serves. The catalog is public, so no key is needed.
pub async fn list_decision_models(
    endpoint: Option<String>,
) -> Result<Vec<DecisionModel>, DecisionError> {
    let endpoint = endpoint
        .map(|endpoint| endpoint.trim().trim_end_matches('/').to_owned())
        .filter(|endpoint| !endpoint.is_empty())
        .unwrap_or_else(|| super::configuration::DEFAULT_ENDPOINT.to_owned());
    let probe = DecisionConfiguration {
        schema_version: 1,
        endpoint: endpoint.clone(),
        api_key: String::new(),
        model: "catalog".into(),
    };
    probe.validate()?;
    let response = client()?
        .get(format!("{endpoint}/v1/models?output_modalities=decisions"))
        .send()
        .await
        .map_err(|error| network_error(&error))?;
    let status = response.status().as_u16();
    if !(200..300).contains(&status) {
        return Err(status_error(status));
    }
    parse_catalog(&read_bounded(response, MAX_CATALOG_BYTES).await?)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn responses_decode_each_answer_type_and_tolerate_new_ones() {
        let body = br#"{
            "id": "gen-1", "model": "vendor/decider-1", "provider": "Vendor",
            "answers": {
                "role": {"type": "choice", "choice": "leftover", "confidence": 0.8,
                         "probabilities": {"leftover": 0.8, "tool": 0.15, "desktop": 0.05}},
                "miss": {"type": "score", "score": 0.4, "confidence": 0.7,
                         "probabilities": {"0": 0.7, "1": 0.2, "2": 0.1}, "legend": {"0": "Nothing"}},
                "fits": {"type": "noul", "noul": 0.93},
                "denied": {"type": "refusal"},
                "future": {"type": "hologram", "hologram": 1}
            },
            "usage": {"input_tokens": 420, "output_tokens": 0, "cost": 0.0000176}
        }"#;
        let response = parse_response(body).expect("valid response");
        assert_eq!(response.model.as_deref(), Some("vendor/decider-1"));
        assert_eq!(response.input_tokens, 420);
        assert_eq!(response.cost_usd, Some(0.0000176));
        assert!(
            matches!(&response.answers["role"], DecisionAnswer::Choice { choice, probabilities } if choice == "leftover" && probabilities["tool"] == 0.15)
        );
        assert!(
            matches!(&response.answers["miss"], DecisionAnswer::Score { probabilities, .. } if probabilities.len() == 3)
        );
        assert_eq!(
            response.answers["fits"],
            DecisionAnswer::Noul { probability: 0.93 }
        );
        assert_eq!(response.answers["denied"], DecisionAnswer::Refusal);
        assert_eq!(response.answers["future"], DecisionAnswer::Unknown);
    }

    #[test]
    fn malformed_responses_are_rejected() {
        assert_eq!(
            parse_response(b"not json"),
            Err(DecisionError::InvalidResponse)
        );
        assert_eq!(
            parse_response(br#"{"id":"x"}"#),
            Err(DecisionError::InvalidResponse)
        );
        let out_of_range = br#"{"answers":{"a":{"type":"noul","noul":1.7}}}"#;
        assert_eq!(
            parse_response(out_of_range).unwrap().answers["a"],
            DecisionAnswer::Unknown
        );
    }

    #[test]
    fn http_statuses_map_to_stable_codes() {
        assert_eq!(status_error(401), DecisionError::Unauthorized);
        assert_eq!(status_error(402), DecisionError::InsufficientCredits);
        assert_eq!(status_error(429), DecisionError::RateLimited);
        assert_eq!(status_error(404), DecisionError::ModelUnavailable);
        assert_eq!(status_error(400), DecisionError::RequestRejected);
        assert_eq!(status_error(529), DecisionError::ProviderUnavailable);
    }

    #[test]
    fn the_catalog_lists_models_with_prices_per_million_tokens() {
        let body = br#"{"data":[
            {"id":"vendor/b","name":"Beta Decider","context_length":32768,"pricing":{"prompt":"0.000000042","completion":"0"}},
            {"id":"vendor/a","name":"Alpha Decider","pricing":{"prompt":0.0000001}},
            {"name":"no id"}
        ]}"#;
        let models = parse_catalog(body).expect("valid catalog");
        assert_eq!(
            models
                .iter()
                .map(|model| model.id.as_str())
                .collect::<Vec<_>>(),
            ["vendor/a", "vendor/b"]
        );
        assert!((models[1].input_price_per_million.unwrap() - 0.042).abs() < 1e-9);
        assert_eq!(models[1].context_length, Some(32768));
    }

    /// Answers one HTTP request with `status` and `body`, returning the raw request text.
    fn fake_server(status: u16, body: &'static str) -> (String, std::thread::JoinHandle<String>) {
        use std::io::{Read, Write};
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .unwrap();
            let mut request = Vec::new();
            loop {
                let mut chunk = [0u8; 8192];
                let length = stream.read(&mut chunk).unwrap();
                request.extend_from_slice(&chunk[..length]);
                let text = String::from_utf8_lossy(&request).into_owned();
                if let Some(end) = text.find("\r\n\r\n") {
                    let length: usize = text[..end]
                        .lines()
                        .find_map(|line| {
                            line.to_ascii_lowercase()
                                .strip_prefix("content-length:")
                                .map(|v| v.trim().parse().unwrap())
                        })
                        .unwrap_or(0);
                    if request.len() >= end + 4 + length {
                        break;
                    }
                }
                assert!(length > 0, "request ended early");
            }
            let reply = format!(
                "HTTP/1.1 {status} X\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            stream.write_all(reply.as_bytes()).unwrap();
            String::from_utf8_lossy(&request).into_owned()
        });
        (format!("http://{address}"), handle)
    }

    fn configuration(endpoint: String) -> DecisionConfiguration {
        DecisionConfiguration {
            schema_version: 1,
            endpoint,
            api_key: "sk-test".into(),
            model: "vendor/decider".into(),
        }
    }

    #[tokio::test]
    async fn requests_carry_the_key_and_model_and_decode_answers() {
        let (endpoint, server) = fake_server(
            200,
            r#"{"model":"vendor/decider-1","answers":{"a":{"type":"noul","noul":0.25}},"usage":{"input_tokens":12,"cost":0.000001}}"#,
        );
        let body = serde_json::json!({"state": {"name": "x"}, "questions": {}});
        let response = decide(&configuration(endpoint), &body)
            .await
            .expect("decided");
        assert_eq!(
            response.answers["a"],
            DecisionAnswer::Noul { probability: 0.25 }
        );
        assert_eq!(response.input_tokens, 12);
        let request = server.join().unwrap();
        assert!(request.starts_with("POST /alpha/decisions "), "{request}");
        assert!(request
            .to_ascii_lowercase()
            .contains("authorization: bearer sk-test"));
        assert!(request.contains(r#""model":"vendor/decider""#));
        assert!(request.contains(r#""state":{"name":"x"}"#));
    }

    #[tokio::test]
    async fn provider_failures_return_stable_codes() {
        let (endpoint, server) =
            fake_server(402, r#"{"error":{"message":"Insufficient credits"}}"#);
        let body = serde_json::json!({"state": {}, "questions": {}});
        assert_eq!(
            decide(&configuration(endpoint), &body).await,
            Err(DecisionError::InsufficientCredits)
        );
        server.join().unwrap();
    }
}
