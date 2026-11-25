//! Decision models: hosted models that score a fixed set of answers instead of writing text.
//!
//! Core talks to an OpenRouter-compatible Decisions API (`POST {endpoint}/alpha/decisions`).
//! Callers build the questions; this module owns the provider configuration, the HTTP exchange
//! and a tolerant decoder, because the API is still marked alpha. Answers are untrusted
//! probabilities: they rank and label things for the user and never authorize an action.

mod client;
mod configuration;

use serde::Serialize;

pub(crate) use client::{decide, DecisionAnswer, DecisionResponse};
pub use client::{list_decision_models, DecisionModel};
pub use configuration::{DecisionConfiguration, DecisionConfigurationUpdate, DecisionSettings};

/// Stable failure codes; the frontend renders text from these, never from provider messages.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum DecisionError {
    NotConfigured,
    InvalidConfiguration,
    ConfigurationUnavailable,
    Busy,
    Cancelled,
    NothingToJudge,
    Unauthorized,
    InsufficientCredits,
    RateLimited,
    ModelUnavailable,
    ProviderUnavailable,
    ConnectionFailed,
    Timeout,
    InvalidResponse,
}

impl std::fmt::Display for DecisionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{self:?}")
    }
}

impl std::error::Error for DecisionError {}
