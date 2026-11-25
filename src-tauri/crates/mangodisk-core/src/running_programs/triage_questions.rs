//! The questions a decision model answers about each program.
//!
//! The built-in set asks for the program's role and how much stopping it would be noticed; the
//! page's labels, leftover filter and sort read those two answers. A user (or another tool
//! working for them) can replace the set with `triage-questions.json` in the data folder, or
//! pass a set for one run from the command line. Every set is validated before use, and the
//! questions travel only to the configured decision model.

use std::{
    fs,
    io::Read,
    path::{Path, PathBuf},
};

use serde::{ser::SerializeMap, Deserialize, Serialize, Serializer};
use serde_json::Value;

use crate::decisions::DecisionError;

const SCHEMA_VERSION: u8 = 1;
const FILE_NAME: &str = "triage-questions.json";
const MAX_DOCUMENT_BYTES: u64 = 64 * 1024;
const MAX_QUESTIONS: usize = 8;
const MAX_OPTIONS: usize = 32;
const MAX_LEVELS: usize = 10;
const MAX_TEXT_CHARS: usize = 600;
const MAX_ID_CHARS: usize = 40;

/// Question ids the page knows how to present as labels.
pub(super) const ROLE_QUESTION: &str = "role";
pub(super) const MISS_QUESTION: &str = "miss";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriageOption {
    pub id: String,
    pub criterion: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "camelCase")]
pub enum TriageQuestionKind {
    /// Pick one option. Options are sent in both orders to cancel first-option bias.
    Choice { options: Vec<TriageOption> },
    /// A position on an ordered scale; levels are listed lowest first.
    Score { levels: Vec<String> },
    /// The probability that the instructions' statement is true.
    Noul,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TriageQuestion {
    pub id: String,
    pub instructions: String,
    #[serde(flatten)]
    pub kind: TriageQuestionKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TriageQuestionSet {
    pub schema_version: u8,
    pub questions: Vec<TriageQuestion>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "camelCase")]
pub enum TriageQuestionSource {
    BuiltIn,
    /// `triage-questions.json` in the data folder.
    File,
    /// Passed for one run, from the command line.
    Supplied,
}

fn option(id: &str, criterion: &str) -> TriageOption {
    TriageOption {
        id: id.into(),
        criterion: criterion.into(),
    }
}

impl TriageQuestionSet {
    pub fn built_in() -> Self {
        Self {
            schema_version: SCHEMA_VERSION,
            questions: vec![
                TriageQuestion {
                    id: ROLE_QUESTION.into(),
                    instructions: "What is this program's role on this computer? Judge only from the facts given about the program.".into(),
                    kind: TriageQuestionKind::Choice {
                        options: vec![
                            option("desktop", "Part of the desktop environment or operating system that the login session or the computer itself needs"),
                            option("needed", "A service, helper or library that another program on this computer needs in order to work"),
                            option("tool", "An application, tool or service a person installed on purpose and still uses"),
                            option("leftover", "Installed for a past task, an experiment or by an install script, and not needed by anything in use now"),
                            option("unclear", "The facts given are not enough to tell which of the other answers fits"),
                        ],
                    },
                },
                TriageQuestion {
                    id: MISS_QUESTION.into(),
                    instructions: "If this program stopped and never started again, how much would the person who uses this computer notice?".into(),
                    kind: TriageQuestionKind::Score {
                        levels: vec![
                            "Nothing anyone uses would change".into(),
                            "A minor or rarely used feature would stop".into(),
                            "A feature in regular use would stop working".into(),
                            "Something used every day would break".into(),
                            "The desktop session or the system would stop working".into(),
                        ],
                    },
                },
            ],
        }
    }

    pub fn validate(&self) -> Result<(), DecisionError> {
        match self.problem() {
            None => Ok(()),
            Some(problem) => {
                log::warn!("triage_questions_invalid problem={problem:?}");
                Err(DecisionError::InvalidQuestions)
            }
        }
    }

    /// The first rule the set breaks, in English, for people and agents editing the file.
    pub fn problem(&self) -> Option<String> {
        let id_problem = |what: &str, id: &str| {
            let valid = !id.is_empty()
                && id.len() <= MAX_ID_CHARS
                && id
                    .chars()
                    .all(|ch| ch.is_ascii_lowercase() || ch.is_ascii_digit() || ch == '_');
            (!valid).then(|| {
                format!("{what} id {id:?} must be 1 to {MAX_ID_CHARS} characters of a-z, 0-9 or _")
            })
        };
        let text_problem = |what: &str, text: &str| {
            if text.trim().is_empty() {
                Some(format!("{what} is empty"))
            } else if text.chars().count() > MAX_TEXT_CHARS {
                Some(format!("{what} is longer than {MAX_TEXT_CHARS} characters"))
            } else if text.chars().any(char::is_control) {
                Some(format!(
                    "{what} contains a control character such as a line break"
                ))
            } else {
                None
            }
        };
        if self.schema_version != SCHEMA_VERSION {
            return Some(format!("schemaVersion must be {SCHEMA_VERSION}"));
        }
        if !(1..=MAX_QUESTIONS).contains(&self.questions.len()) {
            return Some(format!("there must be 1 to {MAX_QUESTIONS} questions"));
        }
        let mut ids = std::collections::BTreeSet::new();
        for question in &self.questions {
            let id = question.id.as_str();
            if let Some(problem) = id_problem("question", id) {
                return Some(problem);
            }
            if !ids.insert(id) {
                return Some(format!("question id {id:?} is used twice"));
            }
            if let Some(problem) = text_problem(
                &format!("the instructions of {id:?}"),
                &question.instructions,
            ) {
                return Some(problem);
            }
            match &question.kind {
                TriageQuestionKind::Choice { options } => {
                    if !(2..=MAX_OPTIONS).contains(&options.len()) {
                        return Some(format!(
                            "choice question {id:?} needs 2 to {MAX_OPTIONS} options"
                        ));
                    }
                    let mut option_ids = std::collections::BTreeSet::new();
                    for option in options {
                        if let Some(problem) =
                            id_problem(&format!("an option of {id:?} has an"), &option.id)
                        {
                            return Some(problem);
                        }
                        if !option_ids.insert(option.id.as_str()) {
                            return Some(format!("option {:?} of {id:?} is used twice", option.id));
                        }
                        if let Some(problem) = text_problem(
                            &format!("the criterion of option {:?} in {id:?}", option.id),
                            &option.criterion,
                        ) {
                            return Some(problem);
                        }
                    }
                }
                TriageQuestionKind::Score { levels } => {
                    if !(2..=MAX_LEVELS).contains(&levels.len()) {
                        return Some(format!(
                            "score question {id:?} needs 2 to {MAX_LEVELS} levels, lowest first"
                        ));
                    }
                    for (index, level) in levels.iter().enumerate() {
                        if let Some(problem) =
                            text_problem(&format!("level {index} of {id:?}"), level)
                        {
                            return Some(problem);
                        }
                    }
                }
                TriageQuestionKind::Noul => {}
            }
        }
        None
    }

    /// Reads a question document, explaining the first problem found.
    pub fn check(text: &str) -> Result<Self, String> {
        let set: Self = serde_json::from_str(text)
            .map_err(|error| format!("not a valid question document: {error}"))?;
        match set.problem() {
            Some(problem) => Err(problem),
            None => Ok(set),
        }
    }

    pub fn parse(text: &str) -> Result<Self, DecisionError> {
        Self::check(text).map_err(|problem| {
            // The problem names ids from the user's own file, never program facts.
            log::warn!("triage_questions_invalid problem={problem:?}");
            DecisionError::InvalidQuestions
        })
    }

    /// The questions in use: the user's file when present, otherwise the built-in set.
    pub fn active() -> Result<(Self, TriageQuestionSource), DecisionError> {
        let path = questions_path()?;
        match read_document(&path)? {
            Some(text) => Ok((Self::parse(&text)?, TriageQuestionSource::File)),
            None => Ok((Self::built_in(), TriageQuestionSource::BuiltIn)),
        }
    }

    /// Writes the built-in set as a starting point, keeping an existing file. Returns its path.
    pub fn write_template() -> Result<PathBuf, DecisionError> {
        let path = questions_path()?;
        if path.exists() {
            return Ok(path);
        }
        let directory = path
            .parent()
            .ok_or(DecisionError::ConfigurationUnavailable)?;
        fs::create_dir_all(directory).map_err(|_| DecisionError::ConfigurationUnavailable)?;
        let mut document = serde_json::to_string_pretty(&Self::built_in())
            .map_err(|_| DecisionError::InvalidQuestions)?;
        document.push('\n');
        fs::write(&path, document).map_err(|_| DecisionError::ConfigurationUnavailable)?;
        Ok(path)
    }
}

pub fn questions_path() -> Result<PathBuf, DecisionError> {
    crate::shared::application_paths()
        .map(|paths| paths.data_directory().join(FILE_NAME))
        .map_err(|_| DecisionError::ConfigurationUnavailable)
}

fn read_document(path: &Path) -> Result<Option<String>, DecisionError> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(DecisionError::ConfigurationUnavailable),
    };
    let mut text = String::new();
    file.take(MAX_DOCUMENT_BYTES + 1)
        .read_to_string(&mut text)
        .map_err(|_| DecisionError::InvalidQuestions)?;
    if text.len() as u64 > MAX_DOCUMENT_BYTES {
        return Err(DecisionError::InvalidQuestions);
    }
    Ok(Some(text))
}

/// Choice options in a fixed order. JSON objects in this crate serialize sorted by key, which
/// would undo the order reversal, so the map is written entry by entry.
struct OrderedCriteria<'a>(Vec<&'a TriageOption>);

impl Serialize for OrderedCriteria<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.0.len()))?;
        for option in &self.0 {
            map.serialize_entry(&option.id, &option.criterion)?;
        }
        map.end()
    }
}

/// One question on the wire, in the Decisions API's shape.
struct WireQuestion<'a> {
    question: &'a TriageQuestion,
    reversed: bool,
}

impl Serialize for WireQuestion<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(None)?;
        match &self.question.kind {
            TriageQuestionKind::Choice { options } => {
                map.serialize_entry("type", "choice")?;
                map.serialize_entry("instructions", &self.question.instructions)?;
                let mut ordered: Vec<&TriageOption> = options.iter().collect();
                if self.reversed {
                    ordered.reverse();
                }
                map.serialize_entry("criteria", &OrderedCriteria(ordered))?;
            }
            TriageQuestionKind::Score { levels } => {
                map.serialize_entry("type", "score")?;
                map.serialize_entry("instructions", &self.question.instructions)?;
                // Score levels must stay lowest first in both passes.
                map.serialize_entry("criteria", levels)?;
            }
            TriageQuestionKind::Noul => {
                map.serialize_entry("type", "noul")?;
                map.serialize_entry("instructions", &self.question.instructions)?;
            }
        }
        map.end()
    }
}

struct WireQuestions<'a> {
    set: &'a TriageQuestionSet,
    reversed: bool,
}

impl Serialize for WireQuestions<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(self.set.questions.len()))?;
        for question in &self.set.questions {
            map.serialize_entry(
                &question.id,
                &WireQuestion {
                    question,
                    reversed: self.reversed,
                },
            )?;
        }
        map.end()
    }
}

/// One Decisions request body: the program's facts and the questions in one option order.
pub(super) struct RequestBody<'a> {
    pub state: Value,
    pub set: &'a TriageQuestionSet,
    pub reversed: bool,
}

impl Serialize for RequestBody<'_> {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut map = serializer.serialize_map(Some(2))?;
        map.serialize_entry("state", &self.state)?;
        map.serialize_entry(
            "questions",
            &WireQuestions {
                set: self.set,
                reversed: self.reversed,
            },
        )?;
        map.end()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_built_in_set_is_valid_and_round_trips() {
        let set = TriageQuestionSet::built_in();
        assert_eq!(set.validate(), Ok(()));
        let text = serde_json::to_string_pretty(&set).unwrap();
        assert_eq!(TriageQuestionSet::parse(&text), Ok(set));
        assert!(text.contains("\"type\": \"choice\""));
    }

    #[test]
    fn user_sets_accept_every_question_type() {
        let text = r#"{"schemaVersion":1,"questions":[
            {"id":"category","type":"choice","instructions":"Which kind of software is it?",
             "options":[{"id":"dev_tool","criterion":"A developer tool"},{"id":"media","criterion":"Media software"}]},
            {"id":"age","type":"score","instructions":"How dated does it look?","levels":["Current","Old","Abandoned"]},
            {"id":"network","type":"noul","instructions":"This program listens for network connections"}
        ]}"#;
        let set = TriageQuestionSet::parse(text).expect("valid set");
        assert_eq!(set.questions.len(), 3);
        assert_eq!(set.questions[2].kind, TriageQuestionKind::Noul);
    }

    #[test]
    fn malformed_sets_are_rejected() {
        let cases = [
            r#"{"schemaVersion":2,"questions":[{"id":"a","type":"noul","instructions":"x"}]}"#,
            r#"{"schemaVersion":1,"questions":[]}"#,
            r#"{"schemaVersion":1,"questions":[{"id":"Bad Id","type":"noul","instructions":"x"}]}"#,
            r#"{"schemaVersion":1,"questions":[{"id":"a","type":"noul","instructions":"x"},{"id":"a","type":"noul","instructions":"y"}]}"#,
            r#"{"schemaVersion":1,"questions":[{"id":"a","type":"choice","instructions":"x","options":[{"id":"only","criterion":"one"}]}]}"#,
            r#"{"schemaVersion":1,"questions":[{"id":"a","type":"score","instructions":"x","levels":["one"]}]}"#,
            r#"{"schemaVersion":1,"questions":[{"id":"a","type":"essay","instructions":"x"}]}"#,
            r#"{"schemaVersion":1,"questions":[{"id":"a","type":"noul","instructions":""}]}"#,
            "not json",
        ];
        for case in cases {
            assert_eq!(
                TriageQuestionSet::parse(case),
                Err(DecisionError::InvalidQuestions),
                "{case}"
            );
        }
    }

    #[test]
    fn problems_name_the_broken_rule_and_the_question() {
        let problem = |text: &str| TriageQuestionSet::check(text).unwrap_err();
        assert!(problem(
            r#"{"schemaVersion":1,"questions":[{"id":"Bad Id","type":"noul","instructions":"x"}]}"#
        )
        .contains("\"Bad Id\" must be 1 to 40 characters"));
        assert!(problem(r#"{"schemaVersion":1,"questions":[{"id":"a","type":"choice","instructions":"x","options":[{"id":"o","criterion":"one"}]}]}"#)
            .contains("\"a\" needs 2 to 32 options"));
        assert!(problem(r#"{"schemaVersion":1,"questions":[{"id":"a","type":"score","instructions":"x","levels":["one","two\nlines"]}]}"#)
            .contains("level 1 of \"a\" contains a control character"));
        assert!(problem("{").starts_with("not a valid question document"));
        assert!(TriageQuestionSet::check(
            &serde_json::to_string(&TriageQuestionSet::built_in()).unwrap()
        )
        .is_ok());
    }

    #[test]
    fn requests_reverse_choice_options_but_not_score_levels() {
        let set = TriageQuestionSet::built_in();
        let text = |reversed: bool| {
            serde_json::to_string(&RequestBody {
                state: serde_json::json!({"name": "x"}),
                set: &set,
                reversed,
            })
            .unwrap()
        };
        let forward = text(false);
        let backward = text(true);
        let position = |text: &str, key: &str| text.find(&format!("\"{key}\":")).unwrap();
        assert!(position(&forward, "desktop") < position(&forward, "unclear"));
        assert!(position(&backward, "desktop") > position(&backward, "unclear"));
        for body in [&forward, &backward] {
            assert!(
                body.find("Nothing anyone uses").unwrap()
                    < body.find("The desktop session").unwrap()
            );
            assert!(body.starts_with(
                "{\"state\":{\"name\":\"x\"},\"questions\":{\"role\":{\"type\":\"choice\""
            ));
        }
    }
}
