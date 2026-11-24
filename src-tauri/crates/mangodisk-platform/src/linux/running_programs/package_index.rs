//! What each installed distro package says it is, and how many installed packages need it.
//!
//! Both come straight from the package database: `/var/lib/dpkg/status` on Debian-family
//! systems and `/var/lib/pacman/local/*/desc` on Arch. A package counts as "needed" when another
//! installed package depends on it directly or through a virtual package it provides. Optional
//! relations (Recommends, Suggests, optdepends) are not counted, because removing their target
//! breaks nothing.

use std::{
    collections::{BTreeSet, HashMap},
    path::Path,
};

use super::proc_reader::read_text;

const DPKG_STATUS: &str = "/var/lib/dpkg/status";
const PACMAN_LOCAL: &str = "/var/lib/pacman/local";
const STATUS_BYTES: u64 = 128 * 1024 * 1024;
pub(super) const DESCRIPTION_CHARS: usize = 300;

#[derive(Debug, Default)]
pub(super) struct PackageIndex {
    descriptions: HashMap<String, String>,
    required_by: HashMap<String, u32>,
    /// dpkg `Essential: yes` or `Priority: required`: the system assumes these exist without
    /// declaring a dependency on them.
    essential: BTreeSet<String>,
}

impl PackageIndex {
    pub(super) fn description(&self, package: &str) -> Option<String> {
        self.descriptions
            .get(package)
            .filter(|text| !text.is_empty())
            .cloned()
    }

    pub(super) fn is_essential(&self, package: &str) -> bool {
        self.essential.contains(package)
    }

    /// `None` when the database could not be read, `Some(0)` when nothing needs the package.
    pub(super) fn required_by(&self, package: &str) -> Option<u32> {
        (!self.descriptions.is_empty()).then(|| self.required_by.get(package).copied().unwrap_or(0))
    }

    pub(super) fn load_dpkg() -> Self {
        read_text(Path::new(DPKG_STATUS), STATUS_BYTES)
            .map(|text| parse_dpkg_status(&text))
            .unwrap_or_default()
    }

    pub(super) fn load_pacman() -> Self {
        let Ok(entries) = std::fs::read_dir(PACMAN_LOCAL) else {
            return Self::default();
        };
        let records = entries
            .filter_map(Result::ok)
            .filter_map(|entry| read_text(&entry.path().join("desc"), 1024 * 1024))
            .filter_map(|text| parse_pacman_desc(&text));
        build_index(records)
    }
}

/// One installed package: name, description, what it needs, and virtual names it provides.
struct PackageRecord {
    name: String,
    essential: bool,
    description: Option<String>,
    needs: Vec<Vec<String>>,
    provides: Vec<String>,
}

/// One line, no control characters, bounded length.
pub(super) fn clean_description(text: &str) -> Option<String> {
    let line: String = text
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .chars()
        .filter(|ch| !ch.is_control())
        .take(DESCRIPTION_CHARS)
        .collect();
    (!line.is_empty()).then_some(line)
}

/// `name:arch (>= 1.2)` → `name`.
fn dependency_name(token: &str) -> Option<String> {
    let name = token.trim().split([' ', '(', '<', '>', '=']).next()?.trim();
    let name = name.split(':').next().unwrap_or(name);
    (!name.is_empty()).then(|| name.to_owned())
}

/// `a (>= 1), b | c` → `[[a], [b, c]]`; each inner list holds alternatives.
fn parse_dpkg_relations(value: &str) -> Vec<Vec<String>> {
    value
        .split(',')
        .map(|group| {
            group
                .split('|')
                .filter_map(dependency_name)
                .collect::<Vec<_>>()
        })
        .filter(|group| !group.is_empty())
        .collect()
}

fn dpkg_fields(stanza: &str) -> HashMap<&str, String> {
    let mut fields: HashMap<&str, String> = HashMap::new();
    let mut current: Option<&str> = None;
    for line in stanza.lines() {
        if line.starts_with([' ', '\t']) {
            // Continuation lines only matter for relation fields, which can wrap.
            if let Some(key) = current.filter(|key| *key != "Description") {
                if let Some(value) = fields.get_mut(key) {
                    value.push(' ');
                    value.push_str(line.trim());
                }
            }
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            fields.insert(key, value.trim().to_owned());
            current = Some(key);
        }
    }
    fields
}

fn parse_dpkg_status(text: &str) -> PackageIndex {
    let records = text.split("\n\n").filter_map(|stanza| {
        let fields = dpkg_fields(stanza);
        let installed = fields
            .get("Status")
            .is_some_and(|status| status.ends_with(" installed"));
        let name = fields.get("Package")?.clone();
        installed.then(|| {
            let mut needs = Vec::new();
            for key in ["Depends", "Pre-Depends"] {
                if let Some(value) = fields.get(key) {
                    needs.extend(parse_dpkg_relations(value));
                }
            }
            PackageRecord {
                essential: fields.get("Essential").is_some_and(|value| value == "yes")
                    || fields
                        .get("Priority")
                        .is_some_and(|value| value == "required"),
                name,
                description: fields
                    .get("Description")
                    .and_then(|value| clean_description(value)),
                needs,
                provides: fields
                    .get("Provides")
                    .map(|value| parse_dpkg_relations(value).into_iter().flatten().collect())
                    .unwrap_or_default(),
            }
        })
    });
    build_index(records)
}

fn parse_pacman_desc(text: &str) -> Option<PackageRecord> {
    let mut sections: HashMap<&str, Vec<&str>> = HashMap::new();
    let mut current: Option<&str> = None;
    for line in text.lines() {
        if line.starts_with('%') && line.ends_with('%') && line.len() > 2 {
            current = Some(line);
            continue;
        }
        if line.is_empty() {
            current = None;
            continue;
        }
        if let Some(section) = current {
            sections.entry(section).or_default().push(line);
        }
    }
    let name = sections.get("%NAME%")?.first()?.to_string();
    let list = |key: &str| -> Vec<String> {
        sections
            .get(key)
            .map(|lines| {
                lines
                    .iter()
                    .filter_map(|line| dependency_name(line))
                    .collect()
            })
            .unwrap_or_default()
    };
    Some(PackageRecord {
        name,
        essential: false,
        description: sections
            .get("%DESC%")
            .and_then(|lines| lines.first())
            .and_then(|line| clean_description(line)),
        needs: list("%DEPENDS%")
            .into_iter()
            .map(|name| vec![name])
            .collect(),
        provides: list("%PROVIDES%"),
    })
}

fn build_index(records: impl Iterator<Item = PackageRecord>) -> PackageIndex {
    let records: Vec<PackageRecord> = records.collect();
    let installed: BTreeSet<&str> = records.iter().map(|record| record.name.as_str()).collect();
    let mut providers: HashMap<&str, Vec<&str>> = HashMap::new();
    for record in &records {
        for virtual_name in &record.provides {
            providers
                .entry(virtual_name.as_str())
                .or_default()
                .push(record.name.as_str());
        }
    }
    let mut dependents: HashMap<&str, BTreeSet<&str>> = HashMap::new();
    for record in &records {
        for group in &record.needs {
            // Any installed alternative could be the one that satisfies the dependency, so all
            // of them count as needed. That overstates rather than understates what is needed.
            for target in group {
                let mut targets: Vec<&str> = Vec::new();
                if installed.contains(target.as_str()) {
                    targets.push(target.as_str());
                }
                if let Some(names) = providers.get(target.as_str()) {
                    targets.extend(names.iter().copied());
                }
                for target in targets.into_iter().filter(|target| *target != record.name) {
                    dependents
                        .entry(target)
                        .or_default()
                        .insert(record.name.as_str());
                }
            }
        }
    }
    let essential = records
        .iter()
        .filter(|record| record.essential)
        .map(|record| record.name.clone())
        .collect();
    PackageIndex {
        essential,
        required_by: dependents
            .into_iter()
            .map(|(name, users)| {
                (
                    name.to_owned(),
                    u32::try_from(users.len()).unwrap_or(u32::MAX),
                )
            })
            .collect(),
        descriptions: records
            .into_iter()
            .map(|record| {
                let description = record.description.unwrap_or_default();
                (record.name, description)
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const STATUS: &str = "Package: libfoo1
Status: install ok installed
Description: shared library for foo
 Long text that is not kept.

Package: foo-cli
Status: install ok installed
Depends: libfoo1 (>= 1.2), python3:any | python3-minimal
Description: command line foo tool

Package: mail-tool
Status: install ok installed
Depends: default-mta | mail-transport-agent
Description: sends mail

Package: postfix
Status: install ok installed
Provides: mail-transport-agent
Description: mail server

Package: python3
Status: install ok installed
Pre-Depends: python3-minimal
Description: interactive high-level language

Package: python3-minimal
Status: install ok installed
Priority: required
Description: minimal python

Package: bash
Essential: yes
Status: install ok installed
Description: GNU Bourne Again SHell

Package: removed-thing
Status: deinstall ok config-files
Description: gone
";

    #[test]
    fn dpkg_status_yields_descriptions_and_dependents() {
        let index = parse_dpkg_status(STATUS);
        assert_eq!(
            index.description("libfoo1").as_deref(),
            Some("shared library for foo")
        );
        assert_eq!(index.required_by("libfoo1"), Some(1));
        assert_eq!(
            index.required_by("python3-minimal"),
            Some(2),
            "both alternatives and pre-depends count"
        );
        assert_eq!(
            index.required_by("postfix"),
            Some(1),
            "virtual packages credit their providers"
        );
        assert_eq!(index.required_by("foo-cli"), Some(0));
        assert_eq!(
            index.description("removed-thing"),
            None,
            "packages not installed are ignored"
        );
        assert!(index.is_essential("bash"));
        assert!(index.is_essential("python3-minimal"));
        assert!(!index.is_essential("foo-cli"));
    }

    #[test]
    fn an_unreadable_database_reports_unknown_dependents() {
        assert_eq!(PackageIndex::default().required_by("anything"), None);
    }

    #[test]
    fn pacman_desc_files_are_parsed() {
        let desc = "%NAME%\nripgrep\n\n%DESC%\nA search tool\n\n%DEPENDS%\ngcc-libs\npcre2>=10\n\n%PROVIDES%\nrg\n";
        let record = parse_pacman_desc(desc).expect("valid desc");
        assert_eq!(record.name, "ripgrep");
        assert_eq!(record.description.as_deref(), Some("A search tool"));
        assert_eq!(
            record.needs,
            vec![vec!["gcc-libs".to_owned()], vec!["pcre2".to_owned()]]
        );
        assert_eq!(record.provides, vec!["rg".to_owned()]);
    }

    #[test]
    fn descriptions_are_one_bounded_line() {
        assert_eq!(
            clean_description("  two\n words\t"),
            Some("two words".to_owned())
        );
        assert_eq!(
            clean_description("x".repeat(400).as_str()).map(|text| text.len()),
            Some(DESCRIPTION_CHARS)
        );
        assert_eq!(clean_description("   "), None);
    }
}
