//! Maps files and top-level modules in Python `site-packages` folders to the distribution that
//! installed them, from each distribution's `RECORD`, `top_level.txt` and `direct_url.json`.

use std::{
    collections::HashMap,
    fs,
    path::{Path, PathBuf},
};

use super::{file_facts::modified_ms, proc_reader::read_text};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct PythonDistribution {
    pub name: String,
    pub version: Option<String>,
    pub installer: Option<String>,
    pub site: PathBuf,
    pub installed_at_ms: Option<u64>,
    pub source_url: Option<String>,
    pub editable_dir: Option<PathBuf>,
}

#[derive(Default)]
struct SiteIndex {
    files: HashMap<PathBuf, usize>,
    modules: HashMap<String, usize>,
    distributions: Vec<PythonDistribution>,
}

#[derive(Default)]
pub(super) struct PythonPackages {
    sites: HashMap<PathBuf, SiteIndex>,
}

fn metadata_headers(text: &str) -> HashMap<String, String> {
    let mut headers = HashMap::new();
    for line in text.lines() {
        if line.trim().is_empty() {
            break;
        }
        if line.starts_with([' ', '\t']) {
            continue;
        }
        if let Some((key, value)) = line.split_once(':') {
            headers
                .entry(key.trim().to_ascii_lowercase())
                .or_insert_with(|| value.trim().to_owned());
        }
    }
    headers
}

/// The first field of a `RECORD` CSV row, which may be quoted.
pub(super) fn record_path(row: &str) -> Option<String> {
    if let Some(rest) = row.strip_prefix('"') {
        let mut out = String::new();
        let mut chars = rest.chars().peekable();
        while let Some(ch) = chars.next() {
            if ch == '"' {
                if chars.peek() == Some(&'"') {
                    out.push('"');
                    chars.next();
                } else {
                    return Some(out);
                }
            } else {
                out.push(ch);
            }
        }
        None
    } else {
        let field = row.split(',').next()?;
        (!field.is_empty()).then(|| field.to_owned())
    }
}

fn lexical_join(base: &Path, relative: &str) -> PathBuf {
    let mut out = base.to_path_buf();
    for part in relative.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                out.pop();
            }
            other => out.push(other),
        }
    }
    out
}

fn read_distribution(site: &Path, info_dir: &Path, metadata_name: &str) -> PythonDistribution {
    let headers =
        metadata_headers(&read_text(&info_dir.join(metadata_name), 64 * 1024).unwrap_or_default());
    let stem = info_dir
        .file_stem()
        .map(|stem| stem.to_string_lossy().into_owned())
        .unwrap_or_default();
    let mut stem_parts = stem.splitn(2, '-');
    let stem_name = stem_parts.next().unwrap_or("").to_owned();
    let stem_version = stem_parts.next().map(str::to_owned);
    let installer = read_text(&info_dir.join("INSTALLER"), 1024)
        .map(|text| text.trim().to_owned())
        .filter(|text| !text.is_empty());
    let mut distribution = PythonDistribution {
        name: headers.get("name").cloned().unwrap_or(stem_name),
        version: headers.get("version").cloned().or(stem_version),
        installer,
        site: site.to_path_buf(),
        installed_at_ms: modified_ms(&info_dir.join("RECORD")).or_else(|| modified_ms(info_dir)),
        source_url: None,
        editable_dir: None,
    };
    let direct: Option<serde_json::Value> = read_text(&info_dir.join("direct_url.json"), 64 * 1024)
        .and_then(|text| serde_json::from_str(&text).ok());
    if let Some(url) = direct
        .as_ref()
        .and_then(|value| value.get("url"))
        .and_then(|url| url.as_str())
    {
        let editable = direct
            .as_ref()
            .and_then(|value| value.pointer("/dir_info/editable"))
            .and_then(serde_json::Value::as_bool)
            .unwrap_or(false);
        match url.strip_prefix("file://") {
            Some(folder) if editable => distribution.editable_dir = Some(PathBuf::from(folder)),
            _ => {
                let commit = direct
                    .as_ref()
                    .and_then(|value| value.pointer("/vcs_info/commit_id"))
                    .and_then(|commit| commit.as_str());
                distribution.source_url = Some(match commit {
                    Some(commit) => format!("{url} @ {}", &commit[..commit.len().min(10)]),
                    None => url.to_owned(),
                });
            }
        }
    }
    distribution
}

fn load_site(site: &Path) -> SiteIndex {
    let mut index = SiteIndex::default();
    let Ok(entries) = fs::read_dir(site) else {
        return index;
    };
    for entry in entries.filter_map(Result::ok) {
        let info_dir = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();
        let id = index.distributions.len();
        if name.ends_with(".dist-info") {
            index
                .distributions
                .push(read_distribution(site, &info_dir, "METADATA"));
            let record = read_text(&info_dir.join("RECORD"), 16 * 1024 * 1024).unwrap_or_default();
            for relative in record.lines().filter_map(record_path) {
                index.files.insert(lexical_join(site, &relative), id);
                let top = relative.split('/').next().unwrap_or("");
                if !top.starts_with("..")
                    && !top.ends_with(".dist-info")
                    && !top.ends_with(".pth")
                    && top != "__pycache__"
                {
                    let module = top.strip_suffix(".py").unwrap_or(top);
                    index.modules.entry(module.to_owned()).or_insert(id);
                }
            }
        } else if name.ends_with(".egg-info") && info_dir.is_dir() {
            index
                .distributions
                .push(read_distribution(site, &info_dir, "PKG-INFO"));
            let files = read_text(&info_dir.join("installed-files.txt"), 4 * 1024 * 1024)
                .unwrap_or_default();
            for relative in files.lines() {
                index.files.insert(lexical_join(&info_dir, relative), id);
            }
        } else {
            continue;
        }
        let top_level = read_text(&info_dir.join("top_level.txt"), 64 * 1024).unwrap_or_default();
        for module in top_level.split_whitespace() {
            index.modules.insert(module.to_owned(), id);
        }
    }
    index
}

/// `site-packages` folders containing `path`, or belonging to the environment of an interpreter.
pub(super) fn sites_near(path: Option<&Path>, interpreters: &[PathBuf]) -> Vec<PathBuf> {
    let mut sites = Vec::new();
    if let Some(path) = path {
        let mut prefix = PathBuf::new();
        for part in path.iter() {
            prefix.push(part);
            if part == "site-packages" || part == "dist-packages" {
                sites.push(prefix.clone());
            }
        }
    }
    let bins = path
        .and_then(Path::parent)
        .into_iter()
        .chain(interpreters.iter().filter_map(|path| path.parent()));
    for bin in bins {
        if bin.file_name().is_none_or(|name| name != "bin") {
            continue;
        }
        let Some(root) = bin.parent() else {
            continue;
        };
        for lib in ["lib", "lib64"] {
            let Ok(entries) = fs::read_dir(root.join(lib)) else {
                continue;
            };
            let mut found: Vec<PathBuf> = entries
                .filter_map(Result::ok)
                .filter(|entry| entry.file_name().to_string_lossy().starts_with("python"))
                .flat_map(|entry| {
                    [
                        entry.path().join("site-packages"),
                        entry.path().join("dist-packages"),
                    ]
                })
                .collect();
            found.sort();
            sites.extend(found);
        }
    }
    let mut unique: Vec<PathBuf> = Vec::new();
    for site in sites {
        if site.is_dir() && !unique.contains(&site) {
            unique.push(site);
        }
    }
    unique
}

/// `~/.local/lib/python*/site-packages` for `pip install --user`.
pub(super) fn user_sites(home: Option<&Path>) -> Vec<PathBuf> {
    let Some(lib) = home.map(|home| home.join(".local/lib")) else {
        return Vec::new();
    };
    let Ok(entries) = fs::read_dir(lib) else {
        return Vec::new();
    };
    let mut sites: Vec<PathBuf> = entries
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("python"))
        .map(|entry| entry.path().join("site-packages"))
        .filter(|site| site.is_dir())
        .collect();
    sites.sort();
    sites
}

impl PythonPackages {
    fn site(&mut self, site: &Path) -> &SiteIndex {
        self.sites
            .entry(site.to_path_buf())
            .or_insert_with(|| load_site(site))
    }

    pub(super) fn look_up(
        &mut self,
        path: Option<&Path>,
        module: Option<&str>,
        interpreters: &[PathBuf],
        user_sites: &[PathBuf],
    ) -> Option<PythonDistribution> {
        let sites = sites_near(path, interpreters);
        if let Some(path) = path {
            for site in &sites {
                let index = self.site(site);
                if let Some(id) = index.files.get(path) {
                    return Some(index.distributions[*id].clone());
                }
                if let Ok(relative) = path.strip_prefix(site) {
                    let top = relative
                        .iter()
                        .next()
                        .map(|part| part.to_string_lossy().into_owned())
                        .unwrap_or_default();
                    let top = top.strip_suffix(".py").unwrap_or(&top);
                    if let Some(id) = index.modules.get(top) {
                        return Some(index.distributions[*id].clone());
                    }
                }
            }
        }
        let top = module?.split('.').next()?;
        let extra = user_sites
            .iter()
            .filter(|site| !sites.contains(site))
            .cloned();
        for site in sites.clone().into_iter().chain(extra) {
            let index = self.site(&site);
            if let Some(id) = index.modules.get(top) {
                return Some(index.distributions[*id].clone());
            }
        }
        None
    }
}

/// `<root>/lib/pythonX.Y/site-packages` → `<root>`.
pub(super) fn environment_root(site: &Path) -> PathBuf {
    site.ancestors()
        .nth(3)
        .map(Path::to_path_buf)
        .unwrap_or_else(|| site.to_path_buf())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn record_rows_handle_quoting() {
        assert_eq!(
            record_path("pkg/__init__.py,sha256=abc,12").as_deref(),
            Some("pkg/__init__.py")
        );
        assert_eq!(
            record_path("\"odd,name.py\",sha256=abc,1").as_deref(),
            Some("odd,name.py")
        );
        assert_eq!(
            record_path("\"say \"\"hi\"\".py\",,").as_deref(),
            Some("say \"hi\".py")
        );
        assert_eq!(record_path(""), None);
    }

    #[test]
    fn metadata_headers_stop_at_the_body() {
        let headers = metadata_headers(
            "Metadata-Version: 2.1\nName: httpie\nVersion: 3.2\n\nName: not-a-header\n",
        );
        assert_eq!(headers["name"], "httpie");
        assert_eq!(headers["version"], "3.2");
    }

    #[test]
    fn environment_root_is_three_levels_up() {
        assert_eq!(
            environment_root(Path::new(
                "/home/a/.local/share/pipx/venvs/x/lib/python3.12/site-packages"
            )),
            PathBuf::from("/home/a/.local/share/pipx/venvs/x")
        );
    }

    #[test]
    fn a_site_maps_files_and_modules_to_their_distribution() {
        let root = std::env::temp_dir().join(format!("md-python-site-{}", std::process::id()));
        let site = root.join("lib/python3.12/site-packages");
        let info = site.join("demo_tool-1.2.dist-info");
        fs::create_dir_all(&info).unwrap();
        fs::write(info.join("METADATA"), "Name: demo-tool\nVersion: 1.2\n").unwrap();
        fs::write(info.join("INSTALLER"), "pip\n").unwrap();
        fs::write(
            info.join("RECORD"),
            "demo_tool/__init__.py,,\n../../../bin/demo,,\n",
        )
        .unwrap();
        fs::write(info.join("direct_url.json"), r#"{"url":"https://example.test/demo.git","vcs_info":{"vcs":"git","commit_id":"0123456789abcdef"}}"#).unwrap();
        let mut packages = PythonPackages::default();
        let found = packages
            .look_up(Some(&root.join("bin/demo")), None, &[], &[])
            .expect("script is in RECORD");
        assert_eq!(found.name, "demo-tool");
        assert_eq!(found.version.as_deref(), Some("1.2"));
        assert_eq!(
            found.source_url.as_deref(),
            Some("https://example.test/demo.git @ 0123456789")
        );
        let by_module = packages
            .look_up(
                None,
                Some("demo_tool.cli"),
                &[root.join("bin/python3")],
                &[],
            )
            .expect("module lookup");
        assert_eq!(by_module.name, "demo-tool");
        fs::remove_dir_all(root).unwrap();
    }
}
