use {
    crate::types::VulnerablePackage,
    chrono::DateTime,
    ignore::Walk,
    indicatif::{ProgressBar, ProgressStyle},
    pyo3::prelude::*,
    rayon::prelude::*,
    regex::Regex,
    semver::Version,
    serde_json::json,
    std::{
        env, fs, path, process, str,
        sync::{Arc, Mutex},
        thread,
    },
    tempfile::tempdir,
    toml, ureq,
};

fn get_repo_name(url: &str) -> String {
    let url = url.trim_end_matches('/');
    let repo_name = url.split('/').last().unwrap();

    let repo_name = if repo_name.ends_with(".git") {
        &repo_name[..repo_name.len() - 4]
    } else {
        repo_name
    };

    repo_name.to_string()
}

/// Main function
#[pyfunction]
pub fn main(path: &str, is_dir: bool, is_url: bool) -> PyResult<Vec<VulnerablePackage>> {
    let vuln_pkgs: Vec<VulnerablePackage>;

    if is_url {
        let dir = tempdir()?;
        let repo_name = get_repo_name(path);

        env::set_current_dir(&dir)?;

        let cloning_done = Arc::new(Mutex::new(false));
        let cloning_done_clone = Arc::clone(&cloning_done);
        let path_clone = path.to_owned(); // Clone path to move into thread

        thread::spawn(move || {
            let _output = process::Command::new("git")
                .args(&["clone", &path_clone])
                .output()
                .expect("Failed to clone the repository");

            let mut done = cloning_done_clone.lock().unwrap();
            *done = true;
        });

        let pb = ProgressBar::new_spinner();
        pb.set_style(ProgressStyle::default_bar());
        pb.set_message("Cloning the repository...");

        while !*cloning_done.lock().unwrap() {
            pb.tick();
            thread::sleep(std::time::Duration::from_millis(100));
        }

        pb.finish_with_message("Repository cloned!");

        let repo_path = dir.path().join(&repo_name).to_str().unwrap().to_string();

        vuln_pkgs = evaluate_dir(&repo_path);

        dir.close()?;
    } else if is_dir {
        vuln_pkgs = evaluate_dir(path);
    } else {
        let parent_dir = path::Path::new(path).parent().unwrap().to_str().unwrap();

        if path.ends_with("requirements.txt") {
            vuln_pkgs = vulnerable_req_pkgs(path, parent_dir);
        } else {
            vuln_pkgs = vulnerable_lock_pkgs(path, parent_dir);
        }
    }

    Ok(vuln_pkgs)
}

fn evaluate_dir(path: &str) -> Vec<VulnerablePackage> {
    let mut pkgs_lock_paths: Vec<String> = Vec::new();
    let mut pkgs_req_paths: Vec<String> = Vec::new();

    let parent_dir = path::Path::new(path).parent().unwrap().to_str().unwrap();

    for entry in Walk::new(path) {
        let entry = entry.unwrap();
        let file_path_str = entry.path().to_str().unwrap();

        if entry.path().is_file() && file_path_str.ends_with("poetry.lock") {
            pkgs_lock_paths.push(file_path_str.to_string());
        }

        if entry.path().is_file() && file_path_str.ends_with("requirements.txt") {
            pkgs_req_paths.push(file_path_str.to_string());
        }
    }

    let pb = ProgressBar::new((pkgs_lock_paths.len() as u64) + (pkgs_req_paths.len() as u64));
    pb.set_style(
        indicatif::ProgressStyle::default_bar()
            .template(
                "{spiner:.green} [{elapsed_precise}] {bar:40.cyan/blue} {pos:>7}/{len:7} {msg}",
            )
            .unwrap()
            .progress_chars("##-"),
    );

    let vuln_lock_pkgs: Vec<Vec<VulnerablePackage>> = pkgs_lock_paths
        .par_iter()
        .map(|pkg_path| {
            pb.inc(1);
            vulnerable_lock_pkgs(&pkg_path, parent_dir)
        })
        .collect();

    let vuln_req_pkgs: Vec<Vec<VulnerablePackage>> = pkgs_req_paths
        .par_iter()
        .map(|pkg_path| {
            pb.inc(1);
            vulnerable_req_pkgs(&pkg_path, parent_dir)
        })
        .collect();

    pb.finish_with_message("Done!");

    vuln_lock_pkgs
        .into_iter()
        .flatten()
        .chain(vuln_req_pkgs.into_iter().flatten())
        .collect()
}

fn vulnerable_pkgs(
    pkgs_info: Vec<(String, String)>,
    path: &str,
    parent_dir: &str,
) -> Vec<VulnerablePackage> {
    let empty_json = json!({});
    let file_path = path::Path::new(path);
    let file_name = file_path.file_name().unwrap().to_str().unwrap();
    let absolute_path = file_path
        .strip_prefix(parent_dir)
        .unwrap()
        .to_str()
        .unwrap();

    let vuln_pkgs: Vec<VulnerablePackage> = pkgs_info
        .par_iter()
        .map(|(pkg_name, pkg_version)| {
            let json_str = format!(
                r#"{{"version": "{}", "package": {{ "name": "{}", "ecosystem": "PyPI", }} }}"#,
                pkg_version, pkg_name
            );

            let response = ureq::post("https://api.osv.dev/v1/query")
                .send_string(&json_str)
                .unwrap();

            let response_str = response.into_string().unwrap();

            let response_json: serde_json::Value =
                serde_json::from_str(response_str.as_str()).unwrap();

            (pkg_name, pkg_version, response_json)
        })
        .filter(|(_, _, response_json)| response_json.clone() != empty_json)
        .map(|(pkg_name, pkg_version, response_json)| {
            let mut vulns: Vec<serde_json::Value> = response_json
                .get("vulns")
                .unwrap()
                .as_array()
                .unwrap()
                .iter()
                .cloned()
                .collect();

            vulns.sort_by(|a, b| {
                let a_date = a.get("published").unwrap().as_str().unwrap();
                let b_date = b.get("published").unwrap().as_str().unwrap();

                let a_date = DateTime::parse_from_rfc3339(a_date).unwrap();
                let b_date = DateTime::parse_from_rfc3339(b_date).unwrap();

                a_date.cmp(&b_date)
            });

            let most_recent_vuln = vulns.last().unwrap();
            // From the most recent vuln, get the following information
            // - vuln_summary
            // - vuln_id
            // - vuln_aliases
            // - fixed_version, if exists
            // - cwe_ids
            // - published_date
            // - severity Vec<(String, String)> (Score, Type)

            let vuln_summary = if let Some(summary) = most_recent_vuln.get("summary") {
                summary.as_str().unwrap().to_string()
            } else {
                String::from("No summary available")
            };

            let vuln_id = most_recent_vuln.get("id").unwrap().as_str().unwrap();
            let vuln_aliases = if let Some(aliases) = most_recent_vuln.get("aliases") {
                aliases
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|alias| alias.as_str().unwrap().to_string())
                    .collect()
            } else {
                Vec::new()
            };

            let fixed_version = if let Some(affected) = most_recent_vuln.get("affected") {
                let affected = affected.as_array().unwrap();

                let mut fixed_versions: Vec<Version> = affected
                    .iter()
                    .map(|affected| {
                        affected
                            .get("ranges")
                            .unwrap()
                            .as_array()
                            .unwrap()
                            .iter()
                            .map(|range| {
                                range
                                    .get("events")
                                    .unwrap()
                                    .as_array()
                                    .unwrap()
                                    .iter()
                                    .filter(|event| event.get("fixed").is_some())
                            })
                            .into_iter()
                            .flatten()
                    })
                    .flatten()
                    .filter(|fixed| {
                        Version::parse(fixed.get("fixed").unwrap().as_str().unwrap()).is_ok()
                    })
                    .map(|fixed| {
                        Version::parse(fixed.get("fixed").unwrap().as_str().unwrap()).unwrap()
                    })
                    .collect();
                fixed_versions.sort();

                if fixed_versions.is_empty() {
                    String::from("No fixed version available")
                } else {
                    fixed_versions.last().unwrap().to_string()
                }
            } else {
                String::from("No fixed version available")
            };

            let cwe_ids = if let Some(db_specific) = most_recent_vuln.get("database_specific") {
                if let Some(cwe) = db_specific.get("cwe_ids") {
                    cwe.as_array()
                        .unwrap()
                        .iter()
                        .map(|cwe| cwe.as_str().unwrap().to_string())
                        .collect()
                } else {
                    Vec::new()
                }
            } else {
                Vec::new()
            };

            let published_date = most_recent_vuln.get("published").unwrap().as_str().unwrap();

            let severity: Vec<(String, String)> =
                if let Some(severity_info) = most_recent_vuln.get("severity") {
                    severity_info
                        .as_array()
                        .unwrap()
                        .iter()
                        .map(|severity| {
                            let score = severity.get("score").unwrap().as_str().unwrap();
                            let typ = severity.get("type").unwrap().as_str().unwrap();
                            (score.to_string(), typ.to_string())
                        })
                        .collect()
                } else {
                    Vec::new()
                };

            VulnerablePackage {
                path: absolute_path.to_string(),
                file_name: file_name.to_string(),
                pkg_name: pkg_name.to_string(),
                vuln_summary,
                vuln_version: pkg_version.to_string(),
                vuln_id: vuln_id.to_string(),
                vuln_aliases,
                fixed_version,
                cwe_ids,
                published_date: published_date.to_string(),
                severity,
            }
        })
        .collect();

    vuln_pkgs
}

fn vulnerable_lock_pkgs(path: &str, parent_dir: &str) -> Vec<VulnerablePackage> {
    let lock_content = fs::read_to_string(path).unwrap();
    let toml_content = lock_content.parse::<toml::Table>().unwrap();
    let packages = toml_content.get("package").unwrap().as_array().unwrap();

    let pkgs_info = packages
        .into_iter()
        .map(|pkg| {
            let pkg_name = pkg.get("name").unwrap().as_str().unwrap();
            let pkg_version = pkg.get("version").unwrap().as_str().unwrap();

            (pkg_name.to_string(), pkg_version.to_string())
        })
        .collect();

    vulnerable_pkgs(pkgs_info, path, parent_dir)
}

fn vulnerable_req_pkgs(path: &str, parent_dir: &str) -> Vec<VulnerablePackage> {
    let req_content = fs::read_to_string(path).unwrap();
    let re = Regex::new(r"^[a-zA-Z]+.*==.*$").unwrap();

    let pkgs_info = req_content
        .lines()
        .filter(|line| re.is_match(line))
        .map(|line| {
            let pkg_info: Vec<&str> = line.split("==").collect();
            let pkg_name = pkg_info[0];
            let pkg_version = pkg_info[1];

            (pkg_name.to_string(), pkg_version.to_string())
        })
        .collect();

    vulnerable_pkgs(pkgs_info, path, parent_dir)
}
