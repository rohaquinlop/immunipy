use pyo3::prelude::*;

#[derive(Clone)]
#[pyclass(module = "immunipy", get_all)]
pub struct VulnerablePackage {
    pub path: String,
    pub file_name: String,
    pub pkg_name: String,
    pub vuln_summary: String,
    pub vuln_version: String,
    pub vuln_id: String,
    pub vuln_aliases: Vec<String>,
    pub fixed_version: String,
    pub cwe_ids: Vec<String>,
    pub published_date: String,
    pub severity: Vec<(String, String)>, // (Score, Type)
}
