// mod pypi_advisor;
mod advisory;
mod types;

use {advisory::main, pyo3::prelude::*, types::VulnerablePackage};

/// A Python module implemented in Rust.
#[pymodule]
#[pyo3(name = "py_watchdog")]
fn py_watchdog(_py: Python, m: &PyModule) -> PyResult<()> {
    m.add_class::<VulnerablePackage>()?;
    m.add_function(wrap_pyfunction!(main, m)?)?;
    Ok(())
}
