// Python bindings for hashsigs-rs. Scaffold only: the API surface (WOTS+,
// SHRINCS sign/verify) lands with the Python-bindings plan.
use pyo3::prelude::*;

#[pymodule]
fn hashsigs(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
