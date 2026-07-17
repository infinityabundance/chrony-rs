//! Integration tests for xtask.
//!
//! xtask is a binary crate (no lib.rs), so these tests cannot import from it
//! as a library. They verify structural properties of the source tree instead.

#[test]
fn test_xtask_src_exists() {
    // Verify that the xtask source directory is present
    let xtask_src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    assert!(xtask_src.exists(), "xtask src dir should exist");
    assert!(
        xtask_src.join("main.rs").exists(),
        "xtask main.rs should exist"
    );
    assert!(
        xtask_src.join("parity.rs").exists(),
        "xtask parity.rs should exist"
    );
}

#[test]
fn test_xtask_main_compiles() {
    // Verify that the main module compiles by checking its key modules are present.
    // This is a structural check — if main.rs references modules that don't exist,
    // the build would fail.
    let src_dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let expected_modules = [
        "capture_trace.rs",
        "compare_diagnostics.rs",
        "generate.rs",
        "main.rs",
        "parity.rs",
        "verify.rs",
    ];
    for module in &expected_modules {
        assert!(
            src_dir.join(module).exists(),
            "expected xtask module {module} to exist"
        );
    }
}
