//! Build-time codegen for `FreeRADIUS` dictionary tables.
//!
//! ## What this does
//!
//! 1. **Discovers** vendor dictionaries by walking
//!    `dictionaries/vendor/dictionary.*` — each file `dictionary.<name>`
//!    defines a `dict-<name>` group with module name `<name>`.
//! 2. **Validates** that every discovered vendor has a matching
//!    `dict-<name>` feature declared in *both* the sub-crate
//!    `Cargo.toml` and the workspace-root `Cargo.toml` (the latter
//!    forwards feature flags). A missing entry fails the build with a
//!    pointer to the file(s) that need updating.
//! 3. **Renders** the typed Rust for each *enabled* group into
//!    `OUT_DIR/dict_<module>.rs`.
//! 4. **Emits** `OUT_DIR/vendor_mods.rs` containing one
//!    `#[cfg(feature = "dict-<name>")] pub mod <name> { … }` block
//!    per discovered vendor; `generated.rs` `include!`s it. This
//!    means **adding a new vendor only requires** dropping the
//!    dictionary file in place plus the two Cargo feature lines —
//!    no `build.rs` or `generated.rs` edits.
//!
//! Output is deterministic: the parser preserves source order, the
//! renderer is a pure function of the parsed dictionary, and we never
//! write anything time- or path-derived into the generated Rust.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};

use radius_tokio_dict_codegen::{FsLoader, Parser};

struct Group {
    /// Cargo feature name (without the `feature = "…"` envelope).
    feature: String,
    /// Module label embedded in the generated file header and used as
    /// the Rust module name under `radius_tokio_dict::`.
    module: String,
    /// Path (relative to `CARGO_MANIFEST_DIR`) of the dictionary
    /// entry-point that pulls in the rest via `$INCLUDE`.
    entry: PathBuf,
    /// One-line module-level rustdoc emitted into `vendor_mods.rs`.
    doc: String,
}

/// RFC group is special-cased: it lives outside `dictionaries/vendor/`
/// and its mod block is hand-written in `src/generated.rs` (so the
/// crate has a known-good module even with zero vendor features).
const RFC: &str = "dict-rfc";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"),
    );
    let out_dir: PathBuf = env::var_os("OUT_DIR")
        .expect("OUT_DIR is set by Cargo")
        .into();

    // ── 1. Discover groups ──────────────────────────────────────────
    let mut groups = Vec::<Group>::new();

    // RFC entry-point (hand-maintained alongside the vendor sweep).
    groups.push(Group {
        feature: RFC.to_string(),
        module: "rfc".to_string(),
        entry: manifest_dir.join("dictionaries/rfc/dictionary"),
        doc: "IETF / RFC attributes vendored under `dictionaries/rfc/`.".to_string(),
    });

    // Vendor entry-points: every `dictionary.<name>` under
    // `dictionaries/vendor/`. The bare `dictionary` umbrella file is
    // skipped (it `$INCLUDE`s the per-vendor files).
    let vendor_dir = manifest_dir.join("dictionaries").join("vendor");
    println!("cargo:rerun-if-changed={}", vendor_dir.display());
    let mut vendors: Vec<String> = fs::read_dir(&vendor_dir)
        .unwrap_or_else(|e| {
            panic!(
                "failed to read vendor dictionary directory `{}`: {e}",
                vendor_dir.display()
            )
        })
        .filter_map(|ent| {
            let ent = ent.ok()?;
            let name = ent.file_name().into_string().ok()?;
            let suffix = name.strip_prefix("dictionary.")?;
            (!suffix.is_empty()).then(|| suffix.to_string())
        })
        .collect();
    vendors.sort();

    for name in &vendors {
        // Vendor file names are lowercase ASCII in practice; the
        // module name is the file suffix verbatim and must therefore
        // be a valid Rust identifier. Validate up front so a future
        // misnamed file fails loudly instead of producing a cryptic
        // syntax error inside the generated source.
        assert!(
            is_valid_module_name(name),
            "vendor dictionary `dictionary.{name}` has a name that is not a valid Rust \
             identifier; rename the file to use `[a-z][a-z0-9_]*`",
        );
        groups.push(Group {
            feature: format!("dict-{name}"),
            module: name.clone(),
            entry: vendor_dir.join(format!("dictionary.{name}")),
            doc: format!(
                "Vendor `{name}` (auto-discovered from `dictionaries/vendor/dictionary.{name}`).",
            ),
        });
    }

    // ── 2. Validate Cargo.toml is in sync ───────────────────────────
    validate_feature_coverage(&manifest_dir, &vendors);

    // ── 3 + 4. Render enabled groups + emit vendor_mods.rs ──────────
    let parser = Parser::new(FsLoader);
    for g in &groups {
        if !cargo_feature_enabled(&g.feature) {
            continue;
        }
        rerun_for_dictionary_dir(&g.entry);

        let parsed = parser
            .parse(&g.entry)
            .unwrap_or_else(|e| panic!("failed to parse dictionary `{}`: {e}", g.entry.display()));
        let rendered = radius_tokio_dict_codegen::codegen::render(&g.module, &parsed);

        let dest = out_dir.join(format!("dict_{}.rs", g.module));
        write_if_changed(&dest, &rendered);
    }

    let mut vendor_mods = String::from(
        "// Auto-generated by `build.rs` from `dictionaries/vendor/dictionary.*`.\n\
         // Do not edit by hand — the file is overwritten on every build.\n\
         //\n\
         // Each block is cfg-gated by its `dict-<vendor>` feature, so a\n\
         // disabled vendor compiles away to nothing.\n\n",
    );
    for g in groups.iter().filter(|g| g.feature != RFC) {
        writeln!(
            vendor_mods,
            "#[cfg(feature = \"{feat}\")]\n\
             #[allow(missing_docs)]\n\
             pub mod {module} {{\n    \
                 //! {doc}\n    \
                 use super::{{AttrInfo, AttrKind, VendorInfo}};\n    \
                 include!(concat!(env!(\"OUT_DIR\"), \"/dict_{module}.rs\"));\n\
             }}\n",
            feat = g.feature,
            module = g.module,
            doc = g.doc,
        )
        .unwrap();
    }
    write_if_changed(&out_dir.join("vendor_mods.rs"), &vendor_mods);
}

/// True when Cargo set `CARGO_FEATURE_<UPPER_FEATURE>` (i.e. this
/// dictionary group is selected for this build).
fn cargo_feature_enabled(feature: &str) -> bool {
    let env_var = format!("CARGO_FEATURE_{}", feature.replace('-', "_").to_uppercase());
    env::var_os(env_var).is_some()
}

/// Names valid as Rust module identifiers and matching the existing
/// vendor-file convention: lowercase ASCII letters, digits, underscores;
/// must start with a letter.
fn is_valid_module_name(s: &str) -> bool {
    let mut chars = s.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    first.is_ascii_lowercase()
        && chars.all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_')
}

/// Watch every file in the directory containing `entry`. The dictionary
/// entry-point pulls siblings in via `$INCLUDE`; this catches edits to
/// any of them without us having to mirror the include graph here.
fn rerun_for_dictionary_dir(entry: &Path) {
    println!("cargo:rerun-if-changed={}", entry.display());
    let Some(dir) = entry.parent() else { return };
    let Ok(rd) = fs::read_dir(dir) else { return };
    for ent in rd.flatten() {
        println!("cargo:rerun-if-changed={}", ent.path().display());
    }
}

/// Avoid touching the file (and its mtime) when the contents are
/// unchanged. Keeps incremental rebuilds quiet.
fn write_if_changed(path: &Path, content: &str) {
    if let Ok(existing) = fs::read_to_string(path) {
        if existing == content {
            return;
        }
    }
    fs::write(path, content).expect("write generated dictionary file");
}

// ── Cargo.toml drift validation ─────────────────────────────────────

/// Fail the build if any auto-discovered vendor lacks a `dict-<name>`
/// feature in the sub-crate manifest **or** in the workspace-root
/// manifest (which forwards the flag to consumers).
fn validate_feature_coverage(manifest_dir: &Path, vendors: &[String]) {
    let pkg_manifest_path = manifest_dir.join("Cargo.toml");
    let root_manifest_path = manifest_dir.join("..").join("..").join("Cargo.toml");
    println!("cargo:rerun-if-changed={}", pkg_manifest_path.display());
    println!("cargo:rerun-if-changed={}", root_manifest_path.display());

    let pkg_manifest = fs::read_to_string(&pkg_manifest_path)
        .unwrap_or_else(|e| panic!("failed to read `{}`: {e}", pkg_manifest_path.display()));

    // The root-manifest drift check is an in-tree development guard:
    // it ensures every vendor dictionary on disk has a matching
    // `dict-<name>` forward in the workspace-root `Cargo.toml`. When
    // the crate is built standalone (e.g. inside `target/package/…`
    // during `cargo publish`, or after consumers fetch it from
    // crates.io) the workspace root is not present and there's
    // nothing to drift against — silently skip in that case rather
    // than failing the build.
    let Ok(root_manifest) = fs::read_to_string(&root_manifest_path) else {
        return;
    };

    let pkg_features = extract_features_section(&pkg_manifest);
    let root_features = extract_features_section(&root_manifest);

    let mut missing: Vec<String> = Vec::new();
    for v in vendors {
        let feat = format!("dict-{v}");
        let in_pkg = pkg_features.iter().any(|f| f == &feat);
        let in_root = root_features.iter().any(|f| f == &feat);
        if in_pkg && in_root {
            continue;
        }
        let mut line = format!("  • {feat}");
        if !in_pkg {
            line.push_str("  [missing in crates/radius-tokio-dict/Cargo.toml]");
        }
        if !in_root {
            line.push_str("  [missing in workspace-root Cargo.toml]");
        }
        missing.push(line);
    }

    if !missing.is_empty() {
        let mut msg = String::from(
            "\nvendor dictionaries on disk without matching `dict-*` Cargo features:\n",
        );
        for line in &missing {
            msg.push_str(line);
            msg.push('\n');
        }
        msg.push_str(
            "\nAdd the feature(s), mirroring an existing vendor. Both manifests must\n\
             declare each `dict-<vendor>` feature; the root one forwards it to\n\
             `radius-tokio-dict/dict-<vendor>` and appends it to the `dict-vendor-all`\n\
             umbrella.\n",
        );
        panic!("{msg}");
    }
}

/// Return every bare key name declared in the `[features]` table of a
/// `Cargo.toml` source string.
///
/// This is a deliberately small, dependency-free scanner sufficient
/// for the manifests we control. It honours TOML table boundaries
/// (`[some.section]`) but does **not** attempt to parse complex value
/// expressions — it only needs the key on the left of `=`.
fn extract_features_section(manifest: &str) -> Vec<String> {
    let mut keys = Vec::new();
    let mut in_features = false;
    for raw_line in manifest.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(rest) = line.strip_prefix('[') {
            // `[features]` (table) or `[[features]]` (array of tables —
            // not actually valid here, but match defensively).
            in_features = rest.trim_start_matches('[').starts_with("features]");
            continue;
        }
        if !in_features {
            continue;
        }
        let Some((key, _)) = line.split_once('=') else {
            continue;
        };
        // Strip optional surrounding quotes (TOML allows `"key" = …`).
        let key = key.trim().trim_matches('"');
        if !key.is_empty() {
            keys.push(key.to_string());
        }
    }
    keys
}

#[cfg(test)]
mod tests {
    use super::extract_features_section;

    #[test]
    fn extracts_keys_from_features_section_only() {
        let manifest = r#"
[package]
name = "x"

[features]
default = ["a"]
dict-rfc = []
dict-cisco = ["radius-tokio-dict/dict-cisco"]

[dependencies]
serde = "1"
"#;
        let keys = extract_features_section(manifest);
        assert!(keys.contains(&"dict-rfc".to_string()));
        assert!(keys.contains(&"dict-cisco".to_string()));
        assert!(keys.contains(&"default".to_string()));
        assert!(!keys.contains(&"serde".to_string()));
        assert!(!keys.contains(&"name".to_string()));
    }
}
