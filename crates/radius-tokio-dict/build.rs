//! Build-time codegen for `FreeRADIUS` dictionary tables.
//!
//! Each `dict-*` Cargo feature picks a dictionary entry-point under
//! `dictionaries/`, parses it using [`radius_tokio_dict_codegen`], and writes a
//! Rust source file into `OUT_DIR`. The library `include!`s those files
//! from `src/generated.rs`.
//!
//! Output is deterministic: the parser preserves source order, the
//! renderer is a pure function of the parsed dictionary, and we never
//! write anything time- or path-derived into the generated Rust.

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use radius_tokio_dict_codegen::{FsLoader, Parser};

struct Group {
    /// Cargo feature name (without the `feature = "…"` envelope).
    feature: &'static str,
    /// Module label embedded in the generated file header.
    module: &'static str,
    /// Path (relative to `CARGO_MANIFEST_DIR`) of the dictionary
    /// entry-point that pulls in the rest via `$INCLUDE`.
    entry: &'static str,
}

/// One row per `dict-*` feature. Order is irrelevant; each row is
/// independent.
const GROUPS: &[Group] = &[
    Group {
        feature: "dict-rfc",
        module: "rfc",
        entry: "dictionaries/rfc/dictionary",
    },
    Group {
        feature: "dict-cisco",
        module: "cisco",
        entry: "dictionaries/vendor/dictionary.cisco",
    },
    Group {
        feature: "dict-aruba",
        module: "aruba",
        entry: "dictionaries/vendor/dictionary.aruba",
    },
    Group {
        feature: "dict-ascend",
        module: "ascend",
        entry: "dictionaries/vendor/dictionary.ascend",
    },
    Group {
        feature: "dict-fortinet",
        module: "fortinet",
        entry: "dictionaries/vendor/dictionary.fortinet",
    },
    Group {
        feature: "dict-hp",
        module: "hp",
        entry: "dictionaries/vendor/dictionary.hp",
    },
    Group {
        feature: "dict-juniper",
        module: "juniper",
        entry: "dictionaries/vendor/dictionary.juniper",
    },
    Group {
        feature: "dict-meraki",
        module: "meraki",
        entry: "dictionaries/vendor/dictionary.meraki",
    },
    Group {
        feature: "dict-microsoft",
        module: "microsoft",
        entry: "dictionaries/vendor/dictionary.microsoft",
    },
    Group {
        feature: "dict-mikrotik",
        module: "mikrotik",
        entry: "dictionaries/vendor/dictionary.mikrotik",
    },
    Group {
        feature: "dict-ruckus",
        module: "ruckus",
        entry: "dictionaries/vendor/dictionary.ruckus",
    },
    Group {
        feature: "dict-wispr",
        module: "wispr",
        entry: "dictionaries/vendor/dictionary.wispr",
    },
    Group {
        feature: "dict-tplink",
        module: "tplink",
        entry: "dictionaries/vendor/dictionary.tplink",
    },
];

fn main() {
    println!("cargo:rerun-if-changed=build.rs");

    let manifest_dir = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").expect("CARGO_MANIFEST_DIR is set by Cargo"),
    );
    let out_dir: PathBuf = env::var_os("OUT_DIR")
        .expect("OUT_DIR is set by Cargo")
        .into();

    let parser = Parser::new(FsLoader);

    for group in GROUPS {
        let env_var = format!(
            "CARGO_FEATURE_{}",
            group.feature.replace('-', "_").to_uppercase()
        );
        if env::var_os(&env_var).is_none() {
            continue;
        }

        let entry = manifest_dir.join(group.entry);
        rerun_for_dictionary_dir(&entry);

        let parsed = parser
            .parse(&entry)
            .unwrap_or_else(|e| panic!("failed to parse dictionary `{}`: {e}", entry.display()));
        let rendered = radius_tokio_dict_codegen::codegen::render(group.module, &parsed);

        let dest = out_dir.join(format!("dict_{}.rs", group.module));
        write_if_changed(&dest, &rendered);
    }
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
