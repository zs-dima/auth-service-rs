//! Generate `OpenAPI` 3.1 spec from proto definitions.
//!
//! Pipeline: buf lint → buf generate (gnostic 3.0.3) → patch to 3.1
//!
//! This replaces shell scripts with cross-platform Rust code.
//! No bash, no yq — runs identically on Windows, macOS, and Linux.

use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, bail};
use serde_yaml_ng::Value;

/// Output path for the generated spec (relative to workspace root).
const SPEC_PATH: &str = "api/openapi/v1/openapi.yaml";

/// buf.gen.yaml path (relative to workspace root).
const BUF_GEN_PATH: &str = "buf.gen.yaml";

pub fn run() -> anyhow::Result<()> {
    let root = workspace_root()?;

    // 1. Read version from Cargo.toml
    let version = cargo_version(&root)?;
    println!("Version: {version}");

    // 2. Inject version into buf.gen.yaml (restored after generation)
    let buf_gen_path = root.join(BUF_GEN_PATH);
    let original_buf_gen =
        fs::read_to_string(&buf_gen_path).context("Failed to read buf.gen.yaml")?;
    inject_version(&root, &version)?;

    // 3. buf lint
    println!("Linting proto files...");
    let lint_result = run_cmd(&root, "buf", &["lint"]);

    // 4. buf generate (only if lint passed)
    let gen_result = lint_result.and_then(|()| {
        println!("Generating OpenAPI spec...");
        run_cmd(&root, "buf", &["generate"])
    });

    // 5. Restore buf.gen.yaml to avoid dirtying the working tree
    fs::write(&buf_gen_path, &original_buf_gen).context("Failed to restore buf.gen.yaml")?;

    // Propagate any error from lint/generate
    gen_result?;

    // 6. Patch generated YAML: 3.0.3 → 3.1.0 + SSE annotations
    let spec_path = root.join(SPEC_PATH);
    println!("Patching {SPEC_PATH}...");
    patch_spec(&spec_path)?;

    println!("OpenAPI 3.1 spec ready: {SPEC_PATH}");
    Ok(())
}

// ---------------------------------------------------------------------------
// Steps
// ---------------------------------------------------------------------------

/// Read `version` from the workspace Cargo.toml.
fn cargo_version(root: &Path) -> anyhow::Result<String> {
    let cargo_toml =
        fs::read_to_string(root.join("Cargo.toml")).context("Failed to read Cargo.toml")?;

    let doc: toml::Table = toml::from_str(&cargo_toml).context("Failed to parse Cargo.toml")?;

    // Try [package].version first, then [workspace.package].version
    if let Some(v) = doc
        .get("package")
        .and_then(|p| p.get("version"))
        .and_then(toml::Value::as_str)
    {
        return Ok(v.to_string());
    }

    if let Some(v) = doc
        .get("workspace")
        .and_then(|w| w.get("package"))
        .and_then(|p| p.get("version"))
        .and_then(toml::Value::as_str)
    {
        return Ok(v.to_string());
    }

    bail!("No version found in Cargo.toml [package] or [workspace.package]");
}

/// Replace the `version=...` option in buf.gen.yaml with the current version.
///
/// Parses the YAML structure and navigates to `plugins[*].opt` entries,
/// replacing any `version=...` value. This is robust against formatting
/// changes unlike the previous line-by-line string matching approach.
fn inject_version(root: &Path, version: &str) -> anyhow::Result<()> {
    let path = root.join(BUF_GEN_PATH);
    let content = fs::read_to_string(&path).context("Failed to read buf.gen.yaml")?;

    let mut doc: Value =
        serde_yaml_ng::from_str(&content).context("Failed to parse buf.gen.yaml")?;

    let plugins = doc
        .as_mapping_mut()
        .and_then(|m| m.get_mut(Value::String("plugins".to_string())))
        .and_then(Value::as_sequence_mut)
        .context("buf.gen.yaml: missing 'plugins' array")?;

    let mut replaced = false;
    for plugin in plugins {
        let Some(opts) = plugin
            .as_mapping_mut()
            .and_then(|m| m.get_mut(Value::String("opt".to_string())))
            .and_then(Value::as_sequence_mut)
        else {
            continue;
        };

        for opt in opts.iter_mut() {
            if opt.as_str().is_some_and(|s| s.starts_with("version=")) {
                *opt = Value::String(format!("version={version}"));
                replaced = true;
            }
        }
    }

    if !replaced {
        bail!("No `version=` option found in buf.gen.yaml plugins");
    }

    let output = serde_yaml_ng::to_string(&doc).context("Failed to serialize buf.gen.yaml")?;
    fs::write(&path, output).context("Failed to write buf.gen.yaml")?;
    Ok(())
}

/// Patch the generated `OpenAPI` spec:
/// - Bump version to 3.1.0
/// - Convert `nullable: true` → type arrays (JSON Schema 2020-12)
/// - Remove `nullable: false` no-ops
/// - Annotate SSE streaming endpoints
fn patch_spec(path: &Path) -> anyhow::Result<()> {
    let content =
        fs::read_to_string(path).with_context(|| format!("Failed to read {}", path.display()))?;

    let mut doc: Value =
        serde_yaml_ng::from_str(&content).context("Failed to parse OpenAPI YAML")?;

    // 3.0.3 → 3.1.0
    upgrade_to_3_1(&mut doc);

    // Convert nullable fields (3.0 → 3.1 structural change)
    convert_nullable(&mut doc);

    // Annotate SSE streaming endpoints (auto-detected from response schemas)
    annotate_sse(&mut doc);

    // Fix redirect endpoints: gnostic maps all RPCs to 200, but /verify-email is 302
    patch_redirect_endpoints(&mut doc);

    let output = serde_yaml_ng::to_string(&doc).context("Failed to serialize OpenAPI YAML")?;

    fs::write(path, output).with_context(|| format!("Failed to write {}", path.display()))?;

    Ok(())
}

// ---------------------------------------------------------------------------
// OpenAPI 3.0 → 3.1 transforms
// ---------------------------------------------------------------------------

/// Set `openapi: "3.1.0"`.
fn upgrade_to_3_1(doc: &mut Value) {
    if let Value::Mapping(map) = doc {
        map.insert(
            Value::String("openapi".to_string()),
            Value::String("3.1.0".to_string()),
        );
    }
}

/// Convert `nullable: true` → `type: [original, "null"]` (JSON Schema 2020-12).
/// Remove `nullable: false` (no-op in 3.1).
fn convert_nullable(value: &mut Value) {
    match value {
        Value::Mapping(map) => {
            let nullable_key = Value::String("nullable".to_string());
            let type_key = Value::String("type".to_string());

            let is_nullable = map
                .get(&nullable_key)
                .is_some_and(|v| *v == Value::Bool(true));

            if map.contains_key(&nullable_key) {
                if is_nullable && let Some(type_val) = map.get(&type_key).cloned() {
                    map.insert(
                        type_key,
                        Value::Sequence(vec![type_val, Value::String("null".to_string())]),
                    );
                }
                map.remove(&nullable_key);
            }

            for (_, v) in map.iter_mut() {
                convert_nullable(v);
            }
        }
        Value::Sequence(seq) => {
            for item in seq.iter_mut() {
                convert_nullable(item);
            }
        }
        _ => {}
    }
}

/// Add `x-streaming: sse` and `x-content-type: text/event-stream` to
/// operations whose response schema reference contains "stream" (case-insensitive).
///
/// gnostic wraps server-streaming RPC responses in schemas named like
/// `Stream_<Package>_<Message>`, so we detect those automatically — no
/// hardcoded path list needed.
fn annotate_sse(doc: &mut Value) {
    let paths_key = Value::String("paths".to_string());

    let Some(paths) = doc
        .as_mapping_mut()
        .and_then(|m| m.get_mut(&paths_key))
        .and_then(Value::as_mapping_mut)
    else {
        return;
    };

    for (_path_key, path_item) in paths.iter_mut() {
        let Some(path_map) = path_item.as_mapping_mut() else {
            continue;
        };

        // Check all HTTP methods (GET, POST, etc.)
        for (_method, operation) in path_map.iter_mut() {
            let Some(op_map) = operation.as_mapping_mut() else {
                continue;
            };

            if !is_streaming_operation(op_map) {
                continue;
            }

            op_map.insert(
                Value::String("x-streaming".to_string()),
                Value::String("sse".to_string()),
            );
            op_map.insert(
                Value::String("x-content-type".to_string()),
                Value::String("text/event-stream".to_string()),
            );

            // Prepend streaming notice to description
            let desc_key = Value::String("description".to_string());
            let existing = op_map
                .get(&desc_key)
                .and_then(Value::as_str)
                .unwrap_or("Server-sent events stream.")
                .to_string();

            if !existing.starts_with("**Streaming (SSE):**") {
                op_map.insert(
                    desc_key,
                    Value::String(format!("**Streaming (SSE):** {existing}")),
                );
            }
        }
    }
}

/// Check whether an operation's response schema references a streaming type.
///
/// gnostic names streaming response schemas `Stream_<package>_<Message>`.
/// We look for `$ref` values containing "stream" (case-insensitive) in
/// the `200` response schema.
fn is_streaming_operation(op: &serde_yaml_ng::Mapping) -> bool {
    let responses = op
        .get(Value::String("responses".to_string()))
        .and_then(Value::as_mapping);

    let Some(responses) = responses else {
        return false;
    };

    // Check 200 response (gnostic maps streaming RPCs to 200)
    let ok_response = responses
        .get(Value::String("200".to_string()))
        .and_then(Value::as_mapping);

    let Some(ok_resp) = ok_response else {
        return false;
    };

    // OpenAPI 3.x: responses.200.content.application/json.schema.$ref
    if let Some(schema_ref) = ok_resp
        .get(Value::String("content".to_string()))
        .and_then(Value::as_mapping)
        .and_then(|c| c.get(Value::String("application/json".to_string())))
        .and_then(Value::as_mapping)
        .and_then(|mt| mt.get(Value::String("schema".to_string())))
        .and_then(Value::as_mapping)
        .and_then(|s| s.get(Value::String("$ref".to_string())))
        .and_then(Value::as_str)
    {
        return schema_ref.to_lowercase().contains("stream");
    }

    // OpenAPI 3.0: responses.200.schema.$ref (gnostic sometimes uses this)
    if let Some(schema_ref) = ok_resp
        .get(Value::String("schema".to_string()))
        .and_then(Value::as_mapping)
        .and_then(|s| s.get(Value::String("$ref".to_string())))
        .and_then(Value::as_str)
    {
        return schema_ref.to_lowercase().contains("stream");
    }

    false
}

/// Patch redirect endpoints: convert `200` response to `302` with `Location` header.
///
/// gnostic maps all proto RPCs to `200 OK`, but `/verify-email` returns a 302
/// redirect. This replaces the generated `200` response with an accurate `302`
/// response documenting the `Location` header.
fn patch_redirect_endpoints(doc: &mut Value) {
    let Some(paths) = doc
        .as_mapping_mut()
        .and_then(|m| m.get_mut("paths"))
        .and_then(Value::as_mapping_mut)
    else {
        return;
    };

    let Some(operation) = paths
        .get_mut("/verify-email")
        .and_then(Value::as_mapping_mut)
        .and_then(|p| p.get_mut("get"))
        .and_then(Value::as_mapping_mut)
    else {
        return;
    };

    let Some(responses) = operation
        .get_mut("responses")
        .and_then(Value::as_mapping_mut)
    else {
        return;
    };

    // Remove the auto-generated 200 response
    responses.remove("200");

    // Build 302 response with Location header
    let redirect: Value = serde_yaml_ng::from_str(
        r"
description: Redirect to frontend success or error page.
headers:
  Location:
    description: Frontend success or error page URL.
    required: true
    schema:
      type: string
      format: uri
",
    )
    .expect("static YAML must parse");

    responses.insert(Value::String("302".to_string()), redirect);
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Find the workspace root (directory containing the top-level Cargo.toml).
fn workspace_root() -> anyhow::Result<std::path::PathBuf> {
    // xtask runs from the workspace root when invoked via `cargo xtask`
    let output = Command::new(env!("CARGO"))
        .args(["locate-project", "--workspace", "--message-format=plain"])
        .output()
        .context("Failed to run `cargo locate-project`")?;

    if !output.status.success() {
        bail!(
            "cargo locate-project failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    let path = Path::new(std::str::from_utf8(&output.stdout)?.trim());
    Ok(path
        .parent()
        .context("Cargo.toml has no parent directory")?
        .to_path_buf())
}

/// Run a command in the workspace root directory.
fn run_cmd(root: &Path, program: &str, args: &[&str]) -> anyhow::Result<()> {
    let status = Command::new(program)
        .args(args)
        .current_dir(root)
        .status()
        .with_context(|| format!("Failed to run `{program} {}`", args.join(" ")))?;

    if !status.success() {
        bail!("`{program} {}` failed with {status}", args.join(" "));
    }
    Ok(())
}
