//! Cross-platform project automation tasks.
//!
//! Usage: `cargo xtask <command>`
//!
//! Commands:
//!   openapi  — Generate `OpenAPI` 3.1 spec from proto definitions
//!
//! This replaces platform-specific shell scripts with portable Rust code.
//! See <https://github.com/matklad/cargo-xtask> for the pattern.

use std::env;
use std::process::ExitCode;

mod openapi;

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();

    let Some(command) = args.first() else {
        eprintln!("Usage: cargo xtask <command>");
        eprintln!();
        eprintln!("Commands:");
        eprintln!("  openapi  Generate OpenAPI 3.1 spec from proto definitions");
        return ExitCode::FAILURE;
    };

    let result = match command.as_str() {
        "openapi" => openapi::run(),
        other => {
            eprintln!("Unknown command: {other}");
            eprintln!("Run `cargo xtask` for usage");
            return ExitCode::FAILURE;
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("Error: {e:#}");
            ExitCode::FAILURE
        }
    }
}
