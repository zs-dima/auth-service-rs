use std::io::Result;

fn main() -> Result<()> {
    let proto_files = &["proto/auth.proto", "proto/core.proto"];
    let includes = &["proto"];

    let out_dir = std::env::var("OUT_DIR").unwrap();
    let descriptor_path = format!("{}/file_descriptor_set.bin", out_dir);

    // Create prost config
    let mut config = prost_build::Config::new();
    config.file_descriptor_set_path(&descriptor_path);

    // Configure prost-validate to add Validator derive to all messages
    // This uses the validation rules defined in proto files (e.g., [(validate.rules).string.email = true])
    prost_validate_build::Builder::new()
        .configure(&mut config, proto_files, includes)
        .expect("Failed to configure prost-validate");

    // Add tonic service generator to the config
    config.service_generator(
        tonic_prost_build::configure()
            .build_server(true)
            .build_client(false)
            .service_generator(),
    );

    // Compile protos with the configured prost config
    config
        .compile_protos(proto_files, includes)
        .expect("Failed to compile protos");

    // Recompile if proto files change
    println!("cargo:rerun-if-changed=proto/auth.proto");
    println!("cargo:rerun-if-changed=proto/core.proto");
    println!("cargo:rerun-if-changed=proto/validate/validate.proto");

    Ok(())
}
