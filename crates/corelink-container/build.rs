//! Build script — compiles the placeholder Health gRPC proto via
//! tonic-build until the canonical REAPI protos are vendored.

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Health service (placeholder até REAPI protos serem vendados)
    // tonic-build 0.14 moved the prost proto codegen (incl. the free
    // `compile_protos` helper) into `tonic-prost-build`.
    tonic_prost_build::configure().compile_protos(
        &["proto/health.proto", "proto/staging_transport_probe.proto"],
        &["proto"],
    )?;

    // TODO semana 1: vendor REAPI protos oficiais de bazelbuild/remote-apis
    // Deve incluir: remote_execution.proto + deps (google/bytestream, google/rpc, build/bazel/semver)
    // tonic_build::configure()
    //     .build_server(true)
    //     .build_client(false)
    //     .compile_protos(
    //         &["proto/build/bazel/remote/execution/v2/remote_execution.proto"],
    //         &["proto"],
    //     )?;

    Ok(())
}
