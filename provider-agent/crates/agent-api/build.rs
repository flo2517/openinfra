fn main() -> Result<(), Box<dyn std::error::Error>> {
    let proto_dir = "../../../protocol/proto";
    let protos = [
        "../../../protocol/proto/openinfra/agent/v1/agent.proto",
        "../../../protocol/proto/openinfra/shared/v1/shared.proto",
        "../../../protocol/proto/openinfra/controlplane/v1/control_plane.proto",
    ];
    for proto in protos {
        println!("cargo:rerun-if-changed={proto}");
    }
    let protoc = protoc_bin_vendored::protoc_bin_path()?;
    std::env::set_var("PROTOC", protoc);
    tonic_build::configure().compile(&protos, &[proto_dir])?;
    Ok(())
}
