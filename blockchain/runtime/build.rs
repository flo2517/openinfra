fn main() {
    #[cfg(feature = "std")]
    polkadot_sdk::substrate_wasm_builder::WasmBuilder::init_with_defaults()
        // rust-lld 21 (bundled with Rust 1.97) rejects Substrate host functions unless
        // unresolved WASM symbols are explicitly retained as imports.
        .append_to_rust_flags("-C link-arg=--allow-undefined")
        .build();
}
