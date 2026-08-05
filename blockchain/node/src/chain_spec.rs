use openinfra_runtime::{interface::AccountId, WASM_BINARY};
use polkadot_sdk::{
    sc_service::{ChainType, Properties},
    *,
};

pub type ChainSpec = sc_service::GenericChainSpec;

fn properties() -> Properties {
    let mut properties = Properties::new();
    properties.insert("tokenDecimals".to_string(), 0.into());
    properties.insert("tokenSymbol".to_string(), "OINF".into());
    properties
}

pub fn development_chain_spec() -> Result<ChainSpec, String> {
    let public_key_path = std::env::var("OPENINFRA_DEV_SUDO_PUBLIC_KEY_FILE")
        .map_err(|_| "OPENINFRA_DEV_SUDO_PUBLIC_KEY_FILE is required".to_string())?;
    let encoded = std::fs::read_to_string(&public_key_path)
        .map_err(|error| format!("read development sudo public key: {error}"))?;
    let decoded = hex::decode(encoded.trim())
        .map_err(|error| format!("decode development sudo public key: {error}"))?;
    let public_key: [u8; 32] = decoded
        .try_into()
        .map_err(|_| "development sudo public key must contain 32 bytes".to_string())?;
    let sudo_account = AccountId::from(public_key);

    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or("development runtime WASM is unavailable")?,
        Default::default(),
    )
    .with_name("OpenInfra Development")
    .with_id("openinfra-dev")
    .with_chain_type(ChainType::Development)
    .with_genesis_config_preset_name(sp_genesis_builder::DEV_RUNTIME_PRESET)
    .with_genesis_config_patch(serde_json::json!({
        "sudo": { "key": sudo_account.clone() },
        "balances": { "balances": [[sudo_account, 1_000_000]] }
    }))
    .with_properties(properties())
    .build())
}
