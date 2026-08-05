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
    chain_spec(
        "OpenInfra Development",
        "openinfra-dev",
        ChainType::Development,
        vec![(
            sp_keyring::Sr25519Keyring::Alice.public().into(),
            sp_keyring::Ed25519Keyring::Alice.public().into(),
        )],
    )
}

pub fn local_testnet_chain_spec() -> Result<ChainSpec, String> {
    chain_spec(
        "OpenInfra Local Testnet",
        "openinfra-local",
        ChainType::Local,
        vec![
            (
                sp_keyring::Sr25519Keyring::Alice.public().into(),
                sp_keyring::Ed25519Keyring::Alice.public().into(),
            ),
            (
                sp_keyring::Sr25519Keyring::Bob.public().into(),
                sp_keyring::Ed25519Keyring::Bob.public().into(),
            ),
        ],
    )
}

fn chain_spec(
    name: &str,
    id: &str,
    chain_type: ChainType,
    authorities: Vec<(
        sp_consensus_aura::sr25519::AuthorityId,
        sp_consensus_grandpa::AuthorityId,
    )>,
) -> Result<ChainSpec, String> {
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

    let aura_authorities: Vec<_> = authorities.iter().map(|(aura, _)| aura.clone()).collect();
    let grandpa_authorities: Vec<_> = authorities
        .iter()
        .map(|(_, grandpa)| (grandpa.clone(), 1))
        .collect();

    Ok(ChainSpec::builder(
        WASM_BINARY.ok_or("development runtime WASM is unavailable")?,
        Default::default(),
    )
    .with_name(name)
    .with_id(id)
    .with_chain_type(chain_type)
    .with_genesis_config_preset_name(sp_genesis_builder::DEV_RUNTIME_PRESET)
    .with_genesis_config_patch(serde_json::json!({
        "sudo": { "key": sudo_account.clone() },
        "balances": { "balances": [[sudo_account, 1_000_000]] },
        "aura": { "authorities": aura_authorities },
        "grandpa": { "authorities": grandpa_authorities }
    }))
    .with_properties(properties())
    .build())
}
