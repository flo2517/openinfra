use jsonrpsee::RpcModule;
use openinfra_runtime::interface::{AccountId, Nonce, OpaqueBlock};
use polkadot_sdk::{
    sc_transaction_pool_api::TransactionPool,
    sp_blockchain::{Error as BlockchainError, HeaderBackend, HeaderMetadata},
    *,
};
use std::sync::Arc;

pub struct FullDeps<C, P> {
    pub client: Arc<C>,
    pub pool: Arc<P>,
}

pub fn create_full<C, P>(
    deps: FullDeps<C, P>,
) -> Result<RpcModule<()>, Box<dyn std::error::Error + Send + Sync>>
where
    C: Send
        + Sync
        + 'static
        + sp_api::ProvideRuntimeApi<OpaqueBlock>
        + HeaderBackend<OpaqueBlock>
        + HeaderMetadata<OpaqueBlock, Error = BlockchainError>,
    C::Api: sp_block_builder::BlockBuilder<OpaqueBlock>,
    C::Api: substrate_frame_rpc_system::AccountNonceApi<OpaqueBlock, AccountId, Nonce>,
    P: TransactionPool + 'static,
{
    use polkadot_sdk::substrate_frame_rpc_system::{System, SystemApiServer};
    let mut module = RpcModule::new(());
    module.merge(System::new(deps.client, deps.pool).into_rpc())?;
    Ok(module)
}
