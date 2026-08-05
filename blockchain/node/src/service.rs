use crate::cli::Consensus;
use openinfra_runtime::{interface::OpaqueBlock as Block, RuntimeApi};
use polkadot_sdk::{
    sc_executor::WasmExecutor,
    sc_service::{error::Error as ServiceError, Configuration, TaskManager},
    sc_telemetry::{Telemetry, TelemetryWorker},
    sp_runtime::traits::Block as BlockT,
    *,
};
use std::sync::Arc;

type HostFunctions = sp_io::SubstrateHostFunctions;
pub(crate) type FullClient =
    sc_service::TFullClient<Block, RuntimeApi, WasmExecutor<HostFunctions>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

pub type Service = sc_service::PartialComponents<
    FullClient,
    FullBackend,
    FullSelectChain,
    sc_consensus::DefaultImportQueue<Block>,
    sc_transaction_pool::TransactionPoolHandle<Block, FullClient>,
    Option<Telemetry>,
>;

pub fn new_partial(config: &Configuration) -> Result<Service, ServiceError> {
    let telemetry = config
        .telemetry_endpoints
        .clone()
        .filter(|x| !x.is_empty())
        .map(|endpoints| -> Result<_, sc_telemetry::Error> {
            let worker = TelemetryWorker::new(16)?;
            let telemetry = worker.handle().new_telemetry(endpoints);
            Ok((worker, telemetry))
        })
        .transpose()?;
    let executor = sc_service::new_wasm_executor(&config.executor);
    let (client, backend, keystore_container, task_manager) =
        sc_service::new_full_parts::<Block, RuntimeApi, _>(
            config,
            telemetry.as_ref().map(|(_, telemetry)| telemetry.handle()),
            executor,
            Default::default(),
        )?;
    let client = Arc::new(client);
    let telemetry = telemetry.map(|(worker, telemetry)| {
        task_manager
            .spawn_handle()
            .spawn("telemetry", None, worker.run());
        telemetry
    });
    let select_chain = sc_consensus::LongestChain::new(backend.clone());
    let transaction_pool = Arc::from(
        sc_transaction_pool::Builder::new(
            task_manager.spawn_essential_handle(),
            client.clone(),
            config.role.is_authority().into(),
        )
        .with_options(config.transaction_pool.clone())
        .with_prometheus(config.prometheus_registry())
        .build(),
    );
    let import_queue = sc_consensus_manual_seal::import_queue(
        Box::new(client.clone()),
        &task_manager.spawn_essential_handle(),
        config.prometheus_registry(),
    );
    Ok(sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: telemetry,
    })
}

pub fn new_full<Network: sc_network::NetworkBackend<Block, <Block as BlockT>::Hash>>(
    config: Configuration,
    consensus: Consensus,
) -> Result<TaskManager, ServiceError> {
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: mut telemetry,
    } = new_partial(&config)?;
    let net_config = sc_network::config::FullNetworkConfiguration::<
        Block,
        <Block as BlockT>::Hash,
        Network,
    >::new(
        &config.network,
        config
            .prometheus_config
            .as_ref()
            .map(|cfg| cfg.registry.clone()),
    );
    let metrics = Network::register_notification_metrics(
        config.prometheus_config.as_ref().map(|cfg| &cfg.registry),
    );
    let (network, system_rpc_tx, tx_handler_controller, sync_service) =
        sc_service::build_network(sc_service::BuildNetworkParams {
            config: &config,
            net_config,
            client: client.clone(),
            transaction_pool: transaction_pool.clone(),
            spawn_handle: task_manager.spawn_handle(),
            spawn_essential_handle: task_manager.spawn_essential_handle(),
            import_queue,
            block_announce_validator_builder: None,
            warp_sync_config: None,
            block_relay: None,
            metrics,
        })?;

    // Off-chain workers are intentionally not started: the OpenInfra runtime must remain
    // deterministic and may not initiate HTTP or other system access.
    let rpc_extensions_builder = {
        let client = client.clone();
        let pool = transaction_pool.clone();
        Box::new(move |_| {
            crate::rpc::create_full(crate::rpc::FullDeps {
                client: client.clone(),
                pool: pool.clone(),
            })
            .map_err(Into::into)
        })
    };
    let prometheus_registry = config.prometheus_registry().cloned();
    let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network,
        client: client.clone(),
        keystore: keystore_container.keystore(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        rpc_builder: rpc_extensions_builder,
        backend,
        system_rpc_tx,
        tx_handler_controller,
        sync_service,
        config,
        telemetry: telemetry.as_mut(),
        tracing_execute_block: None,
    })?;
    let proposer = sc_basic_authorship::ProposerFactory::new(
        task_manager.spawn_handle(),
        client.clone(),
        transaction_pool.clone(),
        prometheus_registry.as_ref(),
        telemetry.as_ref().map(|value| value.handle()),
    );
    match consensus {
        Consensus::InstantSeal => {
            let params = sc_consensus_manual_seal::InstantSealParams {
                block_import: client.clone(),
                env: proposer,
                client,
                pool: transaction_pool,
                select_chain,
                consensus_data_provider: None,
                create_inherent_data_providers: move |_, ()| async move {
                    Ok(sp_timestamp::InherentDataProvider::from_system_time())
                },
            };
            task_manager.spawn_essential_handle().spawn_blocking(
                "instant-seal",
                None,
                sc_consensus_manual_seal::run_instant_seal(params),
            );
        }
        Consensus::ManualSeal(block_time) => {
            let (mut sink, commands_stream) = futures::channel::mpsc::channel(1024);
            task_manager
                .spawn_handle()
                .spawn("block-authoring", None, async move {
                    loop {
                        futures_timer::Delay::new(std::time::Duration::from_millis(block_time))
                            .await;
                        if sink
                            .try_send(sc_consensus_manual_seal::EngineCommand::SealNewBlock {
                                create_empty: true,
                                finalize: true,
                                parent_hash: None,
                                sender: None,
                            })
                            .is_err()
                        {
                            break;
                        }
                    }
                });
            let params = sc_consensus_manual_seal::ManualSealParams {
                block_import: client.clone(),
                env: proposer,
                client,
                pool: transaction_pool,
                select_chain,
                commands_stream: Box::pin(commands_stream),
                consensus_data_provider: None,
                create_inherent_data_providers: move |_, ()| async move {
                    Ok(sp_timestamp::InherentDataProvider::from_system_time())
                },
            };
            task_manager.spawn_essential_handle().spawn_blocking(
                "manual-seal",
                None,
                sc_consensus_manual_seal::run_manual_seal(params),
            );
        }
        Consensus::None => {}
    }
    Ok(task_manager)
}
