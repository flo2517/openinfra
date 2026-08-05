use openinfra_runtime::{interface::OpaqueBlock as Block, RuntimeApi};
use polkadot_sdk::{
    sc_client_api::BlockBackend,
    sc_consensus_aura::{ImportQueueParams, SlotProportion, StartAuraParams},
    sc_consensus_grandpa::{GrandpaPruningFilter, SharedVoterState},
    sc_executor::WasmExecutor,
    sc_service::{error::Error as ServiceError, Configuration, TaskManager, WarpSyncConfig},
    sc_telemetry::{Telemetry, TelemetryWorker},
    sc_transaction_pool_api::OffchainTransactionPoolFactory,
    sp_consensus_aura::sr25519::AuthorityPair as AuraPair,
    sp_runtime::traits::Block as BlockT,
    *,
};
use std::{sync::Arc, time::Duration};

type HostFunctions = sp_io::SubstrateHostFunctions;
pub(crate) type FullClient =
    sc_service::TFullClient<Block, RuntimeApi, WasmExecutor<HostFunctions>>;
type FullBackend = sc_service::TFullBackend<Block>;
type FullSelectChain = sc_consensus::LongestChain<FullBackend, Block>;

const GRANDPA_JUSTIFICATION_PERIOD: u32 = 512;

pub type Service = sc_service::PartialComponents<
    FullClient,
    FullBackend,
    FullSelectChain,
    sc_consensus::DefaultImportQueue<Block>,
    sc_transaction_pool::TransactionPoolHandle<Block, FullClient>,
    (
        sc_consensus_grandpa::GrandpaBlockImport<FullBackend, Block, FullClient, FullSelectChain>,
        sc_consensus_grandpa::LinkHalf<Block, FullClient, FullSelectChain>,
        Option<Telemetry>,
    ),
>;

pub fn new_partial(config: &Configuration) -> Result<Service, ServiceError> {
    let telemetry = config
        .telemetry_endpoints
        .clone()
        .filter(|endpoints| !endpoints.is_empty())
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
            vec![Arc::new(GrandpaPruningFilter)],
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
    let (grandpa_block_import, grandpa_link) = sc_consensus_grandpa::block_import(
        client.clone(),
        GRANDPA_JUSTIFICATION_PERIOD,
        &client,
        select_chain.clone(),
        telemetry.as_ref().map(|telemetry| telemetry.handle()),
    )?;
    let inherent_client = client.clone();
    let import_queue = sc_consensus_aura::import_queue::<AuraPair, _, _, _, _, _>(
        ImportQueueParams {
            block_import: grandpa_block_import.clone(),
            justification_import: Some(Box::new(grandpa_block_import.clone())),
            client: client.clone(),
            create_inherent_data_providers: move |parent_hash, _| {
                let client = inherent_client.clone();
                async move {
                    let slot_duration =
                        sc_consensus_aura::standalone::slot_duration_at(&*client, parent_hash)?;
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
                    let slot = sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                        *timestamp,
                        slot_duration,
                    );
                    Ok((slot, timestamp))
                }
            },
            spawner: &task_manager.spawn_essential_handle(),
            registry: config.prometheus_registry(),
            check_for_equivocation: Default::default(),
            telemetry: telemetry.as_ref().map(|telemetry| telemetry.handle()),
            compatibility_mode: Default::default(),
        },
    )?;
    Ok(sc_service::PartialComponents {
        client,
        backend,
        task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (grandpa_block_import, grandpa_link, telemetry),
    })
}

pub fn new_full<Network: sc_network::NetworkBackend<Block, <Block as BlockT>::Hash>>(
    config: Configuration,
) -> Result<TaskManager, ServiceError> {
    let sc_service::PartialComponents {
        client,
        backend,
        mut task_manager,
        import_queue,
        keystore_container,
        select_chain,
        transaction_pool,
        other: (block_import, grandpa_link, mut telemetry),
    } = new_partial(&config)?;
    let mut net_config = sc_network::config::FullNetworkConfiguration::<
        Block,
        <Block as BlockT>::Hash,
        Network,
    >::new(&config.network, config.prometheus_registry().cloned());
    let metrics = Network::register_notification_metrics(config.prometheus_registry());
    let grandpa_protocol_name = sc_consensus_grandpa::protocol_standard_name(
        &client
            .block_hash(0)
            .ok()
            .flatten()
            .expect("genesis block exists"),
        &config.chain_spec,
    );
    let (grandpa_protocol_config, grandpa_notification_service) =
        sc_consensus_grandpa::grandpa_peers_set_config::<_, Network>(
            grandpa_protocol_name.clone(),
            metrics.clone(),
            net_config.peer_store_handle(),
        );
    net_config.add_notification_protocol(grandpa_protocol_config);
    let warp_sync = Arc::new(sc_consensus_grandpa::warp_proof::NetworkProvider::new(
        backend.clone(),
        grandpa_link.shared_authority_set().clone(),
        Vec::new(),
    ));
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
            warp_sync_config: Some(WarpSyncConfig::WithProvider(warp_sync)),
            block_relay: None,
            metrics,
        })?;
    // Off-chain workers remain disabled: runtime-adjacent code must not perform external I/O.
    let role = config.role;
    let force_authoring = config.force_authoring;
    let backoff_authoring_blocks: Option<()> = None;
    let node_name = config.network.node_name.clone();
    let enable_grandpa = !config.disable_grandpa;
    let prometheus_registry = config.prometheus_registry().cloned();
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
    let _rpc_handlers = sc_service::spawn_tasks(sc_service::SpawnTasksParams {
        network: Arc::new(network.clone()),
        client: client.clone(),
        keystore: keystore_container.keystore(),
        task_manager: &mut task_manager,
        transaction_pool: transaction_pool.clone(),
        rpc_builder: rpc_extensions_builder,
        backend,
        system_rpc_tx,
        tx_handler_controller,
        sync_service: sync_service.clone(),
        config,
        telemetry: telemetry.as_mut(),
        tracing_execute_block: None,
    })?;
    if role.is_authority() {
        let proposer_factory = sc_basic_authorship::ProposerFactory::new(
            task_manager.spawn_handle(),
            client.clone(),
            transaction_pool.clone(),
            prometheus_registry.as_ref(),
            telemetry.as_ref().map(|telemetry| telemetry.handle()),
        );
        let slot_duration = sc_consensus_aura::slot_duration(&*client)?;
        let aura = sc_consensus_aura::start_aura::<AuraPair, _, _, _, _, _, _, _, _, _, _>(
            StartAuraParams {
                slot_duration,
                client,
                select_chain,
                block_import,
                proposer_factory,
                create_inherent_data_providers: move |_, ()| async move {
                    let timestamp = sp_timestamp::InherentDataProvider::from_system_time();
                    let slot = sp_consensus_aura::inherents::InherentDataProvider::from_timestamp_and_slot_duration(
                        *timestamp,
                        slot_duration,
                    );
                    Ok((slot, timestamp))
                },
                force_authoring,
                backoff_authoring_blocks,
                keystore: keystore_container.keystore(),
                sync_oracle: sync_service.clone(),
                justification_sync_link: sync_service.clone(),
                block_proposal_slot_portion: SlotProportion::new(2_f32 / 3_f32),
                max_block_proposal_slot_portion: None,
                telemetry: telemetry.as_ref().map(|telemetry| telemetry.handle()),
                compatibility_mode: Default::default(),
            },
        )?;
        task_manager
            .spawn_essential_handle()
            .spawn_blocking("aura", Some("block-authoring"), aura);
    }
    if enable_grandpa {
        let keystore = role.is_authority().then(|| keystore_container.keystore());
        let config = sc_consensus_grandpa::Config {
            gossip_duration: Duration::from_millis(333),
            justification_generation_period: GRANDPA_JUSTIFICATION_PERIOD,
            name: Some(node_name),
            observer_enabled: false,
            keystore,
            local_role: role,
            telemetry: telemetry.as_ref().map(|telemetry| telemetry.handle()),
            protocol_name: grandpa_protocol_name,
        };
        let params = sc_consensus_grandpa::GrandpaParams {
            config,
            link: grandpa_link,
            network,
            sync: Arc::new(sync_service),
            notification_service: grandpa_notification_service,
            voting_rule: sc_consensus_grandpa::VotingRulesBuilder::default().build(),
            prometheus_registry,
            shared_voter_state: SharedVoterState::empty(),
            telemetry: telemetry.as_ref().map(|telemetry| telemetry.handle()),
            offchain_tx_pool_factory: OffchainTransactionPoolFactory::new(transaction_pool),
        };
        task_manager.spawn_essential_handle().spawn_blocking(
            "grandpa-voter",
            None,
            sc_consensus_grandpa::run_grandpa_voter(params)?,
        );
    }
    Ok(task_manager)
}
