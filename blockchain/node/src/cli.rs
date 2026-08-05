use polkadot_sdk::*;

#[derive(Debug, Clone)]
pub enum Consensus {
    ManualSeal(u64),
    InstantSeal,
    None,
}

impl std::str::FromStr for Consensus {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value == "instant-seal" {
            return Ok(Self::InstantSeal);
        }
        if value.eq_ignore_ascii_case("none") {
            return Ok(Self::None);
        }
        let block_time = value
            .strip_prefix("manual-seal-")
            .ok_or_else(|| {
                "expected manual-seal-<milliseconds>, instant-seal, or none".to_string()
            })?
            .parse::<u64>()
            .map_err(|_| "invalid manual-seal block time".to_string())?;
        if block_time == 0 {
            return Err("manual-seal block time must be greater than zero".into());
        }
        Ok(Self::ManualSeal(block_time))
    }
}

#[derive(Debug, clap::Parser)]
pub struct Cli {
    #[command(subcommand)]
    pub subcommand: Option<Subcommand>,

    /// Development-only consensus mode. Manual seal is not production consensus.
    #[clap(long, default_value = "manual-seal-3000")]
    pub consensus: Consensus,

    #[clap(flatten)]
    pub run: sc_cli::RunCmd,
}

#[derive(Debug, clap::Subcommand)]
pub enum Subcommand {
    #[command(subcommand)]
    Key(sc_cli::KeySubcommand),
    ExportChainSpec(sc_cli::ExportChainSpecCmd),
    CheckBlock(sc_cli::CheckBlockCmd),
    ExportBlocks(sc_cli::ExportBlocksCmd),
    ExportState(sc_cli::ExportStateCmd),
    ImportBlocks(sc_cli::ImportBlocksCmd),
    PurgeChain(sc_cli::PurgeChainCmd),
    Revert(sc_cli::RevertCmd),
    ChainInfo(sc_cli::ChainInfoCmd),
}
