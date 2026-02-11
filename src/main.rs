use clap::Parser;
use std::fs;

mod commands;
mod console;
mod storage;
mod ui;

const DEFAULT_RPC: &str = "66.23.234.250:16210";
const DEFAULT_PRIVATE_KEY: &str = "f2017e3d1f509e53f8c1dc2c941062508b06aed612a9a97e2a58b3aab7e9e829";
const DEFAULT_ADDRESS: &str = "kaspatest:qp8snfastxwvcu40sy7sfwwad0kpkjt2flcdkuuk4gw2td0mcauukn2pq66m6";
const DEFAULT_CONTRACTS_DIR: &str = "contracts";
const DEFAULT_COMPILED_DIR: &str = "compiled-silverscript";
const DEFAULT_CONTRACT_PARAMS_DIR: &str = "contract-params";

#[derive(Parser, Debug)]
#[command(name = "kascov")]
#[command(about = "Console-only Kaspa gRPC CLI for contracts, balance, and transactions")]
struct Cli {
    #[arg(long, env = "KASPA_RPC", default_value = DEFAULT_RPC)]
    rpc: String,
    #[arg(long, default_value = DEFAULT_PRIVATE_KEY)]
    private_key: String,
    #[arg(long, default_value = DEFAULT_ADDRESS)]
    address: String,
    #[arg(long, default_value = DEFAULT_CONTRACTS_DIR)]
    contracts_dir: String,
    #[arg(long, default_value = DEFAULT_COMPILED_DIR)]
    out_dir: String,
}

#[tokio::main]
async fn main() {
    if let Err(err) = run().await {
        eprintln!("error: {err}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let _ = dotenvy::dotenv();
    let cli = Cli::parse();
    storage::parse_testnet_address(&cli.address)?;
    ensure_startup_dirs(&cli.contracts_dir, &cli.out_dir, DEFAULT_CONTRACT_PARAMS_DIR)?;
    console::cmd_console(cli.rpc, cli.private_key, cli.address, cli.contracts_dir, cli.out_dir).await
}

fn ensure_startup_dirs(contracts_dir: &str, out_dir: &str, contract_params_dir: &str) -> Result<(), String> {
    fs::create_dir_all(contracts_dir).map_err(|err| format!("failed to create contracts dir {contracts_dir}: {err}"))?;
    fs::create_dir_all(out_dir).map_err(|err| format!("failed to create compiled dir {out_dir}: {err}"))?;
    fs::create_dir_all(contract_params_dir)
        .map_err(|err| format!("failed to create contract params dir {contract_params_dir}: {err}"))?;
    Ok(())
}
