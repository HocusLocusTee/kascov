use kaspa_addresses::{Address, Prefix, Version};
use secp256k1::SecretKey;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{self, BufRead, Write};
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use crate::ui::{print_header, print_kv};

const DEFAULT_HISTORY_PATH: &str = "tx-history.jsonl";
const DEFAULT_WALLETS_PATH: &str = "wallets.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletRecord {
    pub name: String,
    pub private_key: String,
    pub address: String,
    pub created_at_unix_ms: u128,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxHistoryRecord {
    pub ts_unix_ms: u128,
    pub action: String,
    pub txid: String,
    pub rpc: String,
    pub address: String,
    pub details: String,
}

pub fn history_path() -> String {
    std::env::var("KASPA_HISTORY_FILE").unwrap_or_else(|_| DEFAULT_HISTORY_PATH.to_string())
}

fn wallets_path() -> String {
    std::env::var("KASPA_WALLETS_FILE").unwrap_or_else(|_| DEFAULT_WALLETS_PATH.to_string())
}

fn now_unix_ms() -> u128 {
    match SystemTime::now().duration_since(UNIX_EPOCH) {
        Ok(duration) => duration.as_millis(),
        Err(_) => 0,
    }
}

pub fn load_wallets() -> Result<Vec<WalletRecord>, String> {
    let path = wallets_path();
    if !Path::new(&path).exists() {
        return Ok(Vec::new());
    }
    let json = fs::read_to_string(&path).map_err(|err| format!("failed to read wallets file {path}: {err}"))?;
    serde_json::from_str::<Vec<WalletRecord>>(&json).map_err(|err| format!("failed to parse wallets file {path}: {err}"))
}

pub fn save_wallets(wallets: &[WalletRecord]) -> Result<(), String> {
    let path = wallets_path();
    let json = serde_json::to_string_pretty(wallets).map_err(|err| format!("failed to encode wallets json: {err}"))?;
    fs::write(&path, json).map_err(|err| format!("failed to write wallets file {path}: {err}"))
}

fn random_secret_key() -> Result<SecretKey, String> {
    loop {
        let mut bytes = [0u8; 32];
        getrandom::getrandom(&mut bytes).map_err(|err| format!("os random failed: {err}"))?;
        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            return Ok(secret);
        }
    }
}

fn hex_encode_32(bytes: &[u8; 32]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
}

pub fn generate_wallet_record(name: Option<String>, wallet_index: usize) -> Result<WalletRecord, String> {
    let secret = random_secret_key()?;
    let private_key = hex_encode_32(&secret.secret_bytes());
    let keypair = secp256k1::Keypair::from_secret_key(secp256k1::SECP256K1, &secret);
    let x_only_pubkey = keypair.x_only_public_key().0.serialize();
    let address = Address::new(Prefix::Testnet, Version::PubKey, &x_only_pubkey).to_string();
    Ok(WalletRecord {
        name: name.unwrap_or_else(|| format!("wallet-{wallet_index}")),
        private_key,
        address,
        created_at_unix_ms: now_unix_ms(),
    })
}

pub fn parse_testnet_address(address: &str) -> Result<Address, String> {
    let parsed = Address::try_from(address).map_err(|err| format!("invalid address: {err}"))?;
    if parsed.prefix != Prefix::Testnet {
        return Err(format!(
            "mainnet/devnet/simnet addresses are blocked; use a kaspatest: address (got prefix: {})",
            parsed.prefix
        ));
    }
    Ok(parsed)
}

pub fn cmd_wallets() -> Result<(), String> {
    let wallets = load_wallets()?;
    print_header("Wallets");
    print_kv("wallets_file", wallets_path());
    print_kv("wallet_count", wallets.len());
    for (index, wallet) in wallets.iter().enumerate() {
        println!("  [{}] {}  {}", index + 1, wallet.name, wallet.address);
    }
    Ok(())
}

fn append_history(record: TxHistoryRecord) -> Result<(), String> {
    let path = history_path();
    let line = serde_json::to_string(&record).map_err(|err| format!("failed to encode history json: {err}"))?;
    let mut file = fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
        .map_err(|err| format!("failed to open history file {path}: {err}"))?;
    writeln!(file, "{line}").map_err(|err| format!("failed to write history file {path}: {err}"))?;
    Ok(())
}

pub fn list_history() -> Result<Vec<TxHistoryRecord>, String> {
    let path = history_path();
    if !Path::new(&path).exists() {
        return Ok(Vec::new());
    }
    let file = fs::File::open(&path).map_err(|err| format!("failed to open history file {path}: {err}"))?;
    let reader = io::BufReader::new(file);
    let mut rows = Vec::new();
    for line in reader.lines() {
        let line = line.map_err(|err| format!("failed reading history file {path}: {err}"))?;
        if line.trim().is_empty() {
            continue;
        }
        if let Ok(record) = serde_json::from_str::<TxHistoryRecord>(&line) {
            rows.push(record);
        }
    }
    Ok(rows)
}

pub fn cmd_history(limit: usize) -> Result<(), String> {
    let mut rows = list_history()?;
    rows.sort_by_key(|row| row.ts_unix_ms);
    let take = limit.min(rows.len());
    let start = rows.len().saturating_sub(take);
    print_header("History");
    print_kv("history_file", history_path());
    print_kv("history_count", rows.len());
    print_kv("showing", take);
    for (idx, row) in rows.into_iter().skip(start).enumerate() {
        println!();
        println!("  [{}] {} {}", idx + 1, row.action, row.txid);
        println!("      {:>8}: {}", "ts_ms", row.ts_unix_ms);
        println!("      {:>8}: {}", "rpc", row.rpc);
        println!("      {:>8}: {}", "address", row.address);
        println!("      {:>8}: {}", "details", row.details);
    }
    Ok(())
}

pub fn save_tx_history(action: &str, txid: &str, rpc: &str, address: &str, details: String) {
    let record = TxHistoryRecord {
        ts_unix_ms: now_unix_ms(),
        action: action.to_string(),
        txid: txid.to_string(),
        rpc: rpc.to_string(),
        address: address.to_string(),
        details,
    };
    if let Err(err) = append_history(record) {
        eprintln!("warning: failed to write tx history: {err}");
    }
}
