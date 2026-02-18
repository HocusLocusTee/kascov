use kaspa_consensus_core::{
    constants::TX_VERSION,
    hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
    hashing::sighash_type::SIG_HASH_ALL,
    sign::sign,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{MutableTransaction, ScriptPublicKey, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};
use kaspa_txscript::{
    extract_script_pub_key_address, pay_to_address_script, pay_to_script_hash_script, pay_to_script_hash_signature_script,
};
use secp256k1::{Keypair, Message, SecretKey};
use serde::Deserialize;
use silverscript_lang::{
    ast::Expr,
    compiler::{compile_contract, CompileOptions, CompiledContract},
};
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::str::FromStr;
use walkdir::WalkDir;

use crate::storage::{parse_testnet_address, save_tx_history};
use crate::ui::{print_header, print_kv};

#[derive(Debug, Clone)]
struct SpendOutputSpec {
    destination: SpendOutputDestination,
    amount_sompi: u64,
}

#[derive(Debug, Clone, Deserialize)]
struct SpendOutputSpecInput {
    address: Option<String>,
    locking_bytecode_hex: Option<String>,
    amount_sompi: Option<u64>,
    amount: Option<String>,
}

#[derive(Debug, Clone)]
pub enum SpendOutputDestination {
    Address(String),
    LockingBytecodeHex(String),
}

#[derive(Clone, Copy)]
enum AmountUnit {
    Sompi,
    Kas,
}

impl AmountUnit {
    fn from_env() -> Result<Self, String> {
        match std::env::var("KASPA_AMOUNT_UNIT") {
            Ok(raw) => match raw.trim().to_ascii_uppercase().as_str() {
                "" | "SOMPI" => Ok(Self::Sompi),
                "KAS" => Ok(Self::Kas),
                other => Err(format!(
                    "invalid KASPA_AMOUNT_UNIT '{other}', expected 'SOMPI' or 'KAS'"
                )),
            },
            Err(_) => Ok(Self::Sompi),
        }
    }
}

fn parse_kas_to_sompi(raw: &str) -> Result<u64, String> {
    let text = raw.trim();
    if text.is_empty() {
        return Err("amount is empty".to_string());
    }
    if text.starts_with('-') {
        return Err("amount cannot be negative".to_string());
    }
    if text.matches('.').count() > 1 {
        return Err("invalid KAS amount: too many decimal points".to_string());
    }

    let mut parts = text.split('.');
    let whole_part = parts.next().unwrap_or("");
    let frac_part = parts.next().unwrap_or("");
    if parts.next().is_some() {
        return Err("invalid KAS amount".to_string());
    }
    if whole_part.is_empty() && frac_part.is_empty() {
        return Err("amount is empty".to_string());
    }
    if !whole_part.is_empty() && !whole_part.chars().all(|ch| ch.is_ascii_digit()) {
        return Err("invalid KAS amount: whole part must be digits".to_string());
    }
    if !frac_part.is_empty() && !frac_part.chars().all(|ch| ch.is_ascii_digit()) {
        return Err("invalid KAS amount: fractional part must be digits".to_string());
    }
    if frac_part.len() > 8 {
        return Err("invalid KAS amount: max 8 decimal places".to_string());
    }

    let whole = if whole_part.is_empty() {
        0u64
    } else {
        whole_part
            .parse::<u64>()
            .map_err(|err| format!("invalid KAS amount whole part: {err}"))?
    };
    let mut frac_scaled = 0u64;
    if !frac_part.is_empty() {
        let frac = frac_part
            .parse::<u64>()
            .map_err(|err| format!("invalid KAS amount fractional part: {err}"))?;
        let scale = 10u64
            .checked_pow((8 - frac_part.len()) as u32)
            .ok_or_else(|| "invalid KAS scale".to_string())?;
        frac_scaled = frac
            .checked_mul(scale)
            .ok_or_else(|| "KAS amount overflow".to_string())?;
    }

    let whole_sompi = whole
        .checked_mul(100_000_000)
        .ok_or_else(|| "KAS amount overflow".to_string())?;
    whole_sompi
        .checked_add(frac_scaled)
        .ok_or_else(|| "KAS amount overflow".to_string())
}

fn decode_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    let normalized = input
        .trim()
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '_')
        .collect::<String>();
    let hex = normalized.strip_prefix("0x").unwrap_or(&normalized);
    if hex.is_empty() {
        return Err("hex is empty".to_string());
    }
    if hex.len() % 2 != 0 {
        return Err("hex must have even length".to_string());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|err| format!("invalid hex at byte {}: {err}", i / 2))?;
        out.push(byte);
    }
    Ok(out)
}

pub fn cmd_compile_sil(source: &str, out: Option<&str>, constructor_args_path: Option<&str>) -> Result<(), String> {
    let constructor_args = if let Some(path) = constructor_args_path {
        let json = fs::read_to_string(path).map_err(|err| format!("failed to read constructor args {path}: {err}"))?;
        serde_json::from_str::<Vec<Expr>>(&json).map_err(|err| format!("failed to parse constructor args {path}: {err}"))?
    } else {
        Vec::new()
    };
    cmd_compile_sil_with_args(source, out, constructor_args)
}

pub fn cmd_compile_sil_with_args(source: &str, out: Option<&str>, constructor_args: Vec<Expr>) -> Result<(), String> {
    let source_text = fs::read_to_string(source).map_err(|err| format!("failed to read source file {source}: {err}"))?;

    let compile_options = CompileOptions { allow_yield: true, ..CompileOptions::default() };
    let compiled =
        compile_contract(&source_text, &constructor_args, compile_options).map_err(|err| format!("compile error: {err}"))?;

    let output_path = out
        .map(|value| value.to_string())
        .unwrap_or_else(|| default_sil_output_path(source));
    let json = serde_json::to_string_pretty(&compiled).map_err(|err| format!("failed to serialize output: {err}"))?;
    fs::write(&output_path, json).map_err(|err| format!("failed to write output {output_path}: {err}"))?;
    println!("compiled={source}");
    println!("output={output_path}");
    Ok(())
}

fn constructor_args_for_batch_contract(
    contracts_path: &Path,
    source_path: &Path,
) -> Result<(Vec<Expr>, Option<PathBuf>), String> {
    let relative = source_path
        .strip_prefix(contracts_path)
        .map_err(|err| format!("failed to map relative path for {}: {err}", source_path.display()))?;

    let params_parent = contracts_path.parent().unwrap_or_else(|| Path::new("."));
    let params_root = if params_parent.join("params").exists() {
        params_parent.join("params")
    } else {
        params_parent.join("contract-params")
    };

    let relative_without_ext = relative.with_extension("");
    let stem = relative_without_ext
        .file_name()
        .and_then(|value| value.to_str())
        .ok_or_else(|| format!("failed to resolve contract stem for {}", source_path.display()))?;
    let rel_parent = relative_without_ext.parent().unwrap_or_else(|| Path::new(""));

    let ctor_candidate = params_root.join(rel_parent).join(format!("{stem}_ctor.json"));
    let plain_candidate = params_root.join(&relative_without_ext).with_extension("json");

    let constructor_args_path = if ctor_candidate.exists() {
        Some(ctor_candidate)
    } else if plain_candidate.exists() {
        Some(plain_candidate)
    } else {
        None
    };

    let constructor_args = if let Some(path) = constructor_args_path.as_ref() {
        let json =
            fs::read_to_string(path).map_err(|err| format!("failed to read constructor args {}: {err}", path.display()))?;
        serde_json::from_str::<Vec<Expr>>(&json)
            .map_err(|err| format!("failed to parse constructor args {}: {err}", path.display()))?
    } else {
        Vec::new()
    };

    Ok((constructor_args, constructor_args_path))
}

pub fn cmd_compile_contracts(contracts_dir: &str, out_dir: &str) -> Result<(), String> {
    let contracts_path = Path::new(contracts_dir);
    if !contracts_path.exists() {
        return Err(format!("contracts dir does not exist: {contracts_dir}"));
    }
    fs::create_dir_all(out_dir).map_err(|err| format!("failed to create output dir {out_dir}: {err}"))?;

    let mut compiled_count = 0usize;
    for entry in WalkDir::new(contracts_path) {
        let entry = entry.map_err(|err| format!("walk error: {err}"))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let source_path = entry.path();
        if source_path.extension().and_then(|ext| ext.to_str()) != Some("sil") {
            continue;
        }

        let relative = source_path
            .strip_prefix(contracts_path)
            .map_err(|err| format!("failed to map relative path for {}: {err}", source_path.display()))?;
        let mut output_path: PathBuf = Path::new(out_dir).join(relative);
        output_path.set_extension("json");
        if let Some(parent) = output_path.parent() {
            fs::create_dir_all(parent).map_err(|err| format!("failed to create dir {}: {err}", parent.display()))?;
        }
        let source_text = fs::read_to_string(source_path)
            .map_err(|err| format!("failed to read source file {}: {err}", source_path.display()))?;
        let (constructor_args, constructor_args_path) = constructor_args_for_batch_contract(contracts_path, source_path)?;
        let compile_options = CompileOptions { allow_yield: true, ..CompileOptions::default() };
        let compiled = compile_contract(&source_text, &constructor_args, compile_options)
            .map_err(|err| format!("compile error in {}: {err}", source_path.display()))?;
        let json = serde_json::to_string_pretty(&compiled).map_err(|err| format!("failed to serialize output: {err}"))?;
        fs::write(&output_path, json).map_err(|err| format!("failed to write output {}: {err}", output_path.display()))?;
        println!("compiled={}", source_path.display());
        if let Some(path) = constructor_args_path {
            println!("constructor_args={}", path.display());
        }
        println!("output={}", output_path.display());
        compiled_count += 1;
    }

    println!("contracts_dir={contracts_dir}");
    println!("compiled_dir={out_dir}");
    println!("compiled_count={compiled_count}");
    Ok(())
}

async fn connect_grpc(rpc: &str) -> Result<GrpcClient, String> {
    let endpoint = if rpc.starts_with("grpc://") { rpc.to_string() } else { format!("grpc://{rpc}") };
    GrpcClient::connect_with_args(
        NotificationMode::Direct,
        endpoint,
        None,
        false,
        None,
        false,
        Some(30_000),
        Default::default(),
    )
    .await
    .map_err(|err| format!("grpc connect failed: {err}"))
}

pub async fn cmd_balance(rpc: &str, address: &str) -> Result<(), String> {
    let address = parse_testnet_address(address)?;
    let client = connect_grpc(rpc).await?;

    let server = client.get_server_info().await.map_err(|err| format!("get_server_info failed: {err}"))?;
    let entries = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .map_err(|err| format!("get_utxos_by_addresses failed: {err}"))?;
    let mempool_entries = client
        .get_mempool_entries_by_addresses(vec![address.clone()], true, false)
        .await
        .map_err(|err| format!("get_mempool_entries_by_addresses failed: {err}"))?;

    let total_sompi: u64 = entries.iter().map(|entry| entry.utxo_entry.amount).sum();
    let mut confirmed_outpoint_amounts = HashMap::new();
    for entry in &entries {
        confirmed_outpoint_amounts.insert((entry.outpoint.transaction_id, entry.outpoint.index), entry.utxo_entry.amount);
    }

    let mut pending_spent_outpoints = HashSet::new();
    let mut pending_spent_sompi = 0u64;
    let mut pending_incoming_sompi = 0u64;
    for by_addr in mempool_entries {
        for sending in by_addr.sending {
            for input in sending.transaction.inputs {
                let key = (input.previous_outpoint.transaction_id, input.previous_outpoint.index);
                if pending_spent_outpoints.insert(key) {
                    if let Some(amount) = confirmed_outpoint_amounts.get(&key) {
                        pending_spent_sompi = pending_spent_sompi.saturating_add(*amount);
                    }
                }
            }
        }

        for receiving in by_addr.receiving {
            for output in receiving.transaction.outputs {
                if output
                    .verbose_data
                    .as_ref()
                    .map(|value| value.script_public_key_address == address)
                    .unwrap_or(false)
                {
                    pending_incoming_sompi = pending_incoming_sompi.saturating_add(output.value);
                }
            }
        }
    }

    let available_confirmed_sompi = total_sompi.saturating_sub(pending_spent_sompi);
    let effective_sompi = available_confirmed_sompi.saturating_add(pending_incoming_sompi);
    let whole = total_sompi / 100_000_000;
    let frac = total_sompi % 100_000_000;

    print_header("Balance");
    print_kv("network", server.network_id);
    print_kv("synced", server.is_synced);
    print_kv("utxo_index", server.has_utxo_index);
    print_kv("address", address);
    print_kv("utxo_count", entries.len());
    print_kv("confirmed_sompi", total_sompi);
    print_kv("confirmed_kas", format!("{whole}.{frac:08}"));
    print_kv("pending_spent_sompi", pending_spent_sompi);
    print_kv("pending_incoming_sompi", pending_incoming_sompi);
    print_kv("available_confirmed_sompi", available_confirmed_sompi);
    print_kv("effective_sompi", effective_sompi);
    let effective_whole = effective_sompi / 100_000_000;
    let effective_frac = effective_sompi % 100_000_000;
    print_kv("effective_kas", format!("{effective_whole}.{effective_frac:08}"));

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

pub async fn cmd_utxos(rpc: &str, address: &str, detail: bool) -> Result<(), String> {
    let address = parse_testnet_address(address)?;
    let client = connect_grpc(rpc).await?;

    let server = client.get_server_info().await.map_err(|err| format!("get_server_info failed: {err}"))?;
    let entries = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .map_err(|err| format!("get_utxos_by_addresses failed: {err}"))?;

    print_header("UTXOs");
    print_kv("network", server.network_id);
    print_kv("synced", server.is_synced);
    print_kv("utxo_index", server.has_utxo_index);
    print_kv("address", address);
    print_kv("utxo_count", entries.len());

    let mut total = 0u64;
    for (idx, entry) in entries.iter().enumerate() {
        total += entry.utxo_entry.amount;
        if detail {
            let locking_script_hex = hex_encode(entry.utxo_entry.script_public_key.script());
            println!(
                "#{idx} txid={} vout={} amount={} coinbase={} daa={} spk_ver={} spk_hex={}",
                entry.outpoint.transaction_id,
                entry.outpoint.index,
                entry.utxo_entry.amount,
                entry.utxo_entry.is_coinbase,
                entry.utxo_entry.block_daa_score,
                entry.utxo_entry.script_public_key.version(),
                locking_script_hex
            );
        }
    }
    print_kv("total_sompi", total);

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

pub async fn cmd_pending_txs(rpc: &str, address: &str) -> Result<(), String> {
    let address = parse_testnet_address(address)?;
    let client = connect_grpc(rpc).await?;
    let entries = client
        .get_mempool_entries_by_addresses(vec![address.clone()], true, false)
        .await
        .map_err(|err| format!("get_mempool_entries_by_addresses failed: {err}"))?;

    #[derive(Default)]
    struct PendingTxRow {
        sending: bool,
        receiving: bool,
        fee: u64,
        orphan: bool,
        inputs: usize,
        outputs: usize,
    }

    let mut rows: BTreeMap<String, PendingTxRow> = BTreeMap::new();
    let mut unknown_txid_rows = 0usize;

    for by_addr in entries {
        for item in by_addr.sending {
            let txid = if let Some(verbose) = item.transaction.verbose_data.as_ref() {
                verbose.transaction_id.to_string()
            } else {
                unknown_txid_rows += 1;
                format!("unknown-sending-{unknown_txid_rows}")
            };
            let row = rows.entry(txid).or_default();
            row.sending = true;
            row.fee = item.fee;
            row.orphan = item.is_orphan;
            row.inputs = item.transaction.inputs.len();
            row.outputs = item.transaction.outputs.len();
        }
        for item in by_addr.receiving {
            let txid = if let Some(verbose) = item.transaction.verbose_data.as_ref() {
                verbose.transaction_id.to_string()
            } else {
                unknown_txid_rows += 1;
                format!("unknown-receiving-{unknown_txid_rows}")
            };
            let row = rows.entry(txid).or_default();
            row.receiving = true;
            row.fee = item.fee;
            row.orphan = item.is_orphan;
            row.inputs = item.transaction.inputs.len();
            row.outputs = item.transaction.outputs.len();
        }
    }

    print_header("Pending Transactions");
    print_kv("address", address);
    print_kv("pending_tx_count", rows.len());
    for (txid, row) in rows {
        let direction = match (row.sending, row.receiving) {
            (true, true) => "both",
            (true, false) => "sending",
            (false, true) => "receiving",
            _ => "unknown",
        };
        println!("  - {txid}");
        println!("    direction={direction} fee={} orphan={} inputs={} outputs={}", row.fee, row.orphan, row.inputs, row.outputs);
    }

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

pub async fn cmd_tx_status(rpc: &str, txid: &str) -> Result<(), String> {
    let txid = TransactionId::from_str(txid).map_err(|err| format!("invalid txid: {err}"))?;
    let client = connect_grpc(rpc).await?;

    print_header("Transaction Status");
    print_kv("txid", txid);
    match client.get_mempool_entry(txid, true, false).await {
        Ok(entry) => {
            print_kv("mempool", "true");
            print_kv("mempool_fee", entry.fee);
            print_kv("mempool_orphan", entry.is_orphan);
            print_kv("mempool_inputs", entry.transaction.inputs.len());
            print_kv("mempool_outputs", entry.transaction.outputs.len());
        }
        Err(err) => {
            print_kv("mempool", "false");
            print_kv("mempool_reason", err);
        }
    }

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

pub async fn cmd_fee_estimate(rpc: &str) -> Result<(), String> {
    let client = connect_grpc(rpc).await?;
    let estimate = client.get_fee_estimate().await.map_err(|err| format!("get_fee_estimate failed: {err}"))?;

    print_header("Fee Estimate");
    print_kv("policy_default", "priority_bucket (fastest)");
    print_kv("priority_feerate_sompi_per_gram", estimate.priority_bucket.feerate);
    print_kv("priority_estimated_seconds", estimate.priority_bucket.estimated_seconds);

    if let Some(bucket) = estimate.normal_buckets.first() {
        print_kv("normal_feerate_sompi_per_gram", bucket.feerate);
        print_kv("normal_estimated_seconds", bucket.estimated_seconds);
    }
    if let Some(bucket) = estimate.low_buckets.first() {
        print_kv("low_feerate_sompi_per_gram", bucket.feerate);
        print_kv("low_estimated_seconds", bucket.estimated_seconds);
    }

    print_kv("normal_bucket_count", estimate.normal_buckets.len());
    print_kv("low_bucket_count", estimate.low_buckets.len());

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

pub async fn cmd_submit_self(rpc: &str, private_key: &str, address: &str, amount_sompi: u64) -> Result<(), String> {
    let address = parse_testnet_address(address)?;
    let keypair = parse_keypair(private_key)?;
    let client = connect_grpc(rpc).await?;
    let fee_policy = resolve_fee_policy(&client).await?;

    let server = client.get_server_info().await.map_err(|err| format!("get_server_info failed: {err}"))?;
    print_header("Submit Self");
    print_kv("network", server.network_id);
    print_kv("synced", server.is_synced);

    let utxos = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .map_err(|err| format!("get_utxos_by_addresses failed: {err}"))?;
    if utxos.is_empty() {
        return Err("no UTXOs for address".to_string());
    }

    let mut selected: Vec<(TransactionOutpoint, UtxoEntry)> = Vec::new();
    let mut total_in = 0u64;
    let mut sorted = utxos;
    sorted.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));

    for item in sorted {
        total_in += item.utxo_entry.amount;
        selected.push((TransactionOutpoint::from(item.outpoint), UtxoEntry::from(item.utxo_entry)));
        let need = amount_sompi + fee_sompi_for_policy(selected.len(), 2, fee_policy);
        if total_in >= need {
            break;
        }
    }

    let tx_fee = fee_sompi_for_policy(selected.len(), 2, fee_policy);
    let required = amount_sompi + tx_fee;
    if total_in < required {
        return Err(format!("insufficient funds: total_in={total_in} required={required}"));
    }

    let change = total_in - required;
    let spk = pay_to_address_script(&address);
    let inputs: Vec<_> = selected
        .iter()
        .map(|(outpoint, _)| TransactionInput::new(*outpoint, vec![], 0, 1))
        .collect();

    let mut outputs = vec![TransactionOutput::new(amount_sompi, spk.clone())];
    if change > 0 {
        outputs.push(TransactionOutput::new(change, spk));
    }

    let unsigned = Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let entries = selected.into_iter().map(|(_, entry)| entry).collect::<Vec<_>>();
    let signed = sign(MutableTransaction::with_entries(unsigned, entries), keypair);

    let txid = client
        .submit_transaction((&signed.tx).into(), false)
        .await
        .map_err(|err| format!("submit_transaction failed: {err}"))?;

    print_kv("submitted_txid", txid);
    print_kv("amount_sompi", amount_sompi);
    print_kv("fee_source", fee_policy.label());
    print_kv("fee_sompi", tx_fee);
    print_kv("change_sompi", change);
    save_tx_history(
        "submit-self",
        &txid.to_string(),
        rpc,
        &address.to_string(),
        format!("amount_sompi={amount_sompi} fee_sompi={tx_fee} change_sompi={change}"),
    );

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

pub async fn cmd_send(
    rpc: &str,
    private_key: &str,
    from_address: &str,
    to_address: &str,
    amount_sompi: u64,
) -> Result<(), String> {
    let from_address = parse_testnet_address(from_address)?;
    let to_address = parse_testnet_address(to_address)?;
    let keypair = parse_keypair(private_key)?;
    let client = connect_grpc(rpc).await?;
    let fee_policy = resolve_fee_policy(&client).await?;

    let server = client.get_server_info().await.map_err(|err| format!("get_server_info failed: {err}"))?;
    print_header("Send");
    print_kv("network", server.network_id);
    print_kv("synced", server.is_synced);
    print_kv("from_address", &from_address);
    print_kv("to_address", &to_address);

    let utxos = client
        .get_utxos_by_addresses(vec![from_address.clone()])
        .await
        .map_err(|err| format!("get_utxos_by_addresses failed: {err}"))?;
    if utxos.is_empty() {
        return Err("no UTXOs for source address".to_string());
    }

    let mut selected: Vec<(TransactionOutpoint, UtxoEntry)> = Vec::new();
    let mut total_in = 0u64;
    let mut sorted = utxos;
    sorted.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));

    for item in sorted {
        total_in += item.utxo_entry.amount;
        selected.push((TransactionOutpoint::from(item.outpoint), UtxoEntry::from(item.utxo_entry)));
        let need = amount_sompi + fee_sompi_for_policy(selected.len(), 2, fee_policy);
        if total_in >= need {
            break;
        }
    }

    let tx_fee = fee_sompi_for_policy(selected.len(), 2, fee_policy);
    let required = amount_sompi + tx_fee;
    if total_in < required {
        return Err(format!("insufficient funds: total_in={total_in} required={required}"));
    }

    let change = total_in - required;
    let to_spk = pay_to_address_script(&to_address);
    let change_spk = pay_to_address_script(&from_address);
    let inputs: Vec<_> = selected
        .iter()
        .map(|(outpoint, _)| TransactionInput::new(*outpoint, vec![], 0, 1))
        .collect();

    let mut outputs = vec![TransactionOutput::new(amount_sompi, to_spk)];
    if change > 0 {
        outputs.push(TransactionOutput::new(change, change_spk));
    }

    let unsigned = Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let entries = selected.into_iter().map(|(_, entry)| entry).collect::<Vec<_>>();
    let signed = sign(MutableTransaction::with_entries(unsigned, entries), keypair);

    let txid = client
        .submit_transaction((&signed.tx).into(), false)
        .await
        .map_err(|err| format!("submit_transaction failed: {err}"))?;

    print_kv("submitted_txid", txid);
    print_kv("amount_sompi", amount_sompi);
    print_kv("fee_source", fee_policy.label());
    print_kv("fee_sompi", tx_fee);
    print_kv("change_sompi", change);
    save_tx_history(
        "send",
        &txid.to_string(),
        rpc,
        &from_address.to_string(),
        format!(
            "to_address={} amount_sompi={} fee_sompi={} change_sompi={}",
            to_address, amount_sompi, tx_fee, change
        ),
    );

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

pub async fn cmd_send_with_payload(
    rpc: &str,
    private_key: &str,
    from_address: &str,
    to_address: &str,
    amount_sompi: u64,
    payload: &[u8],
) -> Result<(), String> {
    let from_address = parse_testnet_address(from_address)?;
    let to_address = parse_testnet_address(to_address)?;
    let keypair = parse_keypair(private_key)?;
    let client = connect_grpc(rpc).await?;
    let fee_policy = resolve_fee_policy(&client).await?;

    let server = client.get_server_info().await.map_err(|err| format!("get_server_info failed: {err}"))?;
    print_header("Send");
    print_kv("network", server.network_id);
    print_kv("synced", server.is_synced);
    print_kv("from_address", &from_address);
    print_kv("to_address", &to_address);

    let utxos = client
        .get_utxos_by_addresses(vec![from_address.clone()])
        .await
        .map_err(|err| format!("get_utxos_by_addresses failed: {err}"))?;
    if utxos.is_empty() {
        return Err("no UTXOs for source address".to_string());
    }

    let mut selected: Vec<(TransactionOutpoint, UtxoEntry)> = Vec::new();
    let mut total_in = 0u64;
    let mut sorted = utxos;
    sorted.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));

    for item in sorted {
        total_in += item.utxo_entry.amount;
        selected.push((TransactionOutpoint::from(item.outpoint), UtxoEntry::from(item.utxo_entry)));
        let need = amount_sompi + fee_sompi_for_policy(selected.len(), 2, fee_policy);
        if total_in >= need {
            break;
        }
    }

    let tx_fee = fee_sompi_for_policy(selected.len(), 2, fee_policy);
    let required = amount_sompi + tx_fee;
    if total_in < required {
        return Err(format!("insufficient funds: total_in={total_in} required={required}"));
    }

    let change = total_in - required;
    let to_spk = pay_to_address_script(&to_address);
    let change_spk = pay_to_address_script(&from_address);
    let inputs: Vec<_> = selected
        .iter()
        .map(|(outpoint, _)| TransactionInput::new(*outpoint, vec![], 0, 1))
        .collect();

    let mut outputs = vec![TransactionOutput::new(amount_sompi, to_spk)];
    if change > 0 {
        outputs.push(TransactionOutput::new(change, change_spk));
    }

    let unsigned = Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, payload.to_vec());
    let entries = selected.into_iter().map(|(_, entry)| entry).collect::<Vec<_>>();
    let signed = sign(MutableTransaction::with_entries(unsigned, entries), keypair);

    let txid = client
        .submit_transaction((&signed.tx).into(), false)
        .await
        .map_err(|err| format!("submit_transaction failed: {err}"))?;

    let payload_hex = payload.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    print_kv("submitted_txid", txid);
    print_kv("amount_sompi", amount_sompi);
    print_kv("fee_source", fee_policy.label());
    print_kv("fee_sompi", tx_fee);
    print_kv("change_sompi", change);
    print_kv("payload_hex", &payload_hex);
    save_tx_history(
        "send-payload",
        &txid.to_string(),
        rpc,
        &from_address.to_string(),
        format!(
            "to_address={} amount_sompi={} fee_sompi={} change_sompi={} payload_hex={}",
            to_address, amount_sompi, tx_fee, change, payload_hex
        ),
    );

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

pub async fn cmd_send_all_self_with_payload(
    rpc: &str,
    private_key: &str,
    address: &str,
    payload: &[u8],
) -> Result<(), String> {
    let address = parse_testnet_address(address)?;
    let keypair = parse_keypair(private_key)?;
    let client = connect_grpc(rpc).await?;
    let fee_policy = resolve_fee_policy(&client).await?;

    let server = client.get_server_info().await.map_err(|err| format!("get_server_info failed: {err}"))?;
    print_header("Send");
    print_kv("network", server.network_id);
    print_kv("synced", server.is_synced);
    print_kv("from_address", &address);
    print_kv("to_address", &address);

    let utxos = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .map_err(|err| format!("get_utxos_by_addresses failed: {err}"))?;
    if utxos.is_empty() {
        return Err("no UTXOs for source address".to_string());
    }

    let mut selected: Vec<(TransactionOutpoint, UtxoEntry)> = Vec::with_capacity(utxos.len());
    let mut total_in = 0u64;
    for item in utxos {
        total_in += item.utxo_entry.amount;
        selected.push((TransactionOutpoint::from(item.outpoint), UtxoEntry::from(item.utxo_entry)));
    }

    let tx_fee = fee_sompi_for_policy(selected.len(), 1, fee_policy);
    if total_in <= tx_fee {
        return Err(format!("insufficient funds: total_in={total_in} required_fee={tx_fee}"));
    }
    let amount_sompi = total_in - tx_fee;

    let spk = pay_to_address_script(&address);
    let inputs: Vec<_> = selected
        .iter()
        .map(|(outpoint, _)| TransactionInput::new(*outpoint, vec![], 0, 1))
        .collect();
    let outputs = vec![TransactionOutput::new(amount_sompi, spk)];

    let unsigned = Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, payload.to_vec());
    let entries = selected.into_iter().map(|(_, entry)| entry).collect::<Vec<_>>();
    let signed = sign(MutableTransaction::with_entries(unsigned, entries), keypair);

    let txid = client
        .submit_transaction((&signed.tx).into(), false)
        .await
        .map_err(|err| format!("submit_transaction failed: {err}"))?;

    let payload_hex = payload.iter().map(|byte| format!("{byte:02x}")).collect::<String>();
    print_kv("submitted_txid", txid);
    print_kv("amount_sompi", amount_sompi);
    print_kv("fee_source", fee_policy.label());
    print_kv("fee_sompi", tx_fee);
    print_kv("change_sompi", 0);
    print_kv("payload_hex", &payload_hex);
    save_tx_history(
        "send-payload",
        &txid.to_string(),
        rpc,
        &address.to_string(),
        format!(
            "to_address={} amount_sompi={} fee_sompi={} change_sompi=0 payload_hex={} amount_mode=all_self",
            address, amount_sompi, tx_fee, payload_hex
        ),
    );

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

fn parse_outpoint_text(outpoint: &str) -> Result<TransactionOutpoint, String> {
    let mut parts = outpoint.split(':');
    let txid_text = parts.next().ok_or_else(|| "outpoint must be in txid:vout format".to_string())?;
    let vout_text = parts.next().ok_or_else(|| "outpoint must be in txid:vout format".to_string())?;
    if parts.next().is_some() {
        return Err("outpoint must be in txid:vout format".to_string());
    }
    let txid = TransactionId::from_str(txid_text).map_err(|err| format!("invalid outpoint txid: {err}"))?;
    let vout = vout_text.parse::<u32>().map_err(|err| format!("invalid outpoint vout: {err}"))?;
    Ok(TransactionOutpoint::new(txid, vout))
}

fn load_compiled_contract(compiled_path: &str) -> Result<CompiledContract, String> {
    let compiled_json =
        fs::read_to_string(compiled_path).map_err(|err| format!("failed to read compiled json {compiled_path}: {err}"))?;
    serde_json::from_str(&compiled_json).map_err(|err| format!("failed to parse compiled json {compiled_path}: {err}"))
}

fn load_function_args(function_args_path: &str) -> Result<Vec<Expr>, String> {
    if function_args_path == "-" {
        return Ok(Vec::new());
    }
    let args_json =
        fs::read_to_string(function_args_path).map_err(|err| format!("failed to read function args {function_args_path}: {err}"))?;
    serde_json::from_str::<Vec<Expr>>(&args_json).map_err(|err| format!("failed to parse function args {function_args_path}: {err}"))
}

fn load_spend_outputs(outputs_path: &str) -> Result<Vec<SpendOutputSpec>, String> {
    let outputs_json = fs::read_to_string(outputs_path).map_err(|err| format!("failed to read outputs file {outputs_path}: {err}"))?;
    let output_rows = serde_json::from_str::<Vec<SpendOutputSpecInput>>(&outputs_json)
        .map_err(|err| format!("failed to parse outputs file {outputs_path}: {err}"))?;
    let amount_unit = AmountUnit::from_env()?;
    let mut outputs_spec = Vec::with_capacity(output_rows.len());
    for (index, row) in output_rows.into_iter().enumerate() {
        let destination = match (row.address, row.locking_bytecode_hex) {
            (Some(address), None) => SpendOutputDestination::Address(address),
            (None, Some(locking_bytecode_hex)) => SpendOutputDestination::LockingBytecodeHex(locking_bytecode_hex),
            (Some(_), Some(_)) => {
                return Err(format!(
                    "outputs[{index}] has both address and locking_bytecode_hex; keep exactly one destination"
                ))
            }
            (None, None) => {
                return Err(format!(
                    "outputs[{index}] missing destination (use address or locking_bytecode_hex)"
                ))
            }
        };
        let amount_sompi = match (row.amount_sompi, row.amount.as_deref()) {
            (Some(sompi), None) => sompi,
            (None, Some(amount_text)) => match amount_unit {
                AmountUnit::Sompi => amount_text
                    .parse::<u64>()
                    .map_err(|err| format!("outputs[{index}] invalid amount sompi: {err}"))?,
                AmountUnit::Kas => {
                    parse_kas_to_sompi(amount_text).map_err(|err| format!("outputs[{index}] invalid amount kas: {err}"))?
                }
            },
            (Some(_), Some(_)) => {
                return Err(format!(
                    "outputs[{index}] has both amount_sompi and amount; keep exactly one"
                ))
            }
            (None, None) => {
                return Err(format!(
                    "outputs[{index}] missing amount field (use amount_sompi or amount)"
                ))
            }
        };
        outputs_spec.push(SpendOutputSpec {
            destination,
            amount_sompi,
        });
    }
    if outputs_spec.is_empty() {
        return Err("outputs file must contain at least one output".to_string());
    }
    Ok(outputs_spec)
}

fn build_spend_outputs(spec: Vec<SpendOutputSpec>) -> Result<(Vec<TransactionOutput>, u64), String> {
    let mut total_outputs = 0u64;
    let mut outputs = Vec::with_capacity(spec.len());
    for item in spec {
        total_outputs = total_outputs.saturating_add(item.amount_sompi);
        let spk = match item.destination {
            SpendOutputDestination::Address(address) => {
                let parsed = parse_testnet_address(&address)?;
                pay_to_address_script(&parsed)
            }
            SpendOutputDestination::LockingBytecodeHex(locking_bytecode_hex) => {
                let script = decode_hex_bytes(&locking_bytecode_hex)?;
                ScriptPublicKey::from_vec(0, script)
            }
        };
        outputs.push(TransactionOutput::new(item.amount_sompi, spk));
    }
    Ok((outputs, total_outputs))
}

fn summarize_spend_outputs(spec: &[SpendOutputSpec]) -> String {
    spec.iter()
        .map(|item| match &item.destination {
            SpendOutputDestination::Address(address) => format!("address={address}:{}", item.amount_sompi),
            SpendOutputDestination::LockingBytecodeHex(locking_bytecode_hex) => {
                format!("locking_bytecode_hex={locking_bytecode_hex}:{}", item.amount_sompi)
            }
        })
        .collect::<Vec<_>>()
        .join("|")
}

fn build_spend_contract_tx(
    compiled: &CompiledContract,
    outpoint: TransactionOutpoint,
    input_amount_sompi: u64,
    sig_prefix: Vec<u8>,
    outputs: Vec<TransactionOutput>,
) -> Result<MutableTransaction, String> {
    let signature_script = pay_to_script_hash_signature_script(compiled.script.clone(), sig_prefix)
        .map_err(|err| format!("failed to build p2sh signature script: {err}"))?;
    let input = TransactionInput::new(outpoint, signature_script, 0, 1);
    let unsigned = Transaction::new(TX_VERSION, vec![input], outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let locking_spk = pay_to_script_hash_script(&compiled.script);
    let entry = UtxoEntry::new(input_amount_sompi, locking_spk, 0, false, None);
    Ok(MutableTransaction::with_entries(unsigned.into(), vec![entry]))
}

fn resolve_signed_arg_placeholders(expr: Expr, pubkey: &[u8], signature: &[u8]) -> Expr {
    match expr {
        Expr::Identifier(name) => match name.as_str() {
            "$pubkey" => Expr::Bytes(pubkey.to_vec()),
            "$sig" => Expr::Bytes(signature.to_vec()),
            _ => Expr::Identifier(name),
        },
        Expr::Array(items) => Expr::Array(
            items
                .into_iter()
                .map(|item| resolve_signed_arg_placeholders(item, pubkey, signature))
                .collect(),
        ),
        other => other,
    }
}

pub async fn cmd_spend_contract(
    rpc: &str,
    compiled_path: &str,
    outpoint: &str,
    input_amount_sompi: u64,
    function_name: &str,
    function_args_path: &str,
    outputs_path: &str,
) -> Result<(), String> {
    let function_args = load_function_args(function_args_path)?;
    cmd_spend_contract_with_args(
        rpc,
        compiled_path,
        outpoint,
        input_amount_sompi,
        function_name,
        function_args,
        outputs_path,
        function_args_path,
    )
    .await
}

pub async fn cmd_spend_contract_with_args(
    rpc: &str,
    compiled_path: &str,
    outpoint: &str,
    input_amount_sompi: u64,
    function_name: &str,
    function_args: Vec<Expr>,
    outputs_path: &str,
    function_args_label: &str,
) -> Result<(), String> {
    let outputs_spec = load_spend_outputs(outputs_path)?
        .into_iter()
        .map(|item| (item.destination, Some(item.amount_sompi)))
        .collect::<Vec<_>>();
    cmd_spend_contract_with_args_and_outputs(
        rpc,
        compiled_path,
        outpoint,
        input_amount_sompi,
        function_name,
        function_args,
        outputs_spec,
        function_args_label,
        outputs_path,
    )
    .await
}

pub async fn cmd_spend_contract_with_args_and_outputs(
    rpc: &str,
    compiled_path: &str,
    outpoint: &str,
    input_amount_sompi: u64,
    function_name: &str,
    function_args: Vec<Expr>,
    outputs_spec: Vec<(SpendOutputDestination, Option<u64>)>,
    function_args_label: &str,
    outputs_label: &str,
) -> Result<(), String> {
    if input_amount_sompi == 0 {
        return Err("input_amount_sompi must be greater than 0".to_string());
    }

    let outpoint = parse_outpoint_text(outpoint)?;
    let compiled = load_compiled_contract(compiled_path)?;
    if outputs_spec.is_empty() {
        return Err("at least one output is required".to_string());
    }
    let client = connect_grpc(rpc).await?;
    let fee_policy = resolve_fee_policy(&client).await?;
    let output_count = outputs_spec.len();
    let recommended_fee_sompi = fee_sompi_for_policy(1, output_count, fee_policy);

    let mut all_index: Option<usize> = None;
    let mut explicit_total = 0u64;
    for (index, (_, amount)) in outputs_spec.iter().enumerate() {
        if let Some(value) = amount {
            explicit_total = explicit_total.saturating_add(*value);
        } else if all_index.is_some() {
            return Err("only one output can use `all` amount".to_string());
        } else {
            all_index = Some(index);
        }
    }

    let mut resolved_outputs = Vec::with_capacity(outputs_spec.len());
    let mut auto_fee_deducted_sompi: Option<u64> = None;
    let guided_outputs_mode = outputs_label == "<interactive>";
    let fee_sompi = if let Some(all_idx) = all_index {
        let needed = explicit_total.saturating_add(recommended_fee_sompi);
        if needed > input_amount_sompi {
            return Err(format!(
                "outputs + fastest fee exceed input amount: explicit_outputs_total_sompi={explicit_total} recommended_fee_sompi={recommended_fee_sompi} input_amount_sompi={input_amount_sompi}"
            ));
        }
        let all_amount = input_amount_sompi - needed;
        if all_amount == 0 {
            return Err(
                "resolved `all` output amount is 0; reduce other outputs or increase input amount"
                    .to_string(),
            );
        }
        for (index, (destination, amount)) in outputs_spec.into_iter().enumerate() {
            let resolved_amount = if index == all_idx {
                all_amount
            } else {
                amount.unwrap_or(0)
            };
            resolved_outputs.push((destination, resolved_amount));
        }
        recommended_fee_sompi
    } else {
        if explicit_total > input_amount_sompi {
            return Err(format!(
                "outputs exceed input amount: outputs_total_sompi={explicit_total} input_amount_sompi={input_amount_sompi}"
            ));
        }
        for (destination, amount) in outputs_spec {
            resolved_outputs.push((destination, amount.unwrap_or(0)));
        }
        let implied_fee = input_amount_sompi - explicit_total;
        if implied_fee < recommended_fee_sompi {
            if guided_outputs_mode {
                let shortfall = recommended_fee_sompi - implied_fee;
                let last = resolved_outputs
                    .last_mut()
                    .ok_or_else(|| "at least one output is required".to_string())?;
                if last.1 <= shortfall {
                    return Err(format!(
                        "fee too low for fastest policy and auto-deduct failed: fee_sompi={implied_fee} recommended_fee_sompi={recommended_fee_sompi} shortfall_sompi={shortfall} last_output_amount_sompi={} (reduce outputs or use `all`/`max`)",
                        last.1
                    ));
                }
                last.1 -= shortfall;
                auto_fee_deducted_sompi = Some(shortfall);
                recommended_fee_sompi
            } else {
                return Err(format!(
                    "fee too low for fastest policy: fee_sompi={implied_fee} recommended_fee_sompi={recommended_fee_sompi} (adjust outputs total down)"
                ));
            }
        } else {
            implied_fee
        }
    };

    let outputs_spec = resolved_outputs
        .into_iter()
        .map(|(destination, amount_sompi)| SpendOutputSpec { destination, amount_sompi })
        .collect::<Vec<_>>();
    let outputs_summary = summarize_spend_outputs(&outputs_spec);
    let (outputs, total_outputs) = build_spend_outputs(outputs_spec)?;
    if total_outputs > input_amount_sompi {
        return Err(format!(
            "outputs exceed input amount: outputs_total_sompi={total_outputs} input_amount_sompi={input_amount_sompi}"
        ));
    }

    let sig_prefix = compiled
        .build_sig_script(function_name, function_args)
        .map_err(|err| format!("failed to build signature script: {err}"))?;
    let tx = build_spend_contract_tx(&compiled, outpoint, input_amount_sompi, sig_prefix, outputs)?;
    let txid = client
        .submit_transaction((&(*tx.tx)).into(), false)
        .await
        .map_err(|err| format!("submit_transaction failed: {err}"))?;

    print_header("Spend Contract");
    print_kv("submitted_txid", txid);
    print_kv("contract_name", &compiled.contract_name);
    print_kv("spent_outpoint", format!("{}:{}", outpoint.transaction_id, outpoint.index));
    print_kv("function", function_name);
    print_kv("outputs_total_sompi", total_outputs);
    print_kv("fee_source", fee_policy.label());
    print_kv("recommended_fee_sompi", recommended_fee_sompi);
    print_kv("fee_sompi", fee_sompi);
    if let Some(shortfall) = auto_fee_deducted_sompi {
        print_kv("auto_fee_deducted_from_last_output_sompi", shortfall);
    }
    print_kv("output_count", tx.tx.outputs.len());

    save_tx_history(
        "spend-contract",
        &txid.to_string(),
        rpc,
        "contract-p2sh",
        format!(
            "contract={} outpoint={}:{} function={} input_amount_sompi={} outputs_total_sompi={} fee_source={} recommended_fee_sompi={} fee_sompi={} auto_fee_deducted_sompi={} outputs_file={} outputs={} args_file={}",
            compiled.contract_name,
            outpoint.transaction_id,
            outpoint.index,
            function_name,
            input_amount_sompi,
            total_outputs,
            fee_policy.label(),
            recommended_fee_sompi,
            fee_sompi,
            auto_fee_deducted_sompi.unwrap_or(0),
            outputs_label,
            outputs_summary,
            function_args_label
        ),
    );

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

pub async fn cmd_spend_contract_signed(
    rpc: &str,
    private_key: &str,
    compiled_path: &str,
    outpoint: &str,
    input_amount_sompi: u64,
    function_name: &str,
    function_args_path: &str,
    outputs_path: &str,
) -> Result<(), String> {
    if input_amount_sompi == 0 {
        return Err("input_amount_sompi must be greater than 0".to_string());
    }

    let outpoint = parse_outpoint_text(outpoint)?;
    let compiled = load_compiled_contract(compiled_path)?;
    let keypair = parse_keypair(private_key)?;
    let pubkey = keypair.x_only_public_key().0.serialize();
    let function_args_raw = load_function_args(function_args_path)?;
    let outputs_spec = load_spend_outputs(outputs_path)?;
    let outputs_summary = summarize_spend_outputs(&outputs_spec);
    let (outputs, total_outputs) = build_spend_outputs(outputs_spec)?;
    if total_outputs > input_amount_sompi {
        return Err(format!(
            "outputs exceed input amount: outputs_total_sompi={total_outputs} input_amount_sompi={input_amount_sompi}"
        ));
    }
    let fee_sompi = input_amount_sompi - total_outputs;
    let client = connect_grpc(rpc).await?;
    let fee_policy = resolve_fee_policy(&client).await?;
    let recommended_fee_sompi = fee_sompi_for_policy(1, outputs.len(), fee_policy);
    if fee_sompi < recommended_fee_sompi {
        return Err(format!(
            "fee too low for fastest policy: fee_sompi={fee_sompi} recommended_fee_sompi={recommended_fee_sompi} (adjust outputs total down)"
        ));
    }

    let placeholder_tx = build_spend_contract_tx(
        &compiled,
        outpoint,
        input_amount_sompi,
        vec![],
        outputs.clone(),
    )?;
    let reused_values = SigHashReusedValuesUnsync::new();
    let sig_hash = calc_schnorr_signature_hash(&placeholder_tx.as_verifiable(), 0, SIG_HASH_ALL, &reused_values);
    let msg = Message::from_digest_slice(&sig_hash.as_bytes())
        .map_err(|err| format!("failed to build signature message: {err}"))?;
    let schnorr_sig = keypair.sign_schnorr(msg);
    let mut signature = Vec::with_capacity(65);
    signature.extend_from_slice(schnorr_sig.as_ref());
    signature.push(SIG_HASH_ALL.to_u8());

    let function_args = function_args_raw
        .into_iter()
        .map(|expr| resolve_signed_arg_placeholders(expr, &pubkey, &signature))
        .collect::<Vec<_>>();
    let sig_prefix = compiled
        .build_sig_script(function_name, function_args)
        .map_err(|err| format!("failed to build signature script: {err}"))?;
    let tx = build_spend_contract_tx(&compiled, outpoint, input_amount_sompi, sig_prefix, outputs)?;
    let txid = client
        .submit_transaction((&(*tx.tx)).into(), false)
        .await
        .map_err(|err| format!("submit_transaction failed: {err}"))?;

    print_header("Spend Contract Signed");
    print_kv("submitted_txid", txid);
    print_kv("contract_name", &compiled.contract_name);
    print_kv("spent_outpoint", format!("{}:{}", outpoint.transaction_id, outpoint.index));
    print_kv("function", function_name);
    print_kv("outputs_total_sompi", total_outputs);
    print_kv("fee_source", fee_policy.label());
    print_kv("recommended_fee_sompi", recommended_fee_sompi);
    print_kv("fee_sompi", fee_sompi);
    print_kv("output_count", tx.tx.outputs.len());

    save_tx_history(
        "spend-contract-signed",
        &txid.to_string(),
        rpc,
        "contract-p2sh",
        format!(
            "contract={} outpoint={}:{} function={} input_amount_sompi={} outputs_total_sompi={} fee_source={} recommended_fee_sompi={} fee_sompi={} outputs_file={} outputs={} args_file={} signer_pubkey={}",
            compiled.contract_name,
            outpoint.transaction_id,
            outpoint.index,
            function_name,
            input_amount_sompi,
            total_outputs,
            fee_policy.label(),
            recommended_fee_sompi,
            fee_sompi,
            outputs_path,
            outputs_summary,
            function_args_path,
            hex_encode(&pubkey)
        ),
    );

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

pub async fn cmd_compound_utxos(rpc: &str, private_key: &str, address: &str, max_inputs: usize) -> Result<(), String> {
    let address = parse_testnet_address(address)?;
    let keypair = parse_keypair(private_key)?;
    let client = connect_grpc(rpc).await?;
    let fee_policy = resolve_fee_policy(&client).await?;
    if max_inputs == 0 {
        return Err("max_inputs must be at least 1".to_string());
    }

    let server = client.get_server_info().await.map_err(|err| format!("get_server_info failed: {err}"))?;
    print_header("Compound UTXOs");
    print_kv("network", server.network_id);
    print_kv("synced", server.is_synced);

    let utxos = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .map_err(|err| format!("get_utxos_by_addresses failed: {err}"))?;
    if utxos.is_empty() {
        return Err("no UTXOs for address".to_string());
    }

    let mempool_entries = client
        .get_mempool_entries_by_addresses(vec![address.clone()], true, false)
        .await
        .map_err(|err| format!("get_mempool_entries_by_addresses failed: {err}"))?;
    let mut mempool_spent_outpoints = HashSet::new();
    for by_addr in mempool_entries {
        for sending in by_addr.sending {
            for input in sending.transaction.inputs {
                mempool_spent_outpoints.insert((input.previous_outpoint.transaction_id, input.previous_outpoint.index));
            }
        }
    }

    let mut selected: Vec<(TransactionOutpoint, UtxoEntry)> = Vec::new();
    let mut total_in = 0u64;
    let mut skipped_mempool_spent = 0usize;

    let mut sorted = utxos;
    sorted.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));

    for item in sorted {
        if mempool_spent_outpoints.contains(&(item.outpoint.transaction_id, item.outpoint.index)) {
            skipped_mempool_spent += 1;
            continue;
        }
        if selected.len() >= max_inputs {
            break;
        }
        total_in += item.utxo_entry.amount;
        selected.push((TransactionOutpoint::from(item.outpoint), UtxoEntry::from(item.utxo_entry)));
    }
    if selected.is_empty() {
        return Err(format!(
            "no available confirmed inputs after filtering mempool-spent outputs (skipped={skipped_mempool_spent})"
        ));
    }

    let tx_fee = fee_sompi_for_policy(selected.len(), 1, fee_policy);
    if total_in <= tx_fee {
        return Err(format!("insufficient funds: total_in={total_in} fee_sompi={tx_fee}"));
    }

    let output_amount = total_in - tx_fee;
    let spk = pay_to_address_script(&address);
    let inputs: Vec<_> = selected
        .iter()
        .map(|(outpoint, _)| TransactionInput::new(*outpoint, vec![], 0, 1))
        .collect();
    let outputs = vec![TransactionOutput::new(output_amount, spk)];

    let unsigned = Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let entries = selected.into_iter().map(|(_, entry)| entry).collect::<Vec<_>>();
    let signed = sign(MutableTransaction::with_entries(unsigned, entries), keypair);

    let txid = client
        .submit_transaction((&signed.tx).into(), false)
        .await
        .map_err(|err| format!("submit_transaction failed: {err}"))?;

    print_kv("submitted_txid", txid);
    print_kv("used_inputs", signed.tx.inputs.len());
    print_kv("max_inputs", max_inputs);
    print_kv("skipped_mempool_spent", skipped_mempool_spent);
    print_kv("output_count", signed.tx.outputs.len());
    print_kv("fee_source", fee_policy.label());
    print_kv("output_amount_sompi", output_amount);
    print_kv("fee_sompi", tx_fee);
    save_tx_history(
        "compound-utxos",
        &txid.to_string(),
        rpc,
        &address.to_string(),
        format!(
            "used_inputs={} max_inputs={} output_amount_sompi={} fee_sompi={} skipped_mempool_spent={}",
            signed.tx.inputs.len(),
            max_inputs,
            output_amount,
            tx_fee,
            skipped_mempool_spent
        ),
    );

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

pub async fn cmd_deploy_covenant(
    rpc: &str,
    private_key: &str,
    address: &str,
    compiled_path: &str,
    amount_sompi: u64,
) -> Result<(), String> {
    let address = parse_testnet_address(address)?;
    let keypair = parse_keypair(private_key)?;
    let client = connect_grpc(rpc).await?;
    let fee_policy = resolve_fee_policy(&client).await?;

    let compiled_json =
        fs::read_to_string(compiled_path).map_err(|err| format!("failed to read compiled json {compiled_path}: {err}"))?;
    let compiled: CompiledContract =
        serde_json::from_str(&compiled_json).map_err(|err| format!("failed to parse compiled json {compiled_path}: {err}"))?;

    let utxos = client
        .get_utxos_by_addresses(vec![address.clone()])
        .await
        .map_err(|err| format!("get_utxos_by_addresses failed: {err}"))?;
    if utxos.is_empty() {
        return Err("no UTXOs for source address".to_string());
    }

    let mut selected: Vec<(TransactionOutpoint, UtxoEntry)> = Vec::new();
    let mut total_in = 0u64;
    let mut sorted = utxos;
    sorted.sort_by(|a, b| b.utxo_entry.amount.cmp(&a.utxo_entry.amount));

    for item in sorted {
        total_in += item.utxo_entry.amount;
        selected.push((TransactionOutpoint::from(item.outpoint), UtxoEntry::from(item.utxo_entry)));
        let need = amount_sompi + fee_sompi_for_policy(selected.len(), 2, fee_policy);
        if total_in >= need {
            break;
        }
    }

    let tx_fee = fee_sompi_for_policy(selected.len(), 2, fee_policy);
    let required = amount_sompi + tx_fee;
    if total_in < required {
        return Err(format!("insufficient funds: total_in={total_in} required={required}"));
    }

    let change = total_in - required;
    let source_spk = pay_to_address_script(&address);
    let covenant_spk = pay_to_script_hash_script(&compiled.script);
    let contract_address = extract_script_pub_key_address(&covenant_spk, address.prefix)
        .map_err(|err| format!("failed to derive contract address from locking script: {err}"))?;

    let inputs: Vec<_> = selected
        .iter()
        .map(|(outpoint, _)| TransactionInput::new(*outpoint, vec![], 0, 1))
        .collect();

    let mut outputs = vec![TransactionOutput::new(amount_sompi, covenant_spk)];
    if change > 0 {
        outputs.push(TransactionOutput::new(change, source_spk));
    }

    let unsigned = Transaction::new(TX_VERSION, inputs, outputs, 0, SUBNETWORK_ID_NATIVE, 0, vec![]);
    let entries = selected.into_iter().map(|(_, entry)| entry).collect::<Vec<_>>();
    let signed = sign(MutableTransaction::with_entries(unsigned, entries), keypair);

    let txid = client
        .submit_transaction((&signed.tx).into(), false)
        .await
        .map_err(|err| format!("submit_transaction failed: {err}"))?;

    print_header("Deploy Covenant");
    print_kv("submitted_txid", txid);
    print_kv("contract_name", &compiled.contract_name);
    print_kv("contract_address", &contract_address);
    print_kv("contract_output_outpoint", format!("{txid}:0"));
    print_kv("locking_type", "p2sh");
    print_kv("amount_sompi", amount_sompi);
    print_kv("fee_source", fee_policy.label());
    print_kv("fee_sompi", tx_fee);
    print_kv("change_sompi", change);
    save_tx_history(
        "deploy-covenant",
        &txid.to_string(),
        rpc,
        &address.to_string(),
        format!(
            "contract_name={} compiled={} contract_address={} contract_output_outpoint={}:0 amount_sompi={} fee_source={} fee_sompi={} change_sompi={}",
            compiled.contract_name, compiled_path, contract_address, txid, amount_sompi, fee_policy.label(), tx_fee, change
        ),
    );

    client.disconnect().await.map_err(|err| format!("disconnect failed: {err}"))?;
    Ok(())
}

fn parse_keypair(private_key_hex: &str) -> Result<Keypair, String> {
    let bytes = decode_hex_32(private_key_hex)?;
    let secret = SecretKey::from_slice(&bytes).map_err(|err| format!("invalid private key: {err}"))?;
    Ok(Keypair::from_secret_key(secp256k1::SECP256K1, &secret))
}

fn decode_hex_32(input: &str) -> Result<[u8; 32], String> {
    let value = input.strip_prefix("0x").unwrap_or(input);
    if value.len() != 64 {
        return Err("private key must be 32-byte hex".to_string());
    }
    let mut out = [0u8; 32];
    for i in 0..32 {
        let idx = i * 2;
        out[i] = u8::from_str_radix(&value[idx..idx + 2], 16).map_err(|err| format!("invalid hex: {err}"))?;
    }
    Ok(out)
}

fn fee_sompi(num_inputs: usize, num_outputs: usize) -> u64 {
    let estimated_mass = 200u64 + 34u64 * num_outputs as u64 + 1000u64 * num_inputs as u64;
    10u64 * estimated_mass
}

#[derive(Debug, Clone, Copy)]
enum FeePolicy {
    RpcFastest(f64),
    Heuristic,
}

impl FeePolicy {
    fn label(&self) -> &'static str {
        match self {
            FeePolicy::RpcFastest(_) => "rpc-fastest",
            FeePolicy::Heuristic => "heuristic",
        }
    }
}

fn estimated_mass(num_inputs: usize, num_outputs: usize) -> u64 {
    200u64 + 34u64 * num_outputs as u64 + 1000u64 * num_inputs as u64
}

fn fee_sompi_for_policy(num_inputs: usize, num_outputs: usize, policy: FeePolicy) -> u64 {
    match policy {
        FeePolicy::RpcFastest(feerate) => {
            let mass = estimated_mass(num_inputs, num_outputs) as f64;
            let fee = (feerate * mass).ceil();
            if fee.is_finite() && fee > 0.0 {
                fee as u64
            } else {
                fee_sompi(num_inputs, num_outputs)
            }
        }
        FeePolicy::Heuristic => fee_sompi(num_inputs, num_outputs),
    }
}

async fn resolve_fee_policy(client: &GrpcClient) -> Result<FeePolicy, String> {
    let estimate = client
        .get_fee_estimate()
        .await
        .map_err(|err| format!("get_fee_estimate failed: {err}"))?;
    let feerate = estimate.priority_bucket.feerate;
    if feerate.is_finite() && feerate > 0.0 {
        return Ok(FeePolicy::RpcFastest(feerate));
    }
    Ok(FeePolicy::Heuristic)
}

fn hex_encode(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect::<String>()
}

fn default_sil_output_path(source: &str) -> String {
    if let Some(stripped) = source.strip_suffix(".sil") {
        format!("{stripped}.json")
    } else {
        format!("{source}.json")
    }
}
