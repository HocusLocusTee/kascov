use kaspa_consensus_core::{
    constants::TX_VERSION,
    hashing::sighash::{SigHashReusedValuesUnsync, calc_schnorr_signature_hash},
    hashing::sighash_type::SIG_HASH_ALL,
    sign::sign,
    subnets::SUBNETWORK_ID_NATIVE,
    tx::{MutableTransaction, Transaction, TransactionId, TransactionInput, TransactionOutpoint, TransactionOutput, UtxoEntry},
};
use kaspa_grpc_client::GrpcClient;
use kaspa_rpc_core::{api::rpc::RpcApi, notify::mode::NotificationMode};
use kaspa_txscript::{pay_to_address_script, pay_to_script_hash_script, pay_to_script_hash_signature_script};
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

#[derive(Debug, Deserialize)]
struct SpendOutputSpec {
    address: String,
    amount_sompi: u64,
}

pub fn cmd_compile_sil(source: &str, out: Option<&str>, constructor_args_path: Option<&str>) -> Result<(), String> {
    let source_text = fs::read_to_string(source).map_err(|err| format!("failed to read source file {source}: {err}"))?;

    let constructor_args = if let Some(path) = constructor_args_path {
        let json = fs::read_to_string(path).map_err(|err| format!("failed to read constructor args {path}: {err}"))?;
        serde_json::from_str::<Vec<Expr>>(&json).map_err(|err| format!("failed to parse constructor args {path}: {err}"))?
    } else {
        Vec::new()
    };

    let compiled =
        compile_contract(&source_text, &constructor_args, CompileOptions::default()).map_err(|err| format!("compile error: {err}"))?;

    let output_path = out
        .map(|value| value.to_string())
        .unwrap_or_else(|| default_sil_output_path(source));
    let json = serde_json::to_string_pretty(&compiled).map_err(|err| format!("failed to serialize output: {err}"))?;
    fs::write(&output_path, json).map_err(|err| format!("failed to write output {output_path}: {err}"))?;
    println!("compiled={source}");
    println!("output={output_path}");
    Ok(())
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
        cmd_compile_sil(
            &source_path.to_string_lossy(),
            Some(&output_path.to_string_lossy()),
            None,
        )?;
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

pub async fn cmd_submit_self(rpc: &str, private_key: &str, address: &str, amount_sompi: u64) -> Result<(), String> {
    let address = parse_testnet_address(address)?;
    let keypair = parse_keypair(private_key)?;
    let fee_override = fee_override_from_env()?;
    let client = connect_grpc(rpc).await?;

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
        let need = amount_sompi + fee_sompi_with_override(selected.len(), 2, fee_override);
        if total_in >= need {
            break;
        }
    }

    let tx_fee = fee_sompi_with_override(selected.len(), 2, fee_override);
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
    let fee_override = fee_override_from_env()?;
    let client = connect_grpc(rpc).await?;

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
        let need = amount_sompi + fee_sompi_with_override(selected.len(), 2, fee_override);
        if total_in >= need {
            break;
        }
    }

    let tx_fee = fee_sompi_with_override(selected.len(), 2, fee_override);
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
    let outputs_spec = serde_json::from_str::<Vec<SpendOutputSpec>>(&outputs_json)
        .map_err(|err| format!("failed to parse outputs file {outputs_path}: {err}"))?;
    if outputs_spec.is_empty() {
        return Err("outputs file must contain at least one output".to_string());
    }
    Ok(outputs_spec)
}

fn build_spend_outputs(spec: Vec<SpendOutputSpec>) -> Result<(Vec<TransactionOutput>, u64), String> {
    let mut total_outputs = 0u64;
    let mut outputs = Vec::with_capacity(spec.len());
    for item in spec {
        let address = parse_testnet_address(&item.address)?;
        total_outputs = total_outputs.saturating_add(item.amount_sompi);
        outputs.push(TransactionOutput::new(item.amount_sompi, pay_to_address_script(&address)));
    }
    Ok((outputs, total_outputs))
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
    if input_amount_sompi == 0 {
        return Err("input_amount_sompi must be greater than 0".to_string());
    }

    let outpoint = parse_outpoint_text(outpoint)?;
    let compiled = load_compiled_contract(compiled_path)?;
    let function_args = load_function_args(function_args_path)?;
    let (outputs, total_outputs) = build_spend_outputs(load_spend_outputs(outputs_path)?)?;
    if total_outputs > input_amount_sompi {
        return Err(format!(
            "outputs exceed input amount: outputs_total_sompi={total_outputs} input_amount_sompi={input_amount_sompi}"
        ));
    }
    let fee_sompi = input_amount_sompi - total_outputs;

    let sig_prefix = compiled
        .build_sig_script(function_name, function_args)
        .map_err(|err| format!("failed to build signature script: {err}"))?;
    let tx = build_spend_contract_tx(&compiled, outpoint, input_amount_sompi, sig_prefix, outputs)?;

    let client = connect_grpc(rpc).await?;
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
    print_kv("fee_sompi", fee_sompi);
    print_kv("output_count", tx.tx.outputs.len());

    save_tx_history(
        "spend-contract",
        &txid.to_string(),
        rpc,
        "contract-p2sh",
        format!(
            "contract={} outpoint={}:{} function={} input_amount_sompi={} outputs_total_sompi={} fee_sompi={} outputs_file={} args_file={}",
            compiled.contract_name,
            outpoint.transaction_id,
            outpoint.index,
            function_name,
            input_amount_sompi,
            total_outputs,
            fee_sompi,
            outputs_path,
            function_args_path
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
    let (outputs, total_outputs) = build_spend_outputs(load_spend_outputs(outputs_path)?)?;
    if total_outputs > input_amount_sompi {
        return Err(format!(
            "outputs exceed input amount: outputs_total_sompi={total_outputs} input_amount_sompi={input_amount_sompi}"
        ));
    }
    let fee_sompi = input_amount_sompi - total_outputs;

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

    let client = connect_grpc(rpc).await?;
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
    print_kv("fee_sompi", fee_sompi);
    print_kv("output_count", tx.tx.outputs.len());

    save_tx_history(
        "spend-contract-signed",
        &txid.to_string(),
        rpc,
        "contract-p2sh",
        format!(
            "contract={} outpoint={}:{} function={} input_amount_sompi={} outputs_total_sompi={} fee_sompi={} outputs_file={} args_file={} signer_pubkey={}",
            compiled.contract_name,
            outpoint.transaction_id,
            outpoint.index,
            function_name,
            input_amount_sompi,
            total_outputs,
            fee_sompi,
            outputs_path,
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
    let fee_override = fee_override_from_env()?;
    let client = connect_grpc(rpc).await?;
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

    let tx_fee = fee_sompi_with_override(selected.len(), 1, fee_override);
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
    let fee_override = fee_override_from_env()?;
    let client = connect_grpc(rpc).await?;

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
        let need = amount_sompi + fee_sompi_with_override(selected.len(), 2, fee_override);
        if total_in >= need {
            break;
        }
    }

    let tx_fee = fee_sompi_with_override(selected.len(), 2, fee_override);
    let required = amount_sompi + tx_fee;
    if total_in < required {
        return Err(format!("insufficient funds: total_in={total_in} required={required}"));
    }

    let change = total_in - required;
    let source_spk = pay_to_address_script(&address);
    let covenant_spk = pay_to_script_hash_script(&compiled.script);

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
    print_kv("contract_output_outpoint", format!("{txid}:0"));
    print_kv("locking_type", "p2sh");
    print_kv("amount_sompi", amount_sompi);
    print_kv("fee_sompi", tx_fee);
    print_kv("change_sompi", change);
    save_tx_history(
        "deploy-covenant",
        &txid.to_string(),
        rpc,
        &address.to_string(),
        format!(
            "contract_name={} compiled={} amount_sompi={} fee_sompi={} change_sompi={}",
            compiled.contract_name, compiled_path, amount_sompi, tx_fee, change
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

fn fee_override_from_env() -> Result<Option<u64>, String> {
    match std::env::var("KASPA_FEE_SOMPI") {
        Ok(value) => {
            let fee = value
                .parse::<u64>()
                .map_err(|err| format!("invalid KASPA_FEE_SOMPI value '{value}': {err}"))?;
            Ok(Some(fee))
        }
        Err(std::env::VarError::NotPresent) => Ok(None),
        Err(err) => Err(format!("failed reading KASPA_FEE_SOMPI: {err}")),
    }
}

fn fee_sompi_with_override(num_inputs: usize, num_outputs: usize, fee_override: Option<u64>) -> u64 {
    fee_override.unwrap_or_else(|| fee_sompi(num_inputs, num_outputs))
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
