use rustyline::error::ReadlineError;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::commands::{
    cmd_balance, cmd_compile_contracts, cmd_compile_sil, cmd_compound_utxos, cmd_deploy_covenant, cmd_pending_txs,
    cmd_send, cmd_spend_contract, cmd_spend_contract_signed, cmd_submit_self, cmd_tx_status, cmd_utxos,
};
use crate::storage::{
    cmd_history, cmd_wallets, generate_wallet_record, history_path, list_history, load_wallets, parse_testnet_address,
    save_wallets, TxHistoryRecord,
};
use crate::ui::{print_header, print_kv};

const DEFAULT_CONSOLE_HISTORY_PATH: &str = ".kascov-console-history";

fn print_console_help() {
    println!("commands:");
    println!("  help");
    println!("  show-config");
    println!("  set-rpc <host:port|grpc://host:port>");
    println!("  set-address <kaspatest_address>");
    println!("  wallets");
    println!("  wallet-pk");
    println!("  use-wallet <index>");
    println!("  delete-wallet <index>");
    println!("  balance");
    println!("  utxos [detail]");
    println!("  pending-txs");
    println!("  tx-status <txid|b|last>");
    println!("  compile <source.sil> [out.json] [constructor_args.json]");
    println!("  compile-contracts [contracts_dir] [compiled_dir]");
    println!("  deploy");
    println!("  deploy <compiled.json> <amount_sompi>");
    println!("  spend-contract <compiled.json> <txid:vout> <input_amount_sompi> <function> <args.json|-> <outputs.json>");
    println!("  spend-contract-signed <compiled.json> <txid:vout> <input_amount_sompi> <function> <args.json> <outputs.json>");
    println!("  send <to_address> <amount_sompi>");
    println!("  submit-self <amount_sompi>");
    println!("  compound [max_inputs]");
    println!("  history [limit]");
    println!("  back");
    println!("  quit | exit");
}

fn read_prompt_line(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|err| format!("stdout flush failed: {err}"))?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(|err| format!("stdin read failed: {err}"))?;
    Ok(line.trim().to_string())
}

fn list_compiled_json_files(out_dir: &str) -> Result<Vec<PathBuf>, String> {
    let out_path = Path::new(out_dir);
    if !out_path.exists() {
        return Err(format!("compiled output dir does not exist: {out_dir}"));
    }

    let mut files = Vec::new();
    for entry in WalkDir::new(out_path) {
        let entry = entry.map_err(|err| format!("walk error: {err}"))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("json") {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

fn resolve_compiled_path(input: &str, out_dir: &str) -> String {
    if Path::new(input).exists() {
        return input.to_string();
    }
    let fallback = Path::new(out_dir).join(input);
    if fallback.exists() {
        return fallback.to_string_lossy().to_string();
    }
    input.to_string()
}

fn default_compiled_output_for_source(source: &str, out_dir: &str) -> String {
    let source_path = Path::new(source);
    let stem = source_path
        .file_stem()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
        .unwrap_or("compiled");
    Path::new(out_dir).join(format!("{stem}.json")).to_string_lossy().to_string()
}

async fn cmd_deploy_browse(
    rpc: &str,
    private_key: &str,
    address: &str,
    out_dir: &str,
) -> Result<(), String> {
    let files = list_compiled_json_files(out_dir)?;
    if files.is_empty() {
        return Err(format!("no compiled contract json files found in {out_dir}"));
    }

    print_header("Deploy Browser");
    print_kv("compiled_dir", out_dir);
    print_kv("available_files", files.len());
    for (index, file) in files.iter().enumerate() {
        println!("  [{}] {}", index + 1, file.display());
    }

    let pick = read_prompt_line("pick index (or q)> ")?;
    if pick.eq_ignore_ascii_case("q") {
        println!("deploy cancelled");
        return Ok(());
    }
    let index = pick.parse::<usize>().map_err(|err| format!("invalid index: {err}"))?;
    if index == 0 || index > files.len() {
        return Err("index out of range".to_string());
    }
    let file = &files[index - 1];

    let amount_text = read_prompt_line("amount_sompi> ")?;
    let amount = amount_text
        .parse::<u64>()
        .map_err(|err| format!("invalid amount_sompi '{amount_text}': {err}"))?;

    cmd_deploy_covenant(rpc, private_key, address, &file.to_string_lossy(), amount).await
}

fn recent_history_with_txid(limit: usize) -> Result<Vec<TxHistoryRecord>, String> {
    let mut rows = list_history()?;
    rows.retain(|row| !row.txid.trim().is_empty());
    rows.sort_by_key(|row| row.ts_unix_ms);
    rows.reverse();
    if rows.len() > limit {
        rows.truncate(limit);
    }
    Ok(rows)
}

async fn cmd_tx_status_last(rpc: &str) -> Result<(), String> {
    let rows = recent_history_with_txid(1)?;
    let Some(row) = rows.first() else {
        return Err("no tx history entries found".to_string());
    };
    cmd_tx_status(rpc, &row.txid).await
}

async fn cmd_tx_status_browse(rpc: &str, limit: usize) -> Result<(), String> {
    let rows = recent_history_with_txid(limit)?;
    if rows.is_empty() {
        return Err("no tx history entries found".to_string());
    }

    print_header("Tx History Browser");
    print_kv("history_file", history_path());
    print_kv("available_rows", rows.len());
    for (index, row) in rows.iter().enumerate() {
        println!("  [{}] {} {} {}", index + 1, row.ts_unix_ms, row.action, row.txid);
    }

    let pick = read_prompt_line("pick index (or q)> ")?;
    if pick.eq_ignore_ascii_case("q") {
        println!("browse cancelled");
        return Ok(());
    }

    let index = pick.parse::<usize>().map_err(|err| format!("invalid index: {err}"))?;
    if index == 0 || index > rows.len() {
        return Err("index out of range".to_string());
    }
    let selected = &rows[index - 1];
    cmd_tx_status(rpc, &selected.txid).await
}

fn select_wallet_on_console_boot(private_key: &mut String, address: &mut String) -> Result<(), String> {
    loop {
        let wallets = load_wallets()?;
        println!("wallet selection:");
        print_kv("saved_wallet_count", wallets.len());
        for (index, wallet) in wallets.iter().enumerate() {
            println!("  {}) {}  {}", index + 1, wallet.name, wallet.address);
        }
        println!("  g) generate wallet");
        let choice = read_prompt_line("select wallet> ")?;
        if choice.eq_ignore_ascii_case("g") {
            let name_input = read_prompt_line("wallet name (optional)> ")?;
            let name = if name_input.is_empty() { None } else { Some(name_input) };
            let mut wallets = wallets;
            let wallet = generate_wallet_record(name, wallets.len() + 1)?;
            wallets.push(wallet.clone());
            save_wallets(&wallets)?;
            *private_key = wallet.private_key.clone();
            *address = wallet.address.clone();
            println!("generated wallet name={} address={}", wallet.name, wallet.address);
            return Ok(());
        }

        if let Ok(index) = choice.parse::<usize>() {
            if index >= 1 && index <= wallets.len() {
                let wallet = &wallets[index - 1];
                parse_testnet_address(&wallet.address)?;
                *private_key = wallet.private_key.clone();
                *address = wallet.address.clone();
                println!("selected wallet name={} address={}", wallet.name, wallet.address);
                return Ok(());
            }
        }
        if choice.is_empty() {
            println!("select a wallet index (1..{}) or 'g' to generate", wallets.len());
            continue;
        }
        println!("invalid wallet selection");
    }
}

pub async fn cmd_console(
    mut rpc: String,
    mut private_key: String,
    mut address: String,
    mut contracts_dir: String,
    mut out_dir: String,
) -> Result<(), String> {
    println!("kascov console started");
    select_wallet_on_console_boot(&mut private_key, &mut address)?;
    println!("type 'help' for commands");
    let mut line_editor = rustyline::DefaultEditor::new().map_err(|err| format!("console init failed: {err}"))?;
    let history_file =
        std::env::var("KASPA_CONSOLE_HISTORY_FILE").unwrap_or_else(|_| DEFAULT_CONSOLE_HISTORY_PATH.to_string());
    let _ = line_editor.load_history(&history_file);
    let mut first_prompt = true;

    loop {
        if !first_prompt {
            println!();
        }
        first_prompt = false;
        let input_line = match line_editor.readline("kascov> ") {
            Ok(value) => value,
            Err(ReadlineError::Interrupted) | Err(ReadlineError::Eof) => break,
            Err(err) => return Err(format!("console read failed: {err}")),
        };
        let input = input_line.trim();
        if input.is_empty() {
            continue;
        }
        let _ = line_editor.add_history_entry(input);
        let parts: Vec<&str> = input.split_whitespace().collect();
        match parts[0] {
            "exit" | "quit" => break,
            "back" => {
                if parts.len() != 1 {
                    println!("usage: back");
                    continue;
                }
                if let Err(err) = select_wallet_on_console_boot(&mut private_key, &mut address) {
                    println!("error: {err}");
                } else {
                    println!("type 'help' for commands");
                }
            }
            "help" => print_console_help(),
            "show-config" => {
                println!("rpc={rpc}");
                println!("address={address}");
                println!("contracts_dir={contracts_dir}");
                println!("compiled_dir={out_dir}");
                println!("history_file={}", history_path());
            }
            "set-rpc" => {
                if parts.len() != 2 {
                    println!("usage: set-rpc <host:port|grpc://host:port>");
                    continue;
                }
                rpc = parts[1].to_string();
                println!("ok rpc={rpc}");
            }
            "set-address" => {
                if parts.len() != 2 {
                    println!("usage: set-address <kaspa_address>");
                    continue;
                }
                if let Err(err) = parse_testnet_address(parts[1]) {
                    println!("error: {err}");
                    continue;
                }
                address = parts[1].to_string();
                println!("ok address={address}");
            }
            "wallets" => {
                if let Err(err) = cmd_wallets() {
                    println!("error: {err}");
                }
            }
            "wallet-pk" => {
                print_header("Current Wallet Private Key");
                println!("warning: keep this secret");
                print_kv("address", &address);
                print_kv("private_key", &private_key);
            }
            "use-wallet" => {
                if parts.len() != 2 {
                    println!("usage: use-wallet <index>");
                    continue;
                }
                let index = match parts[1].parse::<usize>() {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: invalid index: {err}");
                        continue;
                    }
                };
                let wallets = match load_wallets() {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: {err}");
                        continue;
                    }
                };
                if index == 0 {
                    println!("error: wallet index starts at 1");
                    continue;
                }
                if index > wallets.len() {
                    println!("error: wallet index out of range");
                    continue;
                }
                let wallet = &wallets[index - 1];
                if let Err(err) = parse_testnet_address(&wallet.address) {
                    println!("error: wallet is not kaspatest and cannot be used: {err}");
                    continue;
                }
                private_key = wallet.private_key.clone();
                address = wallet.address.clone();
                println!("selected wallet name={} address={}", wallet.name, address);
            }
            "delete-wallet" => {
                if parts.len() != 2 {
                    println!("usage: delete-wallet <index>");
                    continue;
                }
                let mut wallets = match load_wallets() {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: {err}");
                        continue;
                    }
                };
                let index = match parts[1].parse::<usize>() {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: invalid index: {err}");
                        continue;
                    }
                };

                if index == 0 {
                    println!("error: wallet index starts at 1");
                    continue;
                }

                if index > wallets.len() {
                    println!("error: wallet index out of range");
                    continue;
                }

                let target = &wallets[index - 1];
                println!("delete wallet [{}] {} {}", index, target.name, target.address);
                let confirm = match read_prompt_line("confirm delete (yes/no)> ") {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: {err}");
                        continue;
                    }
                };
                if confirm.to_lowercase() != "yes" {
                    println!("cancelled");
                    continue;
                }

                let removed = wallets.remove(index - 1);
                if let Err(err) = save_wallets(&wallets) {
                    println!("error: {err}");
                    continue;
                }
                println!("deleted wallet name={} address={}", removed.name, removed.address);
            }
            "balance" => {
                if let Err(err) = cmd_balance(&rpc, &address).await {
                    println!("error: {err}");
                }
            }
            "utxos" => {
                if parts.len() > 2 {
                    println!("usage: utxos [detail]");
                    continue;
                }
                let detail = parts.len() == 2 && parts[1] == "detail";
                if parts.len() == 2 && !detail {
                    println!("usage: utxos [detail]");
                    continue;
                }
                if let Err(err) = cmd_utxos(&rpc, &address, detail).await {
                    println!("error: {err}");
                }
            }
            "pending-txs" => {
                if let Err(err) = cmd_pending_txs(&rpc, &address).await {
                    println!("error: {err}");
                }
            }
            "tx-status" => {
                if parts.len() != 2 {
                    println!("usage: tx-status <txid|b|last>");
                    continue;
                }
                let result = match parts[1] {
                    "b" => cmd_tx_status_browse(&rpc, 50).await,
                    "last" => cmd_tx_status_last(&rpc).await,
                    txid => cmd_tx_status(&rpc, txid).await,
                };
                if let Err(err) = result {
                    println!("error: {err}");
                };
            }
            "compile" => {
                if !(parts.len() == 2 || parts.len() == 3 || parts.len() == 4) {
                    println!("usage: compile <source.sil> [out.json] [constructor_args.json]");
                    continue;
                }
                let default_out;
                let out = if parts.len() == 3 {
                    Some(parts[2])
                } else if parts.len() == 2 {
                    default_out = default_compiled_output_for_source(parts[1], &out_dir);
                    Some(default_out.as_str())
                } else {
                    Some(parts[2])
                };
                let constructor_args = if parts.len() == 4 { Some(parts[3]) } else { None };
                if let Err(err) = cmd_compile_sil(parts[1], out, constructor_args) {
                    println!("error: {err}");
                }
            }
            "compile-contracts" => {
                if parts.len() > 3 {
                    println!("usage: compile-contracts [contracts_dir] [compiled_dir]");
                    continue;
                }
                if parts.len() >= 2 {
                    contracts_dir = parts[1].to_string();
                }
                if parts.len() == 3 {
                    out_dir = parts[2].to_string();
                }
                if let Err(err) = cmd_compile_contracts(&contracts_dir, &out_dir) {
                    println!("error: {err}");
                }
            }
            "deploy" => {
                if parts.len() == 1 {
                    if let Err(err) = cmd_deploy_browse(&rpc, &private_key, &address, &out_dir).await {
                        println!("error: {err}");
                    }
                    continue;
                }
                if parts.len() != 3 {
                    println!("usage: deploy");
                    println!("usage: deploy <compiled.json> <amount_sompi>");
                    continue;
                }
                let amount_sompi = match parts[2].parse::<u64>() {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: invalid amount_sompi: {err}");
                        continue;
                    }
                };
                let compiled_path = resolve_compiled_path(parts[1], &out_dir);
                if let Err(err) = cmd_deploy_covenant(&rpc, &private_key, &address, &compiled_path, amount_sompi).await {
                    println!("error: {err}");
                }
            }
            "spend-contract" => {
                if parts.len() != 7 {
                    println!(
                        "usage: spend-contract <compiled.json> <txid:vout> <input_amount_sompi> <function> <args.json|-> <outputs.json>"
                    );
                    continue;
                }
                let input_amount_sompi = match parts[3].parse::<u64>() {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: invalid input_amount_sompi: {err}");
                        continue;
                    }
                };
                let compiled_path = resolve_compiled_path(parts[1], &out_dir);
                if let Err(err) = cmd_spend_contract(
                    &rpc,
                    &compiled_path,
                    parts[2],
                    input_amount_sompi,
                    parts[4],
                    parts[5],
                    parts[6],
                )
                .await
                {
                    println!("error: {err}");
                }
            }
            "spend-contract-signed" => {
                if parts.len() != 7 {
                    println!(
                        "usage: spend-contract-signed <compiled.json> <txid:vout> <input_amount_sompi> <function> <args.json> <outputs.json>"
                    );
                    println!("note: args.json can use placeholders $pubkey and $sig");
                    continue;
                }
                let input_amount_sompi = match parts[3].parse::<u64>() {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: invalid input_amount_sompi: {err}");
                        continue;
                    }
                };
                let compiled_path = resolve_compiled_path(parts[1], &out_dir);
                if let Err(err) = cmd_spend_contract_signed(
                    &rpc,
                    &private_key,
                    &compiled_path,
                    parts[2],
                    input_amount_sompi,
                    parts[4],
                    parts[5],
                    parts[6],
                )
                .await
                {
                    println!("error: {err}");
                }
            }
            "submit-self" => {
                if parts.len() != 2 {
                    println!("usage: submit-self <amount_sompi>");
                    continue;
                }
                let amount_sompi = match parts[1].parse::<u64>() {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: invalid amount_sompi: {err}");
                        continue;
                    }
                };
                if let Err(err) = cmd_submit_self(&rpc, &private_key, &address, amount_sompi).await {
                    println!("error: {err}");
                }
            }
            "send" => {
                if parts.len() != 3 {
                    println!("usage: send <to_address> <amount_sompi>");
                    continue;
                }
                let to_address = parts[1];
                let amount_sompi = match parts[2].parse::<u64>() {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: invalid amount_sompi: {err}");
                        continue;
                    }
                };
                if let Err(err) = cmd_send(&rpc, &private_key, &address, to_address, amount_sompi).await {
                    println!("error: {err}");
                }
            }
            "compound" => {
                if parts.len() > 2 {
                    println!("usage: compound [max_inputs]");
                    continue;
                }
                let max_inputs = if parts.len() == 2 {
                    match parts[1].parse::<usize>() {
                        Ok(value) => value,
                        Err(err) => {
                            println!("error: invalid max_inputs: {err}");
                            continue;
                        }
                    }
                } else {
                    900
                };
                if let Err(err) = cmd_compound_utxos(&rpc, &private_key, &address, max_inputs).await {
                    println!("error: {err}");
                }
            }
            "history" => {
                if parts.len() > 2 {
                    println!("usage: history [limit]");
                    continue;
                }
                let limit = if parts.len() == 2 {
                    match parts[1].parse::<usize>() {
                        Ok(value) => value,
                        Err(err) => {
                            println!("error: invalid limit: {err}");
                            continue;
                        }
                    }
                } else {
                    50
                };
                if let Err(err) = cmd_history(limit) {
                    println!("error: {err}");
                }
            }
            _ => {
                println!("unknown command: {}", parts[0]);
                println!("type 'help' for supported commands");
            }
        }
    }

    let _ = line_editor.save_history(&history_file);
    println!("console exited");
    Ok(())
}
