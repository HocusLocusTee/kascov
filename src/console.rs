use rustyline::error::ReadlineError;
use silverscript_lang::{ast::{Expr, parse_contract_ast}, compiler::CompiledContract};
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::commands::{
    cmd_balance, cmd_compile_contracts, cmd_compile_sil, cmd_compile_sil_with_args, cmd_compound_utxos, cmd_deploy_covenant,
    cmd_fee_estimate, cmd_pending_txs, cmd_send, cmd_spend_contract, cmd_spend_contract_signed, cmd_spend_contract_with_args,
    cmd_spend_contract_with_args_and_outputs, cmd_submit_self, cmd_tx_status, cmd_utxos,
};
use crate::storage::{
    cmd_history, cmd_wallets, generate_wallet_record, history_path, list_history, load_wallets, parse_testnet_address,
    save_tx_history, save_wallets, TxHistoryRecord,
};
use crate::ui::{print_header, print_kv};

const DEFAULT_CONSOLE_HISTORY_PATH: &str = ".kascov-console-history";

fn print_console_help() {
    println!("commands:");
    println!("  help");
    println!("  clear");
    println!("  config [-h]");
    println!("  wallet [-h]");
    println!("  fees");
    println!("  balance");
    println!("  utxos [detail]");
    println!("  pending-txs");
    println!("  tx-status <txid|b|last>");
    println!("  contracts [-h]");
    println!("  compile [-h]");
    println!("  compile -i");
    println!("  compile -i <source.sil> [out.json]");
    println!("  compile all [contracts_dir] [compiled_dir]");
    println!("  deploy [-h]");
    println!("  deploy -i");
    println!("  spend-contract <compiled.json> <txid:vout> <input_amount_sompi> <function> <args.json|-> <outputs.json>");
    println!("  spend-contract -i");
    println!("  spend-contract -i <compiled.json> <txid:vout> <input_amount_sompi> <function> <outputs.json>");
    println!("  spend-contract-signed <compiled.json> <txid:vout> <input_amount_sompi> <function> <args.json> <outputs.json>");
    println!("  send [-h]");
    println!("  send <to_address> <amount_sompi>");
    println!("  send -s <amount_sompi>");
    println!("  send -c [max_inputs]");
    println!("  history [limit]");
    println!("  back");
    println!("  quit | exit");
}

fn print_contracts_help() {
    println!("usage: contracts");
    println!("  browse `.sil` contracts and view selected source with line numbers");
    println!();
    println!("usage: contracts <path.sil>");
    println!("  print a specific contract source file");
    println!();
    println!("usage: contracts -h");
    println!("  show this help");
    println!("example: contracts contracts/silverscript/openhashlock.sil");
}

fn print_config_help() {
    println!("usage: config");
    println!("  show current runtime config (rpc, selected wallet address, dirs, history file)");
    println!();
    println!("usage: config show");
    println!("  same as `config`");
    println!();
    println!("usage: config rpc <host:port|grpc://host:port>");
    println!("  set the RPC endpoint for this console session");
    println!("example: config rpc 66.23.234.250:16210");
}

fn print_wallet_help() {
    println!("usage: wallet");
    println!("  list saved wallets");
    println!();
    println!("usage: wallet list");
    println!("  list saved wallets");
    println!();
    println!("usage: wallet use <index>");
    println!("  switch active wallet for the session");
    println!();
    println!("usage: wallet pk");
    println!("  show active wallet private key (sensitive)");
    println!();
    println!("usage: wallet delete <index>");
    println!("  delete a saved wallet after confirmation");
    println!("example: wallet use 2");
}

fn print_compile_help() {
    println!("usage: compile <source.sil> [out.json] [constructor_args.json]");
    println!("  compile a single contract; optionally load constructor args from JSON");
    println!();
    println!("usage: compile -i");
    println!("  guided compile flow: pick source contract, optional output path, then prompt constructor args");
    println!();
    println!("usage: compile -i <source.sil> [out.json]");
    println!("  compile a single contract and prompt constructor args interactively");
    println!();
    println!("usage: compile all [contracts_dir] [compiled_dir]");
    println!("  compile all `.sil` files in contracts dir to compiled dir");
    println!("example: compile -i contracts/silverscript/openhashlock.sil");
}

fn print_deploy_help() {
    println!("usage: deploy");
    println!("  interactive deploy browser (pick compiled file + amount)");
    println!();
    println!("usage: deploy -i");
    println!("  same as `deploy`; explicit interactive mode");
    println!();
    println!("usage: deploy <compiled.json> <amount_sompi>");
    println!("  deploy compiled contract and lock amount into P2SH covenant output");
    println!("example: deploy contracts/compiled/openhashlock.json 1000000000");
}

fn print_send_help() {
    println!("usage: send <to_address> <amount_sompi>");
    println!("  send funds to another testnet address");
    println!();
    println!("usage: send -s <amount_sompi>");
    println!("  self-send: send from active wallet back to the same address");
    println!();
    println!("usage: send -c [max_inputs]");
    println!("  compound UTXOs: consolidate many UTXOs into one output on same address");
    println!();
    println!("example: send kaspatest:qp... 250000000");
    println!("example: send -s 100000000");
    println!("example: send -c 900");
}

fn print_spend_contract_help() {
    println!("usage: spend-contract <compiled.json> <txid:vout> <input_amount_sompi> <function> <args.json|-> <outputs.json>");
    println!("  spend a deployed contract UTXO using args JSON (or `-` for no args)");
    println!();
    println!("usage: spend-contract -i");
    println!("  guided spend flow: pick contract, outpoint, amount, function, args, and outputs interactively");
    println!();
    println!("usage: spend-contract -i <compiled.json> <txid:vout> <input_amount_sompi> <function> <outputs.json>");
    println!("  spend a deployed contract UTXO and enter function args interactively");
    println!();
    println!("notes:");
    println!("  - replace placeholders like <txid:vout> and <input_amount_sompi> with real values");
    println!("  - outpoint accepts alias `last` (most recent deploy contract outpoint from history)");
    println!("  - input_amount_sompi must match the spent outpoint amount exactly");
    println!("  - outputs total must be <= input_amount_sompi (fee = input - outputs)");
    println!("  - in guided mode, output address accepts `self` and one output amount can be `all`/`max`");
    println!("  - in guided mode, if fee is too low, shortfall auto-deducts from the last output");
    println!();
    println!(
        "example: spend-contract -i contracts/compiled/openhashlock.json <txid:vout> 1000000000 claim contracts/params/openhashlock_outputs.json"
    );
    println!("example: spend-contract -i");
}

fn read_prompt_line(prompt: &str) -> Result<String, String> {
    print!("{prompt}");
    io::stdout().flush().map_err(|err| format!("stdout flush failed: {err}"))?;
    let mut line = String::new();
    io::stdin().read_line(&mut line).map_err(|err| format!("stdin read failed: {err}"))?;
    let mut value = line.trim().to_string();
    // When bracketed paste mode markers leak into plain stdin prompts,
    // strip them so pasted values parse correctly.
    value = value.replace("\u{1b}[200~", "");
    value = value.replace("\u{1b}[201~", "");
    Ok(value.trim().to_string())
}

fn clear_terminal() -> Result<(), String> {
    print!("\x1B[2J\x1B[1;1H");
    io::stdout().flush().map_err(|err| format!("stdout flush failed: {err}"))
}

fn decode_hex_bytes(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    let normalized = trimmed
        .chars()
        .filter(|ch| !ch.is_whitespace() && *ch != '_')
        .collect::<String>();
    let hex = normalized.strip_prefix("0x").unwrap_or(&normalized);
    if hex.len() % 2 != 0 {
        return Err("hex input must have even length".to_string());
    }
    let mut out = Vec::with_capacity(hex.len() / 2);
    for i in (0..hex.len()).step_by(2) {
        let byte = u8::from_str_radix(&hex[i..i + 2], 16).map_err(|err| format!("invalid hex at byte {}: {err}", i / 2))?;
        out.push(byte);
    }
    Ok(out)
}

fn decode_decimal_byte_list(input: &str) -> Result<Vec<u8>, String> {
    let trimmed = input.trim();
    let body = trimmed
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .ok_or_else(|| "byte list must be in [n,n,...] format".to_string())?;
    if body.trim().is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for (index, part) in body.split(',').enumerate() {
        let value = part
            .trim()
            .parse::<u8>()
            .map_err(|err| format!("invalid byte at index {index}: {err}"))?;
        out.push(value);
    }
    Ok(out)
}

fn parse_bytes_input(value: &str) -> Result<Vec<u8>, String> {
    if value.trim_start().starts_with('[') {
        decode_decimal_byte_list(value)
    } else {
        decode_hex_bytes(value)
    }
}

fn parse_typed_expr(type_name: &str, raw: &str) -> Result<Expr, String> {
    let value = raw.trim();
    if let Some(inner_type) = type_name.strip_suffix("[]") {
        if inner_type == "int" {
            let text = value.trim_start_matches('[').trim_end_matches(']');
            if text.trim().is_empty() {
                return Ok(Expr::Array(Vec::new()));
            }
            let mut items = Vec::new();
            for part in text.split(',') {
                let n = part.trim().parse::<i64>().map_err(|err| format!("invalid int array item '{part}': {err}"))?;
                items.push(Expr::Int(n));
            }
            return Ok(Expr::Array(items));
        }
        if inner_type == "byte" {
            return Ok(Expr::Bytes(decode_hex_bytes(value)?));
        }
        return Err(format!("unsupported interactive array type: {type_name}"));
    }

    match type_name {
        "int" => value
            .parse::<i64>()
            .map(Expr::Int)
            .map_err(|err| format!("invalid int '{value}': {err}")),
        "bool" => match value.to_ascii_lowercase().as_str() {
            "true" | "1" => Ok(Expr::Bool(true)),
            "false" | "0" => Ok(Expr::Bool(false)),
            _ => Err("bool must be true/false or 1/0".to_string()),
        },
        "string" => Ok(Expr::String(value.to_string())),
        "bytes" => {
            if let Some(text) = value.strip_prefix("utf8:") {
                Ok(Expr::Bytes(text.as_bytes().to_vec()))
            } else {
                Ok(Expr::Bytes(parse_bytes_input(value)?))
            }
        }
        "byte" => {
            let bytes = parse_bytes_input(value)?;
            if bytes.len() != 1 {
                return Err("byte requires exactly 1 byte".to_string());
            }
            Ok(Expr::Bytes(bytes))
        }
        "pubkey" => {
            let bytes = parse_bytes_input(value)?;
            if bytes.len() != 32 {
                return Err("pubkey requires exactly 32 bytes".to_string());
            }
            Ok(Expr::Bytes(bytes))
        }
        "sig" | "datasig" => {
            let bytes = parse_bytes_input(value)?;
            if bytes.len() != 64 && bytes.len() != 65 {
                return Err(format!("{type_name} requires 64 or 65 bytes"));
            }
            Ok(Expr::Bytes(bytes))
        }
        _ => {
            if let Some(size) = type_name.strip_prefix("bytes").and_then(|n| n.parse::<usize>().ok()) {
                let bytes = parse_bytes_input(value)?;
                if bytes.len() != size {
                    return Err(format!("{type_name} requires exactly {size} bytes"));
                }
                Ok(Expr::Bytes(bytes))
            } else {
                Err(format!("unsupported interactive type: {type_name}"))
            }
        }
    }
}

fn prompt_for_typed_args(params: &[(String, String)], context: &str) -> Result<Option<Vec<Expr>>, String> {
    let mut args = Vec::with_capacity(params.len());
    if params.is_empty() {
        return Ok(Some(args));
    }
    print_header(context);
    println!("enter values by type; bytes* accepts hex (0x optional) or [n,n,...], `bytes` also accepts utf8:<text>");
    println!("type `q` to cancel");
    for (index, (name, type_name)) in params.iter().enumerate() {
        loop {
            let input = read_prompt_line(&format!("arg[{}] {} ({})> ", index + 1, name, type_name))?;
            if input.eq_ignore_ascii_case("q") || input.eq_ignore_ascii_case("quit") || input.eq_ignore_ascii_case("cancel") {
                return Ok(None);
            }
            match parse_typed_expr(type_name, &input) {
                Ok(expr) => {
                    args.push(expr);
                    break;
                }
                Err(err) => {
                    println!("error: {err}");
                }
            }
        }
    }
    Ok(Some(args))
}

fn parse_u64_cli_arg(arg_name: &str, raw: &str) -> Result<u64, String> {
    if raw.contains('<') || raw.contains('>') {
        return Err(format!(
            "{arg_name} looks like a placeholder (`{raw}`); replace it with a real numeric value"
        ));
    }
    raw.parse::<u64>().map_err(|err| format!("invalid {arg_name}: {err}"))
}

fn log_tx_failure(action: &str, rpc: &str, address: &str, details: String, err: &str) {
    let normalized_err = err.replace('\n', " ");
    save_tx_history(
        action,
        "",
        rpc,
        address,
        format!("{details} result=error error={normalized_err}"),
    );
}

fn is_cancel_input(value: &str) -> bool {
    value.eq_ignore_ascii_case("q") || value.eq_ignore_ascii_case("quit") || value.eq_ignore_ascii_case("cancel")
}

fn extract_outpoint_from_details(details: &str) -> Option<String> {
    for part in details.split_whitespace() {
        if let Some(value) = part.strip_prefix("contract_output_outpoint=") {
            if value.contains(':') {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn resolve_last_deploy_outpoint() -> Result<String, String> {
    let mut rows = list_history()?;
    rows.sort_by_key(|row| row.ts_unix_ms);
    rows.reverse();
    for row in rows {
        if row.action != "deploy-covenant" {
            continue;
        }
        if let Some(outpoint) = extract_outpoint_from_details(&row.details) {
            return Ok(outpoint);
        }
        if !row.txid.trim().is_empty() {
            return Ok(format!("{}:0", row.txid.trim()));
        }
    }
    Err("no deploy-covenant entries found in history".to_string())
}

fn resolve_outpoint_alias(value: &str) -> Result<String, String> {
    if value.eq_ignore_ascii_case("last") {
        resolve_last_deploy_outpoint()
    } else {
        Ok(value.to_string())
    }
}

fn prompt_outpoint_interactive() -> Result<Option<String>, String> {
    let value = read_prompt_line("outpoint (txid:vout, q to cancel)> ")?;
    if is_cancel_input(&value) {
        return Ok(None);
    }
    if value.eq_ignore_ascii_case("last") {
        let resolved = resolve_last_deploy_outpoint()?;
        println!("using last deploy outpoint: {resolved}");
        return Ok(Some(resolved));
    }
    if value.is_empty() {
        return Err("outpoint cannot be empty".to_string());
    }
    Ok(Some(value))
}

fn prompt_amount_interactive() -> Result<Option<u64>, String> {
    let value = read_prompt_line("input_amount_sompi (q to cancel)> ")?;
    if is_cancel_input(&value) {
        return Ok(None);
    }
    let parsed = parse_u64_cli_arg("input_amount_sompi", &value)?;
    Ok(Some(parsed))
}

fn prompt_function_selection(compiled: &CompiledContract) -> Result<Option<String>, String> {
    if compiled.abi.is_empty() {
        return Err("compiled contract ABI has no callable functions".to_string());
    }
    print_header("Contract Functions");
    for (index, entry) in compiled.abi.iter().enumerate() {
        println!("  [{}] {}", index + 1, entry.name);
    }
    let pick = read_prompt_line("pick function index (or q)> ")?;
    if is_cancel_input(&pick) {
        return Ok(None);
    }
    let index = pick.parse::<usize>().map_err(|err| format!("invalid index: {err}"))?;
    if index == 0 || index > compiled.abi.len() {
        return Err("function index out of range".to_string());
    }
    Ok(Some(compiled.abi[index - 1].name.clone()))
}

fn prompt_outputs_interactive(self_address: &str) -> Result<Option<Vec<(String, Option<u64>)>>, String> {
    print_header("Spend Outputs");
    println!("add destination outputs; type `done` when finished, `q` to cancel");
    println!("address alias: `self` = current wallet address");
    println!("amount alias: `all`/`max` = remaining input after fastest fee and other outputs");
    let mut outputs = Vec::new();
    let mut used_all = false;
    loop {
        let output_index = outputs.len() + 1;
        let mut address = read_prompt_line(&format!("output[{output_index}] address> "))?;
        if is_cancel_input(&address) {
            return Ok(None);
        }
        if address.eq_ignore_ascii_case("done") {
            if outputs.is_empty() {
                println!("at least one output is required");
                continue;
            }
            break;
        }
        if address.eq_ignore_ascii_case("self") {
            address = self_address.to_string();
        }
        if let Err(err) = parse_testnet_address(&address) {
            println!("error: invalid output address: {err}");
            continue;
        }

        loop {
            let amount_text = read_prompt_line(&format!("output[{output_index}] amount_sompi> "))?;
            if is_cancel_input(&amount_text) {
                return Ok(None);
            }
            if amount_text.eq_ignore_ascii_case("back") {
                break;
            }
            if amount_text.eq_ignore_ascii_case("all") || amount_text.eq_ignore_ascii_case("max") {
                if used_all {
                    println!("error: only one output can use `all`/`max`");
                    continue;
                }
                outputs.push((address.clone(), None));
                used_all = true;
                break;
            }
            let amount = match parse_u64_cli_arg("amount_sompi", &amount_text) {
                Ok(value) => value,
                Err(err) => {
                    println!("error: {err}");
                    continue;
                }
            };
            if amount == 0 {
                println!("error: amount_sompi must be greater than 0");
                continue;
            }
            outputs.push((address.clone(), Some(amount)));
            break;
        }
    }
    Ok(Some(outputs))
}

async fn cmd_spend_contract_wizard(rpc: &str, out_dir: &str, self_address: &str) -> Result<(), String> {
    let files = list_compiled_json_files(out_dir)?;
    if files.is_empty() {
        return Err(format!("no compiled contract json files found in {out_dir}"));
    }

    print_header("Spend Contract Wizard");
    print_kv("compiled_dir", out_dir);
    for (index, file) in files.iter().enumerate() {
        println!("  [{}] {}", index + 1, file.display());
    }
    let pick = read_prompt_line("pick contract index (or q)> ")?;
    if is_cancel_input(&pick) {
        println!("spend cancelled");
        return Ok(());
    }
    let index = pick.parse::<usize>().map_err(|err| format!("invalid index: {err}"))?;
    if index == 0 || index > files.len() {
        return Err("index out of range".to_string());
    }
    let compiled_path = files[index - 1].to_string_lossy().to_string();

    let compiled_json =
        fs::read_to_string(&compiled_path).map_err(|err| format!("failed to read compiled json {}: {err}", compiled_path))?;
    let compiled = serde_json::from_str::<CompiledContract>(&compiled_json)
        .map_err(|err| format!("failed to parse compiled json {}: {err}", compiled_path))?;

    let Some(outpoint) = prompt_outpoint_interactive()? else {
        println!("spend cancelled");
        return Ok(());
    };
    let Some(input_amount_sompi) = prompt_amount_interactive()? else {
        println!("spend cancelled");
        return Ok(());
    };
    let Some(function_name) = prompt_function_selection(&compiled)? else {
        println!("spend cancelled");
        return Ok(());
    };
    let function = compiled
        .abi
        .iter()
        .find(|entry| entry.name == function_name)
        .ok_or_else(|| "selected function not found in ABI".to_string())?;
    let fn_params = function
        .inputs
        .iter()
        .map(|param| (param.name.clone(), param.type_name.clone()))
        .collect::<Vec<_>>();
    let Some(function_args) = prompt_for_typed_args(&fn_params, "Function Args")? else {
        println!("spend cancelled");
        return Ok(());
    };
    let Some(outputs) = prompt_outputs_interactive(self_address)? else {
        println!("spend cancelled");
        return Ok(());
    };

    cmd_spend_contract_with_args_and_outputs(
        rpc,
        &compiled_path,
        &outpoint,
        input_amount_sompi,
        &function_name,
        function_args,
        outputs,
        "<interactive>",
        "<interactive>",
    )
    .await
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

fn list_sil_files(contracts_dir: &str) -> Result<Vec<PathBuf>, String> {
    let root = Path::new(contracts_dir);
    if !root.exists() {
        return Err(format!("contracts dir does not exist: {contracts_dir}"));
    }
    let mut files = Vec::new();
    for entry in WalkDir::new(root) {
        let entry = entry.map_err(|err| format!("walk error: {err}"))?;
        if !entry.file_type().is_file() {
            continue;
        }
        let path = entry.path();
        if path.extension().and_then(|value| value.to_str()) == Some("sil") {
            files.push(path.to_path_buf());
        }
    }
    files.sort();
    Ok(files)
}

fn render_contract_source(path: &Path) -> Result<(), String> {
    let text = fs::read_to_string(path).map_err(|err| format!("failed to read {}: {err}", path.display()))?;
    print_header("Contract Source");
    print_kv("file", path.display());
    print_kv("lines", text.lines().count());
    println!();
    for (index, line) in text.lines().enumerate() {
        println!("{:>4} | {}", index + 1, line);
    }
    Ok(())
}

fn cmd_contracts_browse(contracts_dir: &str) -> Result<(), String> {
    let files = list_sil_files(contracts_dir)?;
    if files.is_empty() {
        return Err(format!("no .sil files found in {contracts_dir}"));
    }

    print_header("Contracts");
    print_kv("contracts_dir", contracts_dir);
    print_kv("available_files", files.len());
    for (index, file) in files.iter().enumerate() {
        println!("  [{}] {}", index + 1, file.display());
    }

    let pick = read_prompt_line("pick index (or q)> ")?;
    if is_cancel_input(&pick) {
        println!("contracts cancelled");
        return Ok(());
    }
    let index = pick.parse::<usize>().map_err(|err| format!("invalid index: {err}"))?;
    if index == 0 || index > files.len() {
        return Err("index out of range".to_string());
    }

    render_contract_source(&files[index - 1])
}

fn resolve_contract_path(input: &str, contracts_dir: &str) -> String {
    if Path::new(input).exists() {
        return input.to_string();
    }
    let fallback = Path::new(contracts_dir).join(input);
    if fallback.exists() {
        return fallback.to_string_lossy().to_string();
    }
    input.to_string()
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

fn cmd_compile_interactive(contracts_dir: &str, out_dir: &str) -> Result<(), String> {
    let files = list_sil_files(contracts_dir)?;
    if files.is_empty() {
        return Err(format!("no .sil files found in {contracts_dir}"));
    }

    print_header("Compile Browser");
    print_kv("contracts_dir", contracts_dir);
    print_kv("available_files", files.len());
    for (index, file) in files.iter().enumerate() {
        println!("  [{}] {}", index + 1, file.display());
    }

    let pick = read_prompt_line("pick contract index (or q)> ")?;
    if is_cancel_input(&pick) {
        println!("compile cancelled");
        return Ok(());
    }
    let index = pick.parse::<usize>().map_err(|err| format!("invalid index: {err}"))?;
    if index == 0 || index > files.len() {
        return Err("index out of range".to_string());
    }
    let source = files[index - 1].to_string_lossy().to_string();

    let default_out = default_compiled_output_for_source(&source, out_dir);
    print_kv("default_output", &default_out);
    let out_input = read_prompt_line("output path (enter for default, q to cancel)> ")?;
    if is_cancel_input(&out_input) {
        println!("compile cancelled");
        return Ok(());
    }
    let out = if out_input.is_empty() {
        default_out
    } else {
        out_input
    };

    let source_text = fs::read_to_string(&source).map_err(|err| format!("failed to read source file {source}: {err}"))?;
    let contract_ast = parse_contract_ast(&source_text).map_err(|err| format!("parse error: {err}"))?;
    let params = contract_ast
        .params
        .iter()
        .map(|param| (param.name.clone(), param.type_name.clone()))
        .collect::<Vec<_>>();
    let constructor_args = match prompt_for_typed_args(&params, "Constructor Args")? {
        Some(value) => value,
        None => {
            println!("compile cancelled");
            return Ok(());
        }
    };

    cmd_compile_sil_with_args(&source, Some(&out), constructor_args)
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

fn select_wallet_on_console_boot(private_key: &mut String, address: &mut String) -> Result<Option<(String, String)>, String> {
    loop {
        let wallets = load_wallets()?;
        println!("wallet selection:");
        print_kv("saved_wallet_count", wallets.len());
        for (index, wallet) in wallets.iter().enumerate() {
            println!("  {}) {}  {}", index + 1, wallet.name, wallet.address);
        }
        println!();
        println!("  g) generate wallet");
        println!("  q) quit");
        let choice = read_prompt_line("select wallet> ")?;
        if choice.eq_ignore_ascii_case("q") || choice.eq_ignore_ascii_case("quit") {
            return Ok(None);
        }
        if choice.eq_ignore_ascii_case("g") {
            let name_input = read_prompt_line("wallet name (optional)> ")?;
            let name = if name_input.is_empty() { None } else { Some(name_input) };
            let mut wallets = wallets;
            let wallet = generate_wallet_record(name, wallets.len() + 1)?;
            wallets.push(wallet.clone());
            save_wallets(&wallets)?;
            *private_key = wallet.private_key.clone();
            *address = wallet.address.clone();
            return Ok(Some((wallet.name, wallet.address)));
        }

        if let Ok(index) = choice.parse::<usize>() {
            if index >= 1 && index <= wallets.len() {
                let wallet = &wallets[index - 1];
                parse_testnet_address(&wallet.address)?;
                *private_key = wallet.private_key.clone();
                *address = wallet.address.clone();
                return Ok(Some((wallet.name.clone(), wallet.address.clone())));
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
    let Some((mut selected_wallet_name, mut selected_wallet_address)) =
        select_wallet_on_console_boot(&mut private_key, &mut address)?
    else {
        println!("console exited");
        return Ok(());
    };
    clear_terminal()?;
    println!("kascov console started");
    println!("selected wallet name={} address={}", selected_wallet_name, selected_wallet_address);
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
            "clear" => {
                if parts.len() != 1 {
                    println!("usage: clear");
                    continue;
                }
                if let Err(err) = clear_terminal() {
                    println!("error: {err}");
                } else {
                    println!("selected wallet name={} address={}", selected_wallet_name, selected_wallet_address);
                }
            }
            "back" => {
                if parts.len() != 1 {
                    println!("usage: back");
                    continue;
                }
                if let Err(err) = clear_terminal() {
                    println!("error: {err}");
                    continue;
                }
                match select_wallet_on_console_boot(&mut private_key, &mut address) {
                    Err(err) => {
                        println!("error: {err}");
                    }
                    Ok(None) => {
                        println!("console exited");
                        return Ok(());
                    }
                    Ok(Some((name, addr))) => {
                        selected_wallet_name = name;
                        selected_wallet_address = addr;
                        if let Err(err) = clear_terminal() {
                            println!("error: {err}");
                            continue;
                        }
                        println!("kascov console started");
                        println!("selected wallet name={} address={}", selected_wallet_name, selected_wallet_address);
                        println!("type 'help' for commands");
                    }
                }
            }
            "help" => print_console_help(),
            "config" => {
                if parts.len() > 3 {
                    print_config_help();
                    continue;
                }
                if parts.len() == 1 || (parts.len() == 2 && parts[1] == "show") {
                    println!("rpc={rpc}");
                    println!("address={address}");
                    println!("selected_wallet_name={selected_wallet_name}");
                    println!("contracts_dir={contracts_dir}");
                    println!("compiled_dir={out_dir}");
                    println!("history_file={}", history_path());
                    continue;
                }
                if parts.len() == 2 && (parts[1] == "-h" || parts[1] == "--help" || parts[1] == "help") {
                    print_config_help();
                    continue;
                }
                if parts.len() == 3 && parts[1] == "rpc" {
                    rpc = parts[2].to_string();
                    println!("ok rpc={rpc}");
                    continue;
                }
                print_config_help();
            }
            "wallet" => {
                if parts.len() == 1 || (parts.len() == 2 && parts[1] == "list") {
                    if let Err(err) = cmd_wallets() {
                        println!("error: {err}");
                    }
                    continue;
                }
                if parts.len() == 2 && (parts[1] == "-h" || parts[1] == "--help" || parts[1] == "help") {
                    print_wallet_help();
                    continue;
                }
                if parts.len() == 2 && parts[1] == "pk" {
                    print_header("Current Wallet Private Key");
                    println!("warning: keep this secret");
                    print_kv("name", &selected_wallet_name);
                    print_kv("address", &address);
                    print_kv("private_key", &private_key);
                    continue;
                }
                if parts.len() == 3 && parts[1] == "use" {
                    let index = match parts[2].parse::<usize>() {
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
                    selected_wallet_name = wallet.name.clone();
                    selected_wallet_address = wallet.address.clone();
                    println!("selected wallet name={} address={}", selected_wallet_name, selected_wallet_address);
                    continue;
                }
                if parts.len() == 3 && parts[1] == "delete" {
                    let mut wallets = match load_wallets() {
                        Ok(value) => value,
                        Err(err) => {
                            println!("error: {err}");
                            continue;
                        }
                    };
                    let index = match parts[2].parse::<usize>() {
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
                    continue;
                }
                print_wallet_help();
            }
            "balance" => {
                if let Err(err) = cmd_balance(&rpc, &address).await {
                    println!("error: {err}");
                }
            }
            "fees" => {
                if parts.len() != 1 {
                    println!("usage: fees");
                    continue;
                }
                if let Err(err) = cmd_fee_estimate(&rpc).await {
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
                if parts.len() == 2 && (parts[1] == "-h" || parts[1] == "--help" || parts[1] == "help") {
                    print_compile_help();
                    continue;
                }
                if parts.len() == 2 && parts[1] == "-i" {
                    if let Err(err) = cmd_compile_interactive(&contracts_dir, &out_dir) {
                        println!("error: {err}");
                    }
                    continue;
                }
                if parts.len() >= 2 && parts[1] == "-i" {
                    if !(parts.len() == 3 || parts.len() == 4) {
                        print_compile_help();
                        continue;
                    }
                    let source = parts[2];
                    let out = if parts.len() == 4 { Some(parts[3]) } else { None };
                    let source_text = match fs::read_to_string(source) {
                        Ok(value) => value,
                        Err(err) => {
                            println!("error: failed to read source file {source}: {err}");
                            continue;
                        }
                    };
                    let contract_ast = match parse_contract_ast(&source_text) {
                        Ok(value) => value,
                        Err(err) => {
                            println!("error: parse error: {err}");
                            continue;
                        }
                    };
                    let params = contract_ast
                        .params
                        .iter()
                        .map(|param| (param.name.clone(), param.type_name.clone()))
                        .collect::<Vec<_>>();
                    let constructor_args = match prompt_for_typed_args(&params, "Constructor Args") {
                        Ok(Some(value)) => value,
                        Ok(None) => {
                            println!("compile cancelled");
                            continue;
                        }
                        Err(err) => {
                            println!("error: {err}");
                            continue;
                        }
                    };
                    let default_out;
                    let out = if let Some(value) = out {
                        Some(value)
                    } else {
                        default_out = default_compiled_output_for_source(source, &out_dir);
                        Some(default_out.as_str())
                    };
                    if let Err(err) = cmd_compile_sil_with_args(source, out, constructor_args) {
                        println!("error: {err}");
                    }
                    continue;
                }
                if parts.len() >= 2 && parts[1] == "all" {
                    if parts.len() > 4 {
                        print_compile_help();
                        continue;
                    }
                    if parts.len() >= 3 {
                        contracts_dir = parts[2].to_string();
                    }
                    if parts.len() == 4 {
                        out_dir = parts[3].to_string();
                    }
                    if let Err(err) = cmd_compile_contracts(&contracts_dir, &out_dir) {
                        println!("error: {err}");
                    }
                    continue;
                }
                if !(parts.len() == 2 || parts.len() == 3 || parts.len() == 4) {
                    print_compile_help();
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
            "contracts" => {
                if parts.len() == 1 {
                    if let Err(err) = cmd_contracts_browse(&contracts_dir) {
                        println!("error: {err}");
                    }
                    continue;
                }
                if parts.len() == 2 && (parts[1] == "-h" || parts[1] == "--help" || parts[1] == "help") {
                    print_contracts_help();
                    continue;
                }
                if parts.len() == 2 {
                    let path = resolve_contract_path(parts[1], &contracts_dir);
                    if let Err(err) = render_contract_source(Path::new(&path)) {
                        println!("error: {err}");
                    }
                    continue;
                }
                print_contracts_help();
            }
            "deploy" => {
                if parts.len() == 2 && (parts[1] == "-h" || parts[1] == "--help" || parts[1] == "help") {
                    print_deploy_help();
                    continue;
                }
                if parts.len() == 1 || (parts.len() == 2 && parts[1] == "-i") {
                    if let Err(err) = cmd_deploy_browse(&rpc, &private_key, &address, &out_dir).await {
                        println!("error: {err}");
                    }
                    continue;
                }
                if parts.len() != 3 {
                    print_deploy_help();
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
                    log_tx_failure(
                        "deploy-covenant",
                        &rpc,
                        &address,
                        format!("compiled={} amount_sompi={}", compiled_path, amount_sompi),
                        &err,
                    );
                    println!("error: {err}");
                }
            }
            "spend-contract" => {
                if parts.len() == 2 && (parts[1] == "-h" || parts[1] == "--help" || parts[1] == "help") {
                    print_spend_contract_help();
                    continue;
                }
                if parts.len() == 2 && parts[1] == "-i" {
                    if let Err(err) = cmd_spend_contract_wizard(&rpc, &out_dir, &address).await {
                        log_tx_failure("spend-contract", &rpc, "contract-p2sh", "wizard=true".to_string(), &err);
                        println!("error: {err}");
                    }
                    continue;
                }
                if parts.len() == 7 && parts[1] == "-i" {
                    let input_amount_sompi = match parse_u64_cli_arg("input_amount_sompi", parts[4]) {
                        Ok(value) => value,
                        Err(err) => {
                            println!("error: {err}");
                            continue;
                        }
                    };
                    let outpoint = match resolve_outpoint_alias(parts[3]) {
                        Ok(value) => value,
                        Err(err) => {
                            println!("error: {err}");
                            continue;
                        }
                    };
                    let compiled_path = resolve_compiled_path(parts[2], &out_dir);
                    let compiled_json = match fs::read_to_string(&compiled_path) {
                        Ok(value) => value,
                        Err(err) => {
                            println!("error: failed to read compiled json {}: {err}", compiled_path);
                            continue;
                        }
                    };
                    let compiled = match serde_json::from_str::<CompiledContract>(&compiled_json) {
                        Ok(value) => value,
                        Err(err) => {
                            println!("error: failed to parse compiled json {}: {err}", compiled_path);
                            continue;
                        }
                    };
                    let Some(function) = compiled.abi.iter().find(|entry| entry.name == parts[5]) else {
                        println!("error: function '{}' not found in abi", parts[5]);
                        continue;
                    };
                    let fn_params = function
                        .inputs
                        .iter()
                        .map(|param| (param.name.clone(), param.type_name.clone()))
                        .collect::<Vec<_>>();
                    let function_args = match prompt_for_typed_args(&fn_params, "Function Args") {
                        Ok(Some(value)) => value,
                        Ok(None) => {
                            println!("spend cancelled");
                            continue;
                        }
                        Err(err) => {
                            println!("error: {err}");
                            continue;
                        }
                    };
                    if let Err(err) = cmd_spend_contract_with_args(
                        &rpc,
                        &compiled_path,
                        &outpoint,
                        input_amount_sompi,
                        parts[5],
                        function_args,
                        parts[6],
                        "<interactive>",
                    )
                    .await
                    {
                        log_tx_failure(
                            "spend-contract",
                            &rpc,
                            "contract-p2sh",
                            format!(
                                "compiled={} outpoint={} function={} input_amount_sompi={} outputs_file={} args_file=<interactive>",
                                compiled_path, outpoint, parts[5], input_amount_sompi, parts[6]
                            ),
                            &err,
                        );
                        println!("error: {err}");
                    }
                    continue;
                }
                if parts.len() != 7 {
                    print_spend_contract_help();
                    continue;
                }
                let input_amount_sompi = match parse_u64_cli_arg("input_amount_sompi", parts[3]) {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: {err}");
                        continue;
                    }
                };
                let outpoint = match resolve_outpoint_alias(parts[2]) {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: {err}");
                        continue;
                    }
                };
                let compiled_path = resolve_compiled_path(parts[1], &out_dir);
                if let Err(err) = cmd_spend_contract(
                    &rpc,
                    &compiled_path,
                    &outpoint,
                    input_amount_sompi,
                    parts[4],
                    parts[5],
                    parts[6],
                )
                .await
                {
                    log_tx_failure(
                        "spend-contract",
                        &rpc,
                        "contract-p2sh",
                        format!(
                            "compiled={} outpoint={} function={} input_amount_sompi={} outputs_file={} args_file={}",
                            compiled_path, outpoint, parts[4], input_amount_sompi, parts[6], parts[5]
                        ),
                        &err,
                    );
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
                let input_amount_sompi = match parse_u64_cli_arg("input_amount_sompi", parts[3]) {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: {err}");
                        continue;
                    }
                };
                let outpoint = match resolve_outpoint_alias(parts[2]) {
                    Ok(value) => value,
                    Err(err) => {
                        println!("error: {err}");
                        continue;
                    }
                };
                let compiled_path = resolve_compiled_path(parts[1], &out_dir);
                if let Err(err) = cmd_spend_contract_signed(
                    &rpc,
                    &private_key,
                    &compiled_path,
                    &outpoint,
                    input_amount_sompi,
                    parts[4],
                    parts[5],
                    parts[6],
                )
                .await
                {
                    log_tx_failure(
                        "spend-contract-signed",
                        &rpc,
                        "contract-p2sh",
                        format!(
                            "compiled={} outpoint={} function={} input_amount_sompi={} outputs_file={} args_file={}",
                            compiled_path, outpoint, parts[4], input_amount_sompi, parts[6], parts[5]
                        ),
                        &err,
                    );
                    println!("error: {err}");
                }
            }
            "send" => {
                if parts.len() == 1 || (parts.len() == 2 && (parts[1] == "-h" || parts[1] == "--help" || parts[1] == "help")) {
                    print_send_help();
                    continue;
                }
                if parts.len() >= 2 && parts[1] == "-s" {
                    if parts.len() != 3 {
                        print_send_help();
                        continue;
                    }
                    let amount_sompi = match parts[2].parse::<u64>() {
                        Ok(value) => value,
                        Err(err) => {
                            println!("error: invalid amount_sompi: {err}");
                            continue;
                        }
                    };
                    if let Err(err) = cmd_submit_self(&rpc, &private_key, &address, amount_sompi).await {
                        log_tx_failure(
                            "submit-self",
                            &rpc,
                            &address,
                            format!("amount_sompi={amount_sompi}"),
                            &err,
                        );
                        println!("error: {err}");
                    }
                    continue;
                }
                if parts.len() >= 2 && parts[1] == "-c" {
                    if parts.len() > 3 {
                        print_send_help();
                        continue;
                    }
                    let max_inputs = if parts.len() == 3 {
                        match parts[2].parse::<usize>() {
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
                        log_tx_failure(
                            "compound-utxos",
                            &rpc,
                            &address,
                            format!("max_inputs={max_inputs}"),
                            &err,
                        );
                        println!("error: {err}");
                    }
                    continue;
                }
                if parts.len() != 3 {
                    print_send_help();
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
                    log_tx_failure(
                        "send",
                        &rpc,
                        &address,
                        format!("to_address={} amount_sompi={}", to_address, amount_sompi),
                        &err,
                    );
                    println!("error: {err}");
                }
            }
            "submit-self" | "compound" => {
                println!("unknown command: {}", parts[0]);
                println!("use `send -h` for send-related commands");
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
