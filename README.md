# kascov (console-only)

Codex coded CLI App to interact with kas covenants testnet.

**Warning: Do not use or modify for use on mainnet or real funds.**

## Start

From `kascov/`:

```bash
cargo run
```

Dependencies are pulled via Cargo from git (including `silverscript-lang`), so cloning `kascov/` alone is enough.


## `.env` configuration

Create `kascov/.env`:

```bash
KASPA_RPC=XXX.XXX.XXX.XXX:PORT
KASPA_AMOUNT_UNIT=SOMPI
```

`KASPA_AMOUNT_UNIT` controls how CLI/submission amount inputs are interpreted:
- `SOMPI` (default if unset)
- `KAS` (accepts decimals up to 8 places, e.g. `1.25`)

Safety: only `kaspatest:` addresses are allowed. `kaspa:` (mainnet) and other prefixes are rejected.

## Console flow

On boot, you get wallet selection:
- wallet index to select saved wallet
- `g` generate wallet (last option)
- after selection, console clears and shows selected wallet before prompt

Inside console input, `↑` and `↓` navigate previous/next command history.

Inside console, run `help` and use:
- `clear` (clear terminal)
- `config` / `config show`
- `config rpc <host:port|grpc://host:port>`
- `wallet` / `wallet list`
- `wallet use <index>` (wallet indexes start at `1`)
- `wallet pk` (shows currently selected private key)
- `wallet delete <index>` (asks for `yes` confirmation; wallet indexes start at `1`)
- `fees` (show current RPC fee estimate buckets)
- `balance`
- `utxos` (summary count + totals)
- `utxos detail` (full list)
- `pending-txs`
- `tx-status <txid|b|last>`
- `contracts` (interactive `.sil` contract browser and source viewer)
- `contracts <path.sil>` (print one contract source file)
- `compile <source.sil> [out.json] [constructor_args.json]` (default output goes to current compiled dir)
- `compile -i` (fully guided compile flow: pick contract, optional output path, typed constructor args)
- `compile -i <source.sil> [out.json]` (interactive constructor args prompt; no args JSON file needed)
- `compile all [contracts_dir] [compiled_dir]` (defaults: `contracts/silverscript` -> `contracts/compiled`; auto-loads constructor args from `contracts/params/<name>_ctor.json` or `contracts/params/<name>.json` when present)
- `deploy` (interactive picker from compiled dir + amount prompt)
- `deploy -i` (same as `deploy`; explicit interactive mode)
- `deploy <compiled.json> <amount>`
- `spend-contract <compiled.json> <txid:vout> <input_amount> <function> <args.json|-> <outputs.json>`
- `spend-contract -i` (fully guided spend flow: contract selection, outpoint, amount, function, args, outputs; supports `self` address alias and one `all` amount)
- `spend-contract -i <compiled.json> <txid:vout> <input_amount> <function> <outputs.json>` (interactive ABI-typed function args prompt)
- `spend-contract-signed <compiled.json> <txid:vout> <input_amount> <function> <args.json> <outputs.json>`
- `send -h` (show send options)
- `send <to_address> <amount>`
- `send -s <amount>` (self-send)
- `send -c [max_inputs]` (compound UTXOs)
- `history [limit]`
- `back` (return to wallet selection)
- `exit`

Per-command help:
- `config -h`
- `wallet -h`
- `compile -h`
- `contracts -h`
- `deploy -h`
- `spend-contract -h`
- `send -h`

`tx-status` shortcuts:
- `tx-status b` opens a picker from saved tx history entries
- `tx-status last` checks the most recently saved txid
- `tx-status` is mempool-only (no chain confirmation lookup)

`spend-contract` file formats:
- `args.json` is `Vec<Expr>` in SilverScript AST JSON format (use `-` for no args).
- `outputs.json` is an array like:
```json
[
  { "address": "kaspatest:...", "amount_sompi": 99000000 }
]
```
- For covenant/stateful outputs, you can use raw locking script destination instead of address:
```json
[
  { "locking_bytecode_hex": "20...ac", "amount_sompi": 99000000 }
]
```
- Each output row must provide exactly one destination: `address` or `locking_bytecode_hex`.
- You can also use `{ "address": "...", "amount": "..." }`; `amount` is parsed using `KASPA_AMOUNT_UNIT` (`SOMPI` default, or `KAS`).
- `input_amount_sompi - sum(outputs.amount_sompi)` becomes tx fee.
- `spend-contract-signed` supports placeholders in `args.json`:
  - `{ "kind": "identifier", "data": "$pubkey" }`
  - `{ "kind": "identifier", "data": "$sig" }`
  - These are replaced with signer wallet pubkey/signature before script build.

## Contract Spend Model (All Covenants)

Use the same model for every covenant spend:
1. Compile contract (`compiled.json`).
2. Deploy contract with amount (`deploy ... <amount>`), which creates a locked contract UTXO.
3. Copy deploy output `contract_output_outpoint` (`txid:vout`).
4. Spend that exact outpoint with a contract function call and outputs.

`spend-contract` argument mapping:
- `<compiled.json>`: contract bytecode + ABI metadata.
- `<txid:vout>`: deployed contract UTXO to spend.
- `<input_amount>`: amount of that UTXO (parsed via `KASPA_AMOUNT_UNIT`).
- `<function>`: entrypoint to execute.
- `<args.json|->`: function arguments used to satisfy lock conditions.
- `<outputs.json>`: transaction outputs (where unlocked funds go).

Minimal lifecycle example:
```text
compile ../silverscript/silverscript-lang/tests/examples/simple_if_statement.sil
deploy contracts/compiled/simple_if_statement.json 100000000
spend-contract contracts/compiled/simple_if_statement.json <DEPLOY_TXID:0> 100000000 hello contracts/params/simple_if_statement_hello_else_args.json contracts/params/spend_outputs_template.json
```

Interactive (no args JSON) example:
```text
compile -i contracts/silverscript/openhashlock.sil
deploy contracts/compiled/openhashlock.json 1000000000
spend-contract -i contracts/compiled/openhashlock.json <DEPLOY_TXID:0> 1000000000 claim contracts/params/openhashlock_outputs.json
```

Guided interactive spend (no args/outputs files) example:
```text
spend-contract -i
```

Guided spend shortcuts:
- In output address prompts, type `self` to use the currently selected wallet address.
- In exactly one output amount prompt, type `all` or `max` to send the remaining input amount after subtracting fastest-fee and other explicit outputs.
- For outpoint fields, type `last` to use the most recent `deploy-covenant` outpoint from history.
- In guided spend, if entered outputs leave fee below fastest recommendation, the shortfall is auto-deducted from the last output.

## Contract Workspace Layout

Default workspace under `kascov/contracts/`:
- `contracts/silverscript/` contract sources (`.sil`)
- `contracts/compiled/` compiled artifacts (`.json`)
- `contracts/params/` constructor/function/output parameter files

## Persistence

- Wallets file: `wallets.json` (override with `KASPA_WALLETS_FILE`)
- Tx history file: `tx-history.jsonl` (override with `KASPA_HISTORY_FILE`); includes successful tx submissions and failed deploy/spend/send attempts with error details
- Console command history file: `.kascov-console-history` (override with `KASPA_CONSOLE_HISTORY_FILE`)

## Notes

- Transaction-building commands use RPC fee estimate `priority_bucket` (fastest inclusion target): `send`, `send -s`, `send -c`, `deploy`, `spend-contract`, and `spend-contract-signed`.
- `fees` prints current priority/normal/low feerate buckets from RPC.
- `spend-contract` / `spend-contract-signed` enforce a minimum recommended fee for fastest policy; if outputs imply a lower fee, command returns an error and asks you to lower outputs total.
- `.env` controls RPC and amount input unit (`KASPA_AMOUNT_UNIT`); wallet keys/addresses are selected in-console or via CLI flags.
- `--rpc` accepts `host:port` or `grpc://host:port`.
- `deploy` output includes `contract_address` (derived P2SH testnet address) and `contract_output_outpoint`.
- On startup, `kascov` ensures `contracts/silverscript/`, `contracts/compiled/`, and `contracts/params/` exist (or custom `--contracts-dir` / `--out-dir` for source/compiled paths).
