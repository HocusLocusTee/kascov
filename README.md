# kascov (console-only)

This app now runs as a single interactive console session.
Direct subcommand usage was removed by design.

## Start

From `kascov/`:

```bash
cargo run
```

Optional startup overrides:

```bash
cargo run -- --rpc 66.23.234.250:16210 --address kaspatest:qp8snfastxwvcu40sy7sfwwad0kpkjt2flcdkuuk4gw2td0mcauukn2pq66m6
```

## `.env` configuration

Create `kascov/.env`:

```bash
KASPA_RPC=66.23.234.250:16210
KASPA_FEE_SOMPI=1000000
```

Safety: only `kaspatest:` addresses are allowed. `kaspa:` (mainnet) and other prefixes are rejected.

## Console flow

On boot, you get wallet selection:
- wallet index to select saved wallet
- `g` generate wallet (last option)

Inside console input, `↑` and `↓` navigate previous/next command history.

Inside console, run `help` and use:
- `balance`
- `utxos` (summary count + totals)
- `utxos detail` (full list)
- `pending-txs`
- `tx-status <txid|b|last>`
- `wallets`
- `wallet-pk` (shows currently selected private key)
- `use-wallet <index>` (wallet indexes start at `1`)
- `delete-wallet <index>` (asks for `yes` confirmation; wallet indexes start at `1`)
- `compile <source.sil> [out.json] [constructor_args.json]` (default output goes to current compiled dir)
- `compile-contracts [contracts_dir] [compiled_dir]` (defaults: `contracts` -> `compiled-silverscript`)
- `deploy` (interactive picker from compiled dir + amount prompt)
- `deploy <compiled.json> <amount_sompi>`
- `spend-contract <compiled.json> <txid:vout> <input_amount_sompi> <function> <args.json|-> <outputs.json>`
- `spend-contract-signed <compiled.json> <txid:vout> <input_amount_sompi> <function> <args.json> <outputs.json>`
- `send <to_address> <amount_sompi>`
- `submit-self <amount_sompi>`
- `compound [max_inputs]`
- `history [limit]`
- `back` (return to wallet selection)
- `exit`

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
- `input_amount_sompi - sum(outputs.amount_sompi)` becomes tx fee.
- `spend-contract-signed` supports placeholders in `args.json`:
  - `{ "kind": "identifier", "data": "$pubkey" }`
  - `{ "kind": "identifier", "data": "$sig" }`
  - These are replaced with signer wallet pubkey/signature before script build.

## Contract Spend Model (All Covenants)

Use the same model for every covenant spend:
1. Compile contract (`compiled.json`).
2. Deploy contract with amount (`deploy ... <amount_sompi>`), which creates a locked contract UTXO.
3. Copy deploy output `contract_output_outpoint` (`txid:vout`).
4. Spend that exact outpoint with a contract function call and outputs.

`spend-contract` argument mapping:
- `<compiled.json>`: contract bytecode + ABI metadata.
- `<txid:vout>`: deployed contract UTXO to spend.
- `<input_amount_sompi>`: amount of that UTXO.
- `<function>`: entrypoint to execute.
- `<args.json|->`: function arguments used to satisfy lock conditions.
- `<outputs.json>`: transaction outputs (where unlocked funds go).

Minimal lifecycle example:
```text
compile ../silverscript/silverscript-lang/tests/examples/simple_if_statement.sil
deploy compiled-silverscript/simple_if_statement.json 100000000
spend-contract compiled-silverscript/simple_if_statement.json <DEPLOY_TXID:0> 100000000 hello contract-params/simple_if_statement_hello_else_args.json contract-params/spend_outputs_template.json
```

## Persistence

- Wallets file: `wallets.json` (override with `KASPA_WALLETS_FILE`)
- Tx history file: `tx-history.jsonl` (override with `KASPA_HISTORY_FILE`)
- Console command history file: `.kascov-console-history` (override with `KASPA_CONSOLE_HISTORY_FILE`)

## Notes

- `KASPA_FEE_SOMPI` applies to `send`, `submit-self`, `deploy`, and `compound`.
- `.env` only controls RPC and fee overrides; wallet keys/addresses are selected in-console or via CLI flags.
- `--rpc` accepts `host:port` or `grpc://host:port`.
- On startup, `kascov` ensures `contracts/`, `compiled-silverscript/`, and `contract-params/` exist (or custom `--contracts-dir` / `--out-dir` paths for the first two).
