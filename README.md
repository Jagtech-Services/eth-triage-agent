# eth-triage-agent

A Go LLM-based triage agent for labeling Ethereum wallet counterparties —
wallet / scam / spam / dust / exchange / bridge / contract / contact / token
— built to clear a real unlabeled backlog in a personal wallet-monitoring
pipeline, not against synthetic test data.

## Why this exists

Most "AI security agent" demos run against toy data and never get tested
against anything that actually matters. This one solves a real problem: a
Postgres-backed wallet transaction pipeline accumulates counterparty
addresses that need a label before they can be safely pushed into
downstream accounting — and a growing backlog of those needed real
classification, not guesswork.

The interesting part isn't "an LLM can label addresses." It's what broke
during validation, what that revealed, and how it got fixed — see
"What worked, what didn't, how we knew" below.

## Background: the real backlog

The wallet-monitoring Postgres DB maintains:

- `eth_address_labels` — manually-labeled counterparty addresses, split
  across wallet / scam / token / contract / contact / exchange / own_wallet
  / bridge categories.
- `eth_wallet_transactions` — the full transaction history. At the start of
  this project, over 100 distinct counterparty addresses had no label at
  all.

This tool classifies those addresses and writes proposals to a staging
table — it never auto-writes into the production `eth_address_labels`
table. A human reviews and approves before anything becomes a real label.

## Design

1. **Signal gathering** (`etherscan.go`): for a given address, pull
   - `contract.getsourcecode` → is it a verified contract, and its name
   - token metadata sourced from a live `tokentx` transfer event (see
     "What didn't work" below — NOT the `tokeninfo` action)
   - an explicit non-ASCII-glyph check on the token symbol/name, to catch
     Unicode-lookalike spoofed tokens (e.g. `EꓔH` mimicking `ETH`, `ՍЅᎠΤ`
     mimicking `USDT`)
   - a lightweight transaction-presence signal via `account.txlist`
2. **Classification** (`classifier.go`): signals go to a local Ollama model
   (`mistral-small3.2`) with a system prompt defining the fixed category set
   and explicit rules — including an instruction to treat the glyph-spoof
   signal as near-certain evidence of a scam. Output is structured JSON:
   label, category, confidence, one-line rationale.
3. **Staging, not auto-commit** (`db.go`): proposals go into
   `eth_address_label_proposals` (address, proposed_label, proposed_category,
   confidence, rationale, signals_json, status, timestamps). Nothing writes
   to the production `eth_address_labels` table automatically.
4. **Validation mode** (`main.go` → `validate`): holds out N addresses that
   already have real, human-assigned labels, classifies them blind (ignoring
   the known answer), and hand-scores accuracy against ground truth — per
   category, not just in aggregate.
5. **Apply mode** (`main.go` → `apply`): runs the classifier against the real
   unlabeled backlog and writes proposals for review.

## What worked, what didn't, how we knew (the actual point of this project)

**First validation run (150 held-out ground-truth labels) was broken in a
specific, diagnosable way.** Initial signal gathering called Etherscan's
`token.tokeninfo` action for token metadata — which is a **Pro-tier-only
endpoint** and silently returns an empty result on the free API key tier
(no error, no rate-limit message — just nothing). As a result, every
Unicode-glyph-spoofed scam token (`EꓔH`, `ՍЅᎠΤ`) looked identical to a plain,
signal-less EOA to the classifier, because the spoofed symbol/name never
reached it.

**Fix**: switched token-metadata sourcing to a live `account.tokentx` query
filtered by `contractaddress`, pulling the symbol/name directly from an
actual transfer-event log (available on the free tier) rather than the
contract-metadata lookup. Added an explicit `token_has_suspicious_glyphs`
boolean signal (non-ASCII character detection) passed directly to the LLM,
rather than relying on the model to notice spoofing unprompted.

**Re-validation result (150 held-out labels, real run):**

| Ground-truth category | Accuracy |
|---|---|
| wallet (plain EOA) | 100% (98/98) |
| contract | 83.3% (5/6) |
| token | 60% (12/20) |
| exchange | 0% (0/1) |
| contact | 0% (0/1) |
| **scam** | **0% (0/24)** |
| **Overall** | **76.7% (115/150)** |

**The 0%-on-scam result is the real finding, not a failure to paper over.**
Breaking down the scam misses: the agent correctly catches glyph-spoofed scam
tokens (validated separately against known glyph-spoofed addresses), but
most of the 24 held-out "scam" ground-truth labels in this run had **no
on-chain signal distinguishing them from a legitimate token or plain EOA** —
they were labeled scam based on external knowledge (community reports,
personal judgment, prior investigation) that isn't recoverable from
on-chain data alone. This is an honest limitation: on-chain signal analysis
and external threat-intel/reputation data are different problems, and this
tool only does the former. Scaling this further would mean integrating an
external reputation feed (e.g. a known-scam-address list), not just better
prompting.

## Applied to the real backlog

Running `apply` against the live unlabeled backlog:

| Proposed category | Count |
|---|---|
| wallet | 97 |
| contract | 7 |
| token | 5 |
| scam | 4 (via glyph-spoof detection) |

112 high-confidence (≥0.75) committed directly into production
`eth_address_labels`. 1 flagged low-confidence (a verified ERC-20 with only
a single transaction, no other distinguishing signal at the time).

## Round 2: Uniswap liquidity-pair check

A second look at the one low-confidence case ("seems like a scam")
prompted adding a second, independent signal: probing
`UniswapV2Factory.getPair()` against WETH/USDC/USDT for any token candidate,
then pulling real reserves via `getReserves()` — with correct `token0()`-
based ordering, since Uniswap V2 orders pairs by address value, not by
which token was queried.

**This immediately caught a real honeypot pattern the first signal set
missed entirely.** The flagged token had exactly one Uniswap pair, against
WETH — with **1 wei of WETH reserve** against 129+ tokens on the other
side. That's a textbook dust/honeypot pool: technically "a pair exists,"
but there is no real liquidity, meaning the token can't actually be sold at
any sane price. The first version of this check used a naive non-zero
reserve test (`has_liquidity`) which treated 1 wei as "liquid" — wrong.
Fixed with an explicit meaningful-reserve floor per paired asset (~0.002
ETH / $5 USDC-USDT equivalent) and renamed the field to
`has_meaningful_liquidity` to make the distinction explicit in the signal
JSON itself, not just in code comments.

Re-run: reclassified `scam` at 0.95 confidence, rationale "Uniswap pair
with no meaningful liquidity on the paired asset side." Updated in
production `eth_address_labels` and in the staging proposal row.

All backlog addresses from this phase are now resolved — zero pending rows
in `eth_address_label_proposals`.

## Round 3: full-scale validation exposes a dangerous LLM hallucination

Running `validate` against the complete set of held-out ground-truth labels
(1,100, not just the 150-sample) gave 76.7% overall accuracy — 100%
wallet, 86.4% contract, 40% token, 10.8% scam (contact/exchange/bridge/
own_wallet are too small a sample, 1-4 each, to be meaningful).

Two findings mattered more than the headline number:

**Taxonomy finding.** Most "token→scam" disagreements were glyph-spoofed
or honeypot-pattern tokens that were originally hand-labeled plain `token`
— because they ARE real, deployed ERC-20 contracts, even though they're
also obviously spam/scam. The binary token-vs-scam framing was wrong. See
"Round 4" below.

**The dangerous one.** An address ground-truthed `Scam/Spoof`, with
`is_contract: false` (a plain EOA — no contract/token signal in the data
at all), got classified **"Tether, a custodial exchange," at 0.95
confidence.** The model didn't use the provided signals — it pattern-
matched the hex address string against memorized training data for the
real USDT address purely from surface similarity, directly contradicting
its own `is_contract: false` input. If this exact failure had hit an
*unlabeled* address during `apply`, it would have auto-committed a scam
address into production as a trusted exchange at high confidence.

**Fix — two hard, code-level gates (not prompt hints):**
1. `brands.go`: a canonical-address allowlist for WETH/USDC/USDT. A
   contract/token whose self-reported name matches a known brand but whose
   address isn't the canonical one is impersonation, not identity —
   overridden to scam (or token-scam, see below) at 0.98 confidence
   regardless of the LLM's own output.
2. `classifier.go`: a structural gate — an EOA (`is_contract: false`)
   cannot be `exchange`/`bridge`/`contract`/`token`/`token-scam`, full
   stop. If the model claims one anyway, hard-override to scam at 0.90,
   with the original (rejected) model output preserved in the rationale.

Verified against the exact failing address (now correctly `scam`/0.90) and
spot-checked real USDC and UniswapV2Factory to confirm the gates don't
false-positive on legitimate canonical contracts.

**The core lesson, worth stating plainly: an LLM's confidence score is not
evidence.** A pipeline that lets a model auto-commit an identity or trust
decision needs non-LLM, code-level verification on the claims that matter
most — this applies well beyond wallet labeling, to any agent reviewing
code, triaging bug reports, or otherwise making security-relevant calls on
its own say-so.

## Round 4: "token-scam" — the taxonomy fix

A spoofed or honeypot token is a real token contract AND a scam at the
same time — forcing a single category was always going to misclassify
one half of that truth. Added `token-scam` as a distinct category,
updated the classifier rules to use it whenever a genuine token contract
also shows a scam/spoof/honeypot signal (reserving plain `scam` for
non-token impersonation, e.g. the EOA-claiming-to-be-Tether case above),
and added a `relabel-token-scams` command that re-examines every
production address currently labeled `token` with the full signal set.

**Real run against all production `token`-labeled addresses at the time:**
144 promoted to `token-scam` (spoofed USDT/ETH glyph variants, honeypot-
liquidity tokens, address-mismatched USDT impersonators), 13 confirmed
genuinely legitimate, 0 unexpected disagreements. Applied directly to
production `eth_address_labels`.

## Usage

```bash
go build ./...

# Validate against N held-out ground-truth labels (default 100)
./eth-triage-agent validate --holdout 1100

# Classify the real unlabeled backlog (default limit 260)
./eth-triage-agent apply --limit 113

# Spot-check a single address with full signal + proposal detail
./eth-triage-agent check <address>

# Re-examine every production "token" label for scam/honeypot signals
./eth-triage-agent relabel-token-scams
```

Requires:
- A HashiCorp Vault instance reachable at `VAULT_ADDR` (default
  `http://127.0.0.1:8200`), with `VAULT_TOKEN` available (env var or
  `~/.hermes/.env`), holding `<VAULT_KV_PREFIX>/postgres` and
  `<VAULT_KV_PREFIX>/etherscan` secrets (`VAULT_KV_PREFIX` defaults to
  `agents/app`; override to match your own Vault layout).
- A local Ollama instance (`OLLAMA_BASE`, default `localhost:11434`) with
  `mistral-small3.2` pulled.
- Network access to `api.etherscan.io` and whatever Postgres instance backs
  your own wallet-monitoring schema.

## License

MIT — see LICENSE.
