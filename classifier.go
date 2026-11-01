package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"
)

const ollamaModelTriage = "mistral-small3.2"

func ollamaBase() string {
	if v := os.Getenv("OLLAMA_BASE"); v != "" {
		return v
	}
	return "http://localhost:11434"
}

// Proposal is the agent's output for one address.
type Proposal struct {
	Address     string
	Label       string
	Category    string
	Confidence  float32
	Rationale   string
	SignalsJSON []byte
}

const classifierSystemPrompt = `You are a crypto-wallet counterparty triage classifier.
Given on-chain signals about an Ethereum address that has interacted with the
user's wallet, classify it into exactly one category from this fixed set:
scam, token-scam, spam, dust, exchange, bridge, contract, contact, wallet, token.

CRITICAL: use ONLY the JSON signals provided below. Do not use any memorized
or outside knowledge you may have about specific Ethereum addresses — you do
not reliably know real contract addresses from training data, and guessing
based on surface similarity of hex strings is exactly how impersonation scams
succeed. If is_contract is false, this address is a plain externally-owned
account and CANNOT be a token, contract, exchange, or bridge — no matter how
familiar the address or any other detail looks.

Rules of thumb:
- "token-scam": a token exists (it's a real, deployed ERC-20 contract — not
  a plain EOA) but is ALSO a scam/spam/rug-pull — e.g. a Unicode-glyph
  spoofed token (mimicking ETH/USDT visually), a URL-spam token name, or a
  token whose only Uniswap pair has dust/near-zero liquidity (the honeypot
  signature). This is the right category whenever BOTH are true: it is a
  real token contract, AND it shows a scam/spam/spoof signal. Don't force
  a choice between "it's a token" and "it's a scam" — a spoofed or
  honeypot token is literally both at once.
- "scam": a scam/impersonation signal on something that is NOT itself a
  legitimate token contract — e.g. a plain EOA falsely claimed to be a
  known exchange/brand (impersonation without even being a contract), or
  a non-token contract scam.
- "spam": unsolicited low-value interactions with no token identity and no
  other scam-specific signal (distinct from "token-scam", which requires
  an actual token contract).
- token_has_suspicious_glyphs=true (the token symbol/name contains
  non-ASCII Unicode lookalike characters, e.g. mimicking ETH or USDT with
  visually-similar glyphs) is near-certain evidence for "token-scam" if
  is_contract is true, or "scam" otherwise.
- "dust": trivial-value transfers with no other signal of relationship.
- Liquidity check: if uniswap_pairs_checked is true and uniswap_pairs is
  empty (no pair found against WETH/USDC/USDT) or every listed pair has
  has_meaningful_liquidity=false (dust/near-zero reserve on the paired-asset
  side — e.g. 1 wei of WETH against a huge token reserve, the classic
  honeypot/rug-pull signature), treat that as strong evidence for
  "token-scam" (it IS a token, and it IS the rug-pull/honeypot pattern) —
  a legitimate token with any real trading activity almost always has at
  least one pair with a meaningful paired-asset reserve. A token with
  has_meaningful_liquidity=true in at least one pair is correspondingly
  strong evidence AGAINST "token-scam"/"scam"/"spam", even if other
  signals are thin.
- "exchange"/"bridge": well-known verified contract patterns for custodial
  exchanges or cross-chain bridges. IMPORTANT: if brand_check.is_impersonation
  is true, this address claims to be a known brand (brand_check.claims_brand)
  but its address does NOT match the real canonical contract
  (brand_check.canonical_address) — this is impersonation, not identity.
  Classify as "token-scam" if is_contract and a token symbol/name is set
  (it's a fake token impersonating a real one), otherwise "scam" — but
  never "exchange"/"bridge" for an impersonation case. A name match alone
  is never evidence of identity.
- "contract": a verified, legitimate smart contract that isn't an exchange/
  bridge/token.
- "token": a verified, legitimate ERC-20 token contract with no scam/spam/
  spoof/honeypot signal — use "token-scam" instead whenever any such
  signal is present, even if the token is otherwise a real contract.
- "contact": looks like a normal EOA with a real, reciprocal transaction
  pattern (not spam-shaped).
- "wallet": a plain EOA with no other distinguishing signal.

Respond with JSON only: {"label": "<short human label, e.g. a name or symbol>",
"category": "<one of the categories above>", "confidence": <0.0-1.0>,
"rationale": "<one sentence, cite the signals you used>"}`

func classifyAddress(sig AddrSignals) (Proposal, error) {
	sigJSON, err := json.Marshal(sig)
	if err != nil {
		return Proposal{}, err
	}

	payload := map[string]any{
		"model":  ollamaModelTriage,
		"system": classifierSystemPrompt,
		"prompt": fmt.Sprintf("On-chain signals: %s", string(sigJSON)),
		"stream": false,
		"format": "json",
		"think":  false,
		"options": map[string]any{
			"temperature": 0.1,
			"num_predict": 256,
		},
	}
	body, _ := json.Marshal(payload)

	client := &http.Client{Timeout: 60 * time.Second}
	resp, err := client.Post(ollamaBase()+"/api/generate", "application/json", bytes.NewReader(body))
	if err != nil {
		return Proposal{}, err
	}
	defer resp.Body.Close()

	var env struct {
		Response string `json:"response"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return Proposal{}, err
	}

	var out struct {
		Label      string  `json:"label"`
		Category   string  `json:"category"`
		Confidence float32 `json:"confidence"`
		Rationale  string  `json:"rationale"`
	}
	if err := json.Unmarshal([]byte(env.Response), &out); err != nil {
		return Proposal{}, fmt.Errorf("llm response not valid JSON: %w (raw=%s)", err, env.Response)
	}

	prop := Proposal{
		Address:     sig.Address,
		Label:       out.Label,
		Category:    out.Category,
		Confidence:  out.Confidence,
		Rationale:   out.Rationale,
		SignalsJSON: sigJSON,
	}

	// Hard structural gate — EOAs cannot be contract-only categories. This
	// is enforced in code, not just prompted, because validation showed
	// the model will hallucinate a well-known identity ("Tether") from
	// surface hex-string similarity even when is_contract is explicitly
	// false in its own input signals. A model claiming contract-only
	// identity for a plain EOA with no supporting evidence is itself a
	// scam-adjacent pattern (e.g. a fake "deposit address" scam), not a
	// borderline call — flag it, don't silently downgrade it.
	contractOnlyCategories := map[string]bool{"exchange": true, "bridge": true, "contract": true, "token": true, "token-scam": true}
	if !sig.IsContract && contractOnlyCategories[prop.Category] {
		original := fmt.Sprintf("%s/%s (conf %.2f): %s", prop.Label, prop.Category, prop.Confidence, prop.Rationale)
		prop.Category = "scam"
		prop.Label = "unverified identity claim"
		prop.Confidence = 0.9
		prop.Rationale = fmt.Sprintf(
			"Hard override: is_contract=false but model claimed a contract-only identity. An EOA cannot be a contract/token/exchange/bridge — rejected unsupported claim. Original model output: %s",
			original,
		)
	}

	// Hard post-classification override — not a prompt hint, a code-level
	// gate the LLM cannot talk its way around. Validation caught the LLM
	// pattern-matching a scam contract's self-reported "Tether" name and
	// confidently (0.95) calling it a trusted exchange, without checking
	// the address against the real USDT contract. A name match without an
	// address match is itself near-certain evidence of impersonation, not
	// evidence of identity — it inverts the LLM's own reasoning on purpose.
	// A fake token impersonating a real one is "token-scam" (it IS a token
	// contract, and IS the scam); impersonation by something that isn't
	// itself a token contract is plain "scam".
	if sig.BrandCheck.IsImpersonation {
		category := "scam"
		if sig.IsContract && sig.TokenSymbol != "" {
			category = "token-scam"
		}
		prop.Category = category
		prop.Label = fmt.Sprintf("%s (impersonation)", sig.BrandCheck.ClaimsBrand)
		prop.Confidence = 0.98
		prop.Rationale = fmt.Sprintf(
			"Hard override: claims to be %q but address does not match the canonical contract (%s). Name match without address match is impersonation, not identity.",
			sig.BrandCheck.ClaimsBrand, sig.BrandCheck.CanonicalAddress,
		)
	}

	return prop, nil
}
