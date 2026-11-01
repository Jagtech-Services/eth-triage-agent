package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"
)

const etherscanBase = "https://api.etherscan.io/v2/api"
const drpcRPC = "https://eth.drpc.org"

// rateLimiter enforces ~3 req/s against Etherscan's free tier.
type rateLimiter struct {
	mu   sync.Mutex
	last time.Time
	min  time.Duration
}

func newRateLimiter(perSecond float64) *rateLimiter {
	return &rateLimiter{min: time.Duration(float64(time.Second) / perSecond)}
}

func (r *rateLimiter) wait() {
	r.mu.Lock()
	defer r.mu.Unlock()
	elapsed := time.Since(r.last)
	if elapsed < r.min {
		time.Sleep(r.min - elapsed)
	}
	r.last = time.Now()
}

var esRL = newRateLimiter(3.0)

type EtherscanClient struct {
	apiKey string
	http   *http.Client
}

func newEtherscanClient(apiKey string) *EtherscanClient {
	return &EtherscanClient{apiKey: apiKey, http: &http.Client{Timeout: 20 * time.Second}}
}

func (c *EtherscanClient) get(params map[string]string) (json.RawMessage, error) {
	esRL.wait()
	q := make([]string, 0, len(params)+2)
	for k, v := range params {
		q = append(q, k+"="+v)
	}
	q = append(q, "chainid=1", "apikey="+c.apiKey)
	url := etherscanBase + "?" + strings.Join(q, "&")
	resp, err := c.http.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	var env struct {
		Status  string          `json:"status"`
		Message string          `json:"message"`
		Result  json.RawMessage `json:"result"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return nil, fmt.Errorf("etherscan parse: %w (body=%s)", err, string(body))
	}
	if env.Status == "0" && env.Message != "No transactions found" {
		return nil, fmt.Errorf("etherscan error: %s (%s)", env.Message, string(env.Result))
	}
	return env.Result, nil
}

// AddrSignals is the bundle of on-chain evidence gathered for one address.
type AddrSignals struct {
	Address                  string            `json:"address"`
	IsContract               bool              `json:"is_contract"`
	SourceVerified           bool              `json:"source_verified,omitempty"`
	ContractName             string            `json:"contract_name,omitempty"`
	TokenSymbol              string            `json:"token_symbol,omitempty"`
	TokenName                string            `json:"token_name,omitempty"`
	TokenHasSuspiciousGlyphs bool              `json:"token_has_suspicious_glyphs,omitempty"`
	TxCount                  int               `json:"tx_count"`
	FirstTxAgeDays           int               `json:"first_tx_age_days,omitempty"`
	UniswapPairs             []UniswapPairInfo `json:"uniswap_pairs,omitempty"`
	UniswapPairsChecked      bool              `json:"uniswap_pairs_checked"`
	BrandCheck               BrandCheck        `json:"brand_check"`
}

func (c *EtherscanClient) getSourceCode(addr string) (verified bool, name string, err error) {
	res, err := c.get(map[string]string{"module": "contract", "action": "getsourcecode", "address": addr})
	if err != nil {
		return false, "", err
	}
	var rows []struct {
		SourceCode  string `json:"SourceCode"`
		ContractName string `json:"ContractName"`
	}
	if err := json.Unmarshal(res, &rows); err != nil {
		return false, "", nil // non-contract addresses return odd shapes; treat as EOA
	}
	if len(rows) > 0 && rows[0].SourceCode != "" {
		return true, rows[0].ContractName, nil
	}
	return false, "", nil
}

// getTokenInfo sources the declared token symbol/name from an actual
// tokentx transfer-event log rather than the Etherscan "tokeninfo" action,
// which is Pro-tier-only and returns nothing on the free API key. This is
// also the field scam/spoof tokens actually set (the contract's own declared
// metadata, as emitted in transfer events) — it's what lets us catch
// Unicode-lookalike spoofs like "EꓔH" or "ՍЅᎠΤ" at all.
func (c *EtherscanClient) getTokenInfo(addr string) (symbol, name string, err error) {
	res, err := c.get(map[string]string{
		"module": "account", "action": "tokentx", "contractaddress": addr,
		"page": "1", "offset": "1", "sort": "asc",
	})
	if err != nil {
		return "", "", err
	}
	var rows []struct {
		TokenSymbol string `json:"tokenSymbol"`
		TokenName   string `json:"tokenName"`
	}
	if err := json.Unmarshal(res, &rows); err != nil || len(rows) == 0 {
		return "", "", nil
	}
	return rows[0].TokenSymbol, rows[0].TokenName, nil
}

// hasSuspiciousGlyphs flags non-ASCII characters in a token symbol/name —
// a strong, cheap, explicit signal for Unicode-lookalike spoof tokens
// (e.g. "EꓔH" mimicking "ETH", "ՍЅᎠΤ" mimicking "USDT") that an LLM alone
// may not reliably catch from the raw string without being told to look.
func hasSuspiciousGlyphs(s string) bool {
	for _, r := range s {
		if r > 127 {
			return true
		}
	}
	return false
}

func (c *EtherscanClient) getTxCount(addr string) (int, error) {
	res, err := c.get(map[string]string{
		"module": "account", "action": "txlist", "address": addr,
		"startblock": "0", "endblock": "99999999", "page": "1", "offset": "1", "sort": "asc",
	})
	if err != nil {
		return 0, err
	}
	var rows []json.RawMessage
	_ = json.Unmarshal(res, &rows)
	// Etherscan doesn't give a direct count endpoint on free tier; approximate
	// with presence/absence. A real count would need proxy module calls.
	if len(rows) > 0 {
		return 1, nil // at least one tx exists; good enough signal for triage
	}
	return 0, nil
}

// GatherSignals pulls the on-chain evidence bundle used for classification.
func (c *EtherscanClient) GatherSignals(addr string) (AddrSignals, error) {
	sig := AddrSignals{Address: addr}

	verified, name, err := c.getSourceCode(addr)
	if err != nil {
		return sig, err
	}
	sig.SourceVerified = verified
	sig.ContractName = name
	sig.IsContract = verified // refined below if token lookup succeeds

	symbol, tname, err := c.getTokenInfo(addr)
	if err == nil && symbol != "" {
		sig.TokenSymbol = symbol
		sig.TokenName = tname
		sig.IsContract = true
		sig.TokenHasSuspiciousGlyphs = hasSuspiciousGlyphs(symbol) || hasSuspiciousGlyphs(tname)

		// Token identified — probe for real Uniswap liquidity. No pair
		// against any major asset (or only drained/zero-reserve pairs) is
		// a strong independent scam/rug-pull signal, separate from and
		// complementary to the glyph-spoof check.
		pairs, perr := FindUniswapPairs(addr)
		if perr == nil {
			sig.UniswapPairs = pairs
			sig.UniswapPairsChecked = true
		}
	}

	n, err := c.getTxCount(addr)
	if err == nil {
		sig.TxCount = n
	}

	// Brand-impersonation check runs regardless of contract/token status —
	// a verified contract's self-reported ContractName can claim a brand
	// just as easily as a token symbol can.
	sig.BrandCheck = checkBrandImpersonation(sig)

	return sig, nil
}
