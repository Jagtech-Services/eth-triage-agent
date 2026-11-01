package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"math/big"
	"net/http"
	"strings"
	"time"
)

// Mainnet addresses used for liquidity-pair probing.
const (
	uniswapV2Factory = "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f"
	addrWETH         = "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2"
	addrUSDC         = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"
	addrUSDT         = "0xdAC17F958D2ee523a2206206994597C13D831ec7"
)

var pairingAssets = map[string]string{
	"WETH": addrWETH,
	"USDC": addrUSDC,
	"USDT": addrUSDT,
}

// minMeaningfulReserve is the minimum raw-unit reserve on the PAIRED-ASSET
// side for a pool to count as having real liquidity, not a dust/honeypot
// pool. WETH/USDC/USDT all happen to need different thresholds because of
// decimals (18 for WETH, 6 for USDC/USDT) — chosen conservatively low
// (roughly $5-10 equivalent) so we flag genuinely-empty pools without
// false-flagging small-but-real ones.
var minMeaningfulReserve = map[string]*big.Int{
	"WETH": big.NewInt(0).Mul(big.NewInt(2), big.NewInt(1e15)), // ~0.002 ETH
	"USDC": big.NewInt(5_000_000),                              // 5 USDC (6 decimals)
	"USDT": big.NewInt(5_000_000),                              // 5 USDT (6 decimals)
}

// UniswapPairInfo describes one discovered pair for a candidate token.
type UniswapPairInfo struct {
	PairedWith       string `json:"paired_with"` // "WETH" / "USDC" / "USDT"
	PairAddress      string `json:"pair_address"`
	PairedAssetReserveRaw string `json:"paired_asset_reserve_raw"`
	TokenReserveRaw  string `json:"token_reserve_raw"`
	HasMeaningfulLiquidity bool `json:"has_meaningful_liquidity"`
}

func rpcCall(method string, params []any) (json.RawMessage, error) {
	payload, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0", "id": 1, "method": method, "params": params,
	})
	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Post(drpcRPC, "application/json", bytes.NewReader(payload))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var env struct {
		Result json.RawMessage `json:"result"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&env); err != nil {
		return nil, err
	}
	if env.Error != nil {
		return nil, fmt.Errorf("rpc error: %s", env.Error.Message)
	}
	return env.Result, nil
}

func ethCall(to, data string) (string, error) {
	res, err := rpcCall("eth_call", []any{
		map[string]string{"to": to, "data": data},
		"latest",
	})
	if err != nil {
		return "", err
	}
	var hex string
	if err := json.Unmarshal(res, &hex); err != nil {
		return "", err
	}
	return hex, nil
}

// padAddress left-pads a 20-byte address to a 32-byte ABI word.
func padAddress(addr string) string {
	a := strings.TrimPrefix(strings.ToLower(addr), "0x")
	return strings.Repeat("0", 64-len(a)) + a
}

// getPair calls UniswapV2Factory.getPair(tokenA, tokenB) -> address.
// Selector: keccak256("getPair(address,address)")[:4] = 0xe6a43905
func getPair(tokenA, tokenB string) (string, error) {
	data := "0xe6a43905" + padAddress(tokenA) + padAddress(tokenB)
	hex, err := ethCall(uniswapV2Factory, data)
	if err != nil {
		return "", err
	}
	if len(hex) < 66 {
		return "", nil
	}
	pair := "0x" + hex[len(hex)-40:]
	if pair == "0x0000000000000000000000000000000000000000" {
		return "", nil // no pair exists
	}
	return pair, nil
}

// token0 calls pair.token0() -> address. Selector 0x0dfe1681.
// Needed because Uniswap V2 orders token0/token1 by address value, not by
// which token we asked about — without this, reserve0/reserve1 can't be
// correctly attributed to "the target token" vs "the paired asset."
func token0(pairAddr string) (string, error) {
	hex, err := ethCall(pairAddr, "0x0dfe1681")
	if err != nil {
		return "", err
	}
	if len(hex) < 66 {
		return "", fmt.Errorf("short token0 response: %s", hex)
	}
	return "0x" + strings.ToLower(hex[len(hex)-40:]), nil
}

// getReserves calls pair.getReserves() -> (reserve0 uint112, reserve1 uint112, ts uint32).
// Selector: keccak256("getReserves()")[:4] = 0x0902f1ac
func getReserves(pairAddr string) (r0, r1 *big.Int, err error) {
	hex, err := ethCall(pairAddr, "0x0902f1ac")
	if err != nil {
		return nil, nil, err
	}
	raw := strings.TrimPrefix(hex, "0x")
	if len(raw) < 128 {
		return big.NewInt(0), big.NewInt(0), nil
	}
	r0 = new(big.Int)
	r0.SetString(raw[0:64], 16)
	r1 = new(big.Int)
	r1.SetString(raw[64:128], 16)
	return r0, r1, nil
}

// FindUniswapPairs probes the three major pairing assets (WETH/USDC/USDT)
// for a Uniswap V2 pair involving tokenAddr. For each discovered pair, it
// determines token ordering via token0() (V2 orders by address value, not
// by call order) so reserves are correctly attributed, then checks the
// PAIRED-ASSET side's reserve against a meaningful-liquidity floor — a
// non-zero-but-dust reserve (e.g. 1 wei of WETH) is the classic
// honeypot/rug-pull signature and must NOT be treated as real liquidity.
func FindUniswapPairs(tokenAddr string) ([]UniswapPairInfo, error) {
	var out []UniswapPairInfo
	tokenLower := strings.ToLower(tokenAddr)

	for name, asset := range pairingAssets {
		pair, err := getPair(tokenAddr, asset)
		if err != nil {
			return out, fmt.Errorf("getPair(%s): %w", name, err)
		}
		if pair == "" {
			continue
		}

		t0, err := token0(pair)
		if err != nil {
			return out, fmt.Errorf("token0(%s): %w", name, err)
		}
		r0, r1, err := getReserves(pair)
		if err != nil {
			return out, fmt.Errorf("getReserves(%s): %w", name, err)
		}

		var tokenReserve, assetReserve *big.Int
		if t0 == tokenLower {
			tokenReserve, assetReserve = r0, r1
		} else {
			tokenReserve, assetReserve = r1, r0
		}

		floor, ok := minMeaningfulReserve[name]
		meaningful := ok && assetReserve.Cmp(floor) >= 0

		out = append(out, UniswapPairInfo{
			PairedWith:             name,
			PairAddress:            pair,
			PairedAssetReserveRaw:  assetReserve.String(),
			TokenReserveRaw:        tokenReserve.String(),
			HasMeaningfulLiquidity: meaningful,
		})
	}
	return out, nil
}
