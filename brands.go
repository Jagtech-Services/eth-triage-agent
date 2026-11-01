package main

import "strings"

// knownBrands maps canonical lowercase symbol/name tokens to their real
// mainnet contract address. Used to catch impersonation: a contract or
// token claiming to be one of these names at any OTHER address is almost
// certainly a scam, regardless of how "legitimate" its other signals look.
//
// This exists because validation caught a real, dangerous failure mode: the
// LLM pattern-matched a scam contract's self-reported name ("Tether") and
// classified it as a trusted exchange at 0.95 confidence, without ever
// checking the address against the real USDT contract. Name-matching alone
// is not evidence of identity — it's exactly what an impersonator sets.
var knownBrands = map[string]string{
	"tether": strings.ToLower(addrUSDT),
	"usdt":   strings.ToLower(addrUSDT),
	"usdc":   strings.ToLower(addrUSDC),
	"usd coin": strings.ToLower(addrUSDC),
	"weth":   strings.ToLower(addrWETH),
	"wrapped ether": strings.ToLower(addrWETH),
}

// BrandCheck is the result of checking a candidate address's self-reported
// name/symbol against the known-brand canonical address list.
type BrandCheck struct {
	ClaimsBrand      string `json:"claims_brand,omitempty"`       // which known brand name it matches, if any
	CanonicalAddress string `json:"canonical_address,omitempty"`  // the real address for that brand
	IsImpersonation  bool   `json:"is_impersonation,omitempty"`    // claims a brand but isn't the canonical address
}

// checkBrandImpersonation inspects every name-shaped signal we have
// (contract name, token symbol, token name) against the known-brand list.
// Matching is substring-based and case-insensitive on purpose — scam
// contracts often embed the real name inside a longer string
// ("Tether USD (PoS)", "USD Tether V2") to pass casual review.
func checkBrandImpersonation(sig AddrSignals) BrandCheck {
	addrLower := strings.ToLower(sig.Address)
	candidates := []string{sig.ContractName, sig.TokenSymbol, sig.TokenName}

	for _, c := range candidates {
		cLower := strings.ToLower(c)
		if cLower == "" {
			continue
		}
		for brand, canonical := range knownBrands {
			if strings.Contains(cLower, brand) {
				return BrandCheck{
					ClaimsBrand:      brand,
					CanonicalAddress: canonical,
					IsImpersonation:  addrLower != canonical,
				}
			}
		}
	}
	return BrandCheck{}
}
