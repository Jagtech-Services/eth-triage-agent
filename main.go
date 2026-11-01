package main

import (
	"context"
	"encoding/json"
	"fmt"
	"math/rand"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
)

func main() {
	ctx := context.Background()

	if len(os.Args) < 2 {
		fmt.Println("usage: eth-triage-agent <validate|apply> [--limit N] [--holdout N]")
		os.Exit(1)
	}
	cmd := os.Args[1]

	pool, err := connectPG(ctx)
	if err != nil {
		fatal("db connect", err)
	}
	defer pool.Close()

	if err := ensureStagingTable(ctx, pool); err != nil {
		fatal("ensure staging table", err)
	}

	apiKey, err := etherscanAPIKey()
	if err != nil {
		fatal("etherscan api key", err)
	}
	es := newEtherscanClient(apiKey)

	switch cmd {
	case "validate":
		holdout := flagInt("--holdout", 100)
		runValidate(ctx, pool, es, holdout)
	case "apply":
		limit := flagInt("--limit", 260)
		runApply(ctx, pool, es, limit)
	case "check":
		if len(os.Args) < 3 {
			fmt.Println("usage: eth-triage-agent check <address>")
			os.Exit(1)
		}
		runCheck(es, os.Args[2])
	case "relabel-token-scams":
		runRelabelTokenScams(ctx, pool, es)
	default:
		fmt.Printf("unknown command %q\n", cmd)
		os.Exit(1)
	}
}

// runCheck classifies a single address and prints full signal + proposal
// detail — useful for spot-checking a specific flagged address (e.g. a
// low-confidence proposal) without re-running the whole backlog.
func runCheck(es *EtherscanClient, addr string) {
	sig, err := es.GatherSignals(addr)
	if err != nil {
		fatal("gather signals", err)
	}
	sigJSON, _ := json.MarshalIndent(sig, "", "  ")
	fmt.Printf("=== Signals for %s ===\n%s\n\n", addr, string(sigJSON))

	prop, err := classifyAddress(sig)
	if err != nil {
		fatal("classify", err)
	}
	fmt.Printf("=== Proposal ===\nlabel=%s category=%s confidence=%.2f\nrationale: %s\n",
		prop.Label, prop.Category, prop.Confidence, prop.Rationale)
}

// runRelabelTokenScams re-examines every currently "token"-labeled address
// with the full signal set (glyph check, Uniswap liquidity, brand
// impersonation) and promotes any that now classify as "token-scam" —
// a spoofed/honeypot token is both a token AND a scam, not an either/or
// choice. Only promotes when the new classification is specifically
// "token-scam"; leaves plain "token" and anything else (which would
// indicate a classifier regression, not a real promotion) untouched and
// reported separately.
func runRelabelTokenScams(ctx context.Context, pool *pgxpool.Pool, es *EtherscanClient) {
	rows, err := fetchByCategory(ctx, pool, "token")
	if err != nil {
		fatal("fetch token category", err)
	}
	fmt.Printf("Re-examining %d addresses currently labeled 'token'...\n\n", len(rows))

	var promoted, unchanged, otherChange int
	for _, row := range rows {
		sig, err := es.GatherSignals(row.Address)
		if err != nil {
			fmt.Printf("  [skip] %s: %v\n", row.Address, err)
			continue
		}
		prop, err := classifyAddress(sig)
		if err != nil {
			fmt.Printf("  [skip] %s: %v\n", row.Address, err)
			continue
		}

		switch {
		case prop.Category == "token-scam":
			note := fmt.Sprintf("promoted token->token-scam by eth-triage-agent relabel pass, conf=%.2f — %s", prop.Confidence, prop.Rationale)
			if err := updateLabelCategory(ctx, pool, row.Address, prop.Label, "token-scam", note); err != nil {
				fmt.Printf("  [db-err] %s: %v\n", row.Address, err)
				continue
			}
			promoted++
			fmt.Printf("  [PROMOTED] %s %s -> token-scam (conf=%.2f) — %s\n", row.Address, row.Label, prop.Confidence, prop.Rationale)
		case prop.Category == "token":
			unchanged++
		default:
			// Classifier now disagrees in some OTHER direction (e.g. now
			// says "scam" outright, or "contract") — don't silently apply,
			// just report for manual review.
			otherChange++
			fmt.Printf("  [REVIEW] %s %s: token -> %s (conf=%.2f) — %s\n", row.Address, row.Label, prop.Category, prop.Confidence, prop.Rationale)
		}
	}

	fmt.Printf("\n=== Relabel summary ===\n")
	fmt.Printf("Promoted to token-scam: %d\n", promoted)
	fmt.Printf("Unchanged (still token): %d\n", unchanged)
	fmt.Printf("Other disagreement (flagged, not applied): %d\n", otherChange)
}

func flagInt(name string, def int) int {
	for i, a := range os.Args {
		if a == name && i+1 < len(os.Args) {
			return mustAtoi(os.Args[i+1], def)
		}
	}
	return def
}

func fatal(ctx string, err error) {
	fmt.Fprintf(os.Stderr, "FATAL [%s]: %v\n", ctx, err)
	os.Exit(1)
}

// runValidate holds out `holdout` already-labeled addresses, runs the
// classifier blind (ignoring the known category), and hand-scores
// precision/recall-shaped stats against the real human labels already in
// eth_address_labels. This is the "what worked, what didn't, how you knew"
// evidence for the job application.
func runValidate(ctx context.Context, pool *pgxpool.Pool, es *EtherscanClient, holdout int) {
	all, err := fetchAllLabeled(ctx, pool)
	if err != nil {
		fatal("fetch labeled", err)
	}
	if len(all) == 0 {
		fatal("fetch labeled", fmt.Errorf("no labeled addresses found"))
	}

	rand.Shuffle(len(all), func(i, j int) { all[i], all[j] = all[j], all[i] })
	if holdout > len(all) {
		holdout = len(all)
	}
	sample := all[:holdout]

	var correct, total int
	byCategory := map[string][2]int{} // category -> [correct, total]

	fmt.Printf("Validating against %d held-out ground-truth labels...\n\n", len(sample))

	for _, gt := range sample {
		sig, err := es.GatherSignals(gt.Address)
		if err != nil {
			fmt.Printf("  [skip] %s: signal gather error: %v\n", gt.Address, err)
			continue
		}
		prop, err := classifyAddress(sig)
		if err != nil {
			fmt.Printf("  [skip] %s: classify error: %v\n", gt.Address, err)
			continue
		}

		total++
		match := normCategory(prop.Category) == normCategory(gt.Category)
		if match {
			correct++
		}
		stats := byCategory[gt.Category]
		stats[1]++
		if match {
			stats[0]++
		}
		byCategory[gt.Category] = stats

		status := "MISS"
		if match {
			status = "match"
		}
		fmt.Printf("  [%s] %s truth=%s(%s) predicted=%s(%s) conf=%.2f — %s\n",
			status, gt.Address, gt.Label, gt.Category, prop.Label, prop.Category, prop.Confidence, prop.Rationale)
	}

	fmt.Printf("\n=== Validation summary ===\n")
	fmt.Printf("Overall accuracy: %d/%d (%.1f%%)\n", correct, total, pct(correct, total))
	fmt.Println("By ground-truth category:")
	for cat, s := range byCategory {
		fmt.Printf("  %-10s %d/%d (%.1f%%)\n", cat, s[0], s[1], pct(s[0], s[1]))
	}
}

// runApply classifies the real unlabeled backlog and writes proposals to
// the staging table for manual review/approval.
func runApply(ctx context.Context, pool *pgxpool.Pool, es *EtherscanClient, limit int) {
	addrs, err := fetchUnlabeledAddrs(ctx, pool, limit)
	if err != nil {
		fatal("fetch unlabeled", err)
	}
	fmt.Printf("Classifying %d unlabeled addresses...\n\n", len(addrs))

	var high, low int
	for _, addr := range addrs {
		sig, err := es.GatherSignals(addr)
		if err != nil {
			fmt.Printf("  [skip] %s: %v\n", addr, err)
			continue
		}
		prop, err := classifyAddress(sig)
		if err != nil {
			fmt.Printf("  [skip] %s: %v\n", addr, err)
			continue
		}
		if err := upsertProposal(ctx, pool, prop); err != nil {
			fmt.Printf("  [db-err] %s: %v\n", addr, err)
			continue
		}
		conf := "LOW "
		if prop.Confidence >= 0.75 {
			conf = "HIGH"
			high++
		} else {
			low++
		}
		fmt.Printf("  [%s conf=%.2f] %s -> %s/%s — %s\n", conf, prop.Confidence, addr, prop.Label, prop.Category, prop.Rationale)
	}
	fmt.Printf("\nWrote %d proposals (%d high-confidence, %d flagged for manual review) to eth_address_label_proposals\n", high+low, high, low)
}

func normCategory(c string) string {
	switch c {
	case "spam":
		return "scam"
	default:
		return c
	}
}

func pct(a, b int) float64 {
	if b == 0 {
		return 0
	}
	return 100 * float64(a) / float64(b)
}
