package main

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func connectPG(ctx context.Context) (*pgxpool.Pool, error) {
	cfg, err := pgConfig()
	if err != nil {
		return nil, fmt.Errorf("pg config: %w", err)
	}
	pool, err := pgxpool.New(ctx, cfg.DSN())
	if err != nil {
		return nil, fmt.Errorf("pg connect: %w", err)
	}
	return pool, nil
}

const createStagingTable = `
CREATE TABLE IF NOT EXISTS eth_address_label_proposals (
    address          TEXT PRIMARY KEY,
    proposed_label   TEXT NOT NULL,
    proposed_category TEXT NOT NULL,
    confidence       REAL NOT NULL,
    rationale        TEXT NOT NULL,
    signals_json      JSONB NOT NULL,
    status           TEXT NOT NULL DEFAULT 'pending', -- pending | approved | rejected
    created_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    reviewed_at      TIMESTAMPTZ
)`

func ensureStagingTable(ctx context.Context, pool *pgxpool.Pool) error {
	_, err := pool.Exec(ctx, createStagingTable)
	return err
}

// LabeledAddr is a known ground-truth row from eth_address_labels.
type LabeledAddr struct {
	Address  string
	Label    string
	Category string
}

func fetchAllLabeled(ctx context.Context, pool *pgxpool.Pool) ([]LabeledAddr, error) {
	rows, err := pool.Query(ctx, `SELECT address, label, COALESCE(category,'') FROM eth_address_labels ORDER BY address`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LabeledAddr
	for rows.Next() {
		var l LabeledAddr
		if err := rows.Scan(&l.Address, &l.Label, &l.Category); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// fetchUnlabeledAddrs returns distinct counterparty addresses from
// eth_wallet_transactions that have no row in eth_address_labels.
func fetchUnlabeledAddrs(ctx context.Context, pool *pgxpool.Pool, limit int) ([]string, error) {
	q := `
    SELECT DISTINCT cp AS address FROM (
        SELECT CASE WHEN t.direction = 'outbound' THEN lower(t.to_address)
                    ELSE lower(t.from_address) END AS cp
        FROM eth_wallet_transactions t
    ) x
    LEFT JOIN eth_address_labels l ON lower(l.address) = x.cp
    WHERE l.address IS NULL
    ORDER BY cp
    LIMIT $1`
	rows, err := pool.Query(ctx, q, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var a string
		if err := rows.Scan(&a); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

func upsertProposal(ctx context.Context, pool *pgxpool.Pool, p Proposal) error {
	_, err := pool.Exec(ctx, `
        INSERT INTO eth_address_label_proposals
            (address, proposed_label, proposed_category, confidence, rationale, signals_json)
        VALUES ($1,$2,$3,$4,$5,$6)
        ON CONFLICT (address) DO UPDATE SET
            proposed_label = EXCLUDED.proposed_label,
            proposed_category = EXCLUDED.proposed_category,
            confidence = EXCLUDED.confidence,
            rationale = EXCLUDED.rationale,
            signals_json = EXCLUDED.signals_json,
            created_at = now()
    `, p.Address, p.Label, p.Category, p.Confidence, p.Rationale, p.SignalsJSON)
	return err
}

// silence unused import warning helper if needed
var _ = pgx.ErrNoRows

// fetchByCategory returns all addresses currently labeled with the given
// category in eth_address_labels — used to re-run the classifier against
// an already-labeled slice (e.g. re-examining every "token" row for
// scam/honeypot signals the original labeling pass didn't check for).
func fetchByCategory(ctx context.Context, pool *pgxpool.Pool, category string) ([]LabeledAddr, error) {
	rows, err := pool.Query(ctx,
		`SELECT address, label, COALESCE(category,'') FROM eth_address_labels WHERE category = $1 ORDER BY address`,
		category)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []LabeledAddr
	for rows.Next() {
		var l LabeledAddr
		if err := rows.Scan(&l.Address, &l.Label, &l.Category); err != nil {
			return nil, err
		}
		out = append(out, l)
	}
	return out, rows.Err()
}

// updateLabelCategory promotes an existing eth_address_labels row to a new
// category/label, appending to its notes rather than overwriting them, so
// the original labeling history stays visible.
func updateLabelCategory(ctx context.Context, pool *pgxpool.Pool, address, label, category, noteAppend string) error {
	_, err := pool.Exec(ctx, `
        UPDATE eth_address_labels
        SET label = $2, category = $3,
            notes = COALESCE(notes || ' | ', '') || $4
        WHERE address = $1
    `, address, label, category, noteAppend)
	return err
}
