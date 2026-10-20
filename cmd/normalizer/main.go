// Command normalizer reads rows from raw_events (written by the Phase 1
// consumer), parses each one into the common event schema (see
// docs/EVENT_SCHEMA_V1.md), extracts entities with stable IDs, deduplicates,
// and writes the result into events and entities.
//
// It reads from Postgres, not Kafka - see docs/NORMALIZER_NOTES.md for why.
// Progress is tracked in normalizer_cursor (the highest raw_events.id
// processed so far), so restarting the normalizer resumes rather than
// re-processing everything, and a crash mid-batch re-reads that batch
// (the UNIQUE(dedup_key) constraint on events makes that replay safe).
//
// Usage:
//
//	go run ./cmd/normalizer -pg "postgres://postgres:postgres@localhost:5432/detection?sslmode=disable"
package main

import (
	"context"
	"database/sql"
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"detection-platform/internal/parse"
)

func main() {
	var (
		pgDSN     = flag.String("pg", envOr("DATABASE_URL", "postgres://postgres:postgres@localhost:5432/detection?sslmode=disable"), "Postgres connection string")
		batchMax  = flag.Int("batch-max", 500, "max raw_events rows to process per poll")
		pollEvery = flag.Duration("poll-interval", 2*time.Second, "how often to poll raw_events for new rows")
		runOnce   = flag.Bool("once", false, "process a single batch and exit (handy for scripts/tests)")
	)
	flag.Parse()

	db, err := sql.Open("postgres", *pgDSN)
	if err != nil {
		log.Fatalf("open postgres: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		log.Fatalf("ping postgres (is it running and reachable at %s?): %v", *pgDSN, err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("normalizer starting: pg=%s batch-max=%d poll-interval=%s", *pgDSN, *batchMax, *pollEvery)

	for {
		n, err := normalizeBatch(ctx, db, *batchMax)
		if err != nil {
			log.Printf("ERROR normalizing batch: %v", err)
		} else if n > 0 {
			log.Printf("normalized %d raw events", n)
		}

		if *runOnce {
			return
		}

		select {
		case <-ctx.Done():
			log.Println("shutting down")
			return
		case <-time.After(*pollEvery):
		}
	}
}

// rawRow is one row read from raw_events.
type rawRow struct {
	ID      int64
	Source  string
	Host    string
	RawLine string
	Payload []byte // nil if the raw line wasn't JSON
	// ReceivedAt stands in for "when this event happened" - see
	// docs/NORMALIZER_NOTES.md for why we don't try to parse a real
	// timestamp out of every source.
	ReceivedAt time.Time
}

// normalizeBatch reads up to batchMax rows after the current cursor,
// parses each, and writes entities/events/parse_failures, all within one
// transaction, then advances the cursor. Returns the number of raw_events
// rows read (successfully parsed or not - both count as "processed").
func normalizeBatch(ctx context.Context, db *sql.DB, batchMax int) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	var cursor int64
	if err := tx.QueryRowContext(ctx, `SELECT last_raw_event_id FROM normalizer_cursor WHERE id = 1 FOR UPDATE`).Scan(&cursor); err != nil {
		return 0, err
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT id, source, host, raw_line, payload, received_at
		FROM raw_events
		WHERE id > $1
		ORDER BY id
		LIMIT $2
	`, cursor, batchMax)
	if err != nil {
		return 0, err
	}
	var raws []rawRow
	for rows.Next() {
		var r rawRow
		var payload sql.NullString
		if err := rows.Scan(&r.ID, &r.Source, &r.Host, &r.RawLine, &payload, &r.ReceivedAt); err != nil {
			rows.Close()
			return 0, err
		}
		if payload.Valid {
			r.Payload = []byte(payload.String)
		}
		raws = append(raws, r)
	}
	if err := rows.Err(); err != nil {
		return 0, err
	}
	rows.Close()

	if len(raws) == 0 {
		return 0, nil
	}

	entityStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO entities (id, entity_type, value, first_seen, last_seen)
		VALUES ($1, $2, $3, $4, $4)
		ON CONFLICT (id) DO UPDATE SET last_seen = EXCLUDED.last_seen
		WHERE entities.last_seen < EXCLUDED.last_seen
	`)
	if err != nil {
		return 0, err
	}
	defer entityStmt.Close()

	eventStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO events (
			raw_event_id, event_time, source, host, event_type, outcome,
			user_entity, process_entity, parent_process_entity, src_ip_entity, domain_entity,
			fields, dedup_key
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (dedup_key) DO NOTHING
	`)
	if err != nil {
		return 0, err
	}
	defer eventStmt.Close()

	failureStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO parse_failures (raw_event_id, source, error) VALUES ($1, $2, $3)
	`)
	if err != nil {
		return 0, err
	}
	defer failureStmt.Close()

	var maxID int64
	for _, r := range raws {
		if r.ID > maxID {
			maxID = r.ID
		}

		ev, perr := parseRow(r)
		if perr != nil {
			if _, err := failureStmt.ExecContext(ctx, r.ID, r.Source, perr.Error()); err != nil {
				return 0, err
			}
			continue
		}

		entityIDs := map[string]string{} // role -> entity id
		for role, ent := range ev.Entities {
			id := ent.ID()
			if _, err := entityStmt.ExecContext(ctx, id, ent.Type, ent.Value, ev.EventTime); err != nil {
				return 0, err
			}
			entityIDs[role] = id
		}

		fieldsJSON, err := marshalFields(ev.Fields)
		if err != nil {
			return 0, err
		}

		dedupKey := parse.DedupKey(r.Source, r.Host, r.RawLine, ev.EventTime)

		_, err = eventStmt.ExecContext(ctx,
			r.ID, ev.EventTime, r.Source, r.Host, ev.EventType, nullIfEmpty(ev.Outcome),
			nullIfEmpty(entityIDs[parse.RoleUser]),
			nullIfEmpty(entityIDs[parse.RoleProcess]),
			nullIfEmpty(entityIDs[parse.RoleParentProcess]),
			nullIfEmpty(entityIDs[parse.RoleSrcIP]),
			nullIfEmpty(entityIDs[parse.RoleDomain]),
			fieldsJSON, dedupKey,
		)
		if err != nil {
			return 0, err
		}
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE normalizer_cursor SET last_raw_event_id = $1, updated_at = now() WHERE id = 1
	`, maxID); err != nil {
		return 0, err
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return len(raws), nil
}

// parseRow dispatches a raw_events row to the right parser based on source.
func parseRow(r rawRow) (*parse.ParsedEvent, error) {
	switch r.Source {
	case "auth":
		return parse.ParseAuth(r.RawLine, r.Host, r.ReceivedAt)
	case "auditd":
		if r.Payload == nil {
			return nil, errNotJSON(r.Source, r.RawLine)
		}
		return parse.ParseAuditd(r.Payload, r.Host, r.ReceivedAt)
	case "dns":
		return parse.ParseDNS(r.RawLine, r.Host, r.ReceivedAt)
	default:
		return nil, errUnknownSource(r.Source)
	}
}

func nullIfEmpty(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
