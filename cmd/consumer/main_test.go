package main

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// TestInsertBatch exercises insertBatch against a real Postgres instance.
// Set TEST_DATABASE_URL to run it, e.g. in CI:
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/detection?sslmode=disable go test ./...
//
// It is skipped by default so `go test ./...` works without a database.
func TestInsertBatch(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	defer db.Close()
	ctx := context.Background()

	if _, err := db.ExecContext(ctx, `TRUNCATE raw_events, ingest_watermarks`); err != nil {
		t.Fatalf("truncate: %v", err)
	}

	batch := []rawEvent{
		{Source: "auth", Host: "host-a", Topic: "auth.raw", Partition: 0, Offset: 1, RawLine: "sshd: Accepted password for root"},
		{Source: "auth", Host: "host-a", Topic: "auth.raw", Partition: 0, Offset: 2, RawLine: `{"host":"host-a","msg":"ok"}`, Payload: []byte(`{"host":"host-a","msg":"ok"}`)},
	}

	n, err := insertBatch(ctx, db, batch)
	if err != nil {
		t.Fatalf("insertBatch: %v", err)
	}
	if n != 2 {
		t.Fatalf("expected 2 rows inserted, got %d", n)
	}

	// Re-inserting the same batch must be a no-op (idempotent replay after a
	// crash before offset commit).
	n2, err := insertBatch(ctx, db, batch)
	if err != nil {
		t.Fatalf("insertBatch (replay): %v", err)
	}
	if n2 != 0 {
		t.Fatalf("expected 0 rows inserted on replay, got %d", n2)
	}

	var count int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM raw_events`).Scan(&count); err != nil {
		t.Fatalf("count raw_events: %v", err)
	}
	if count != 2 {
		t.Fatalf("expected 2 rows in raw_events, got %d", count)
	}

	var lastOffset int64
	if err := db.QueryRowContext(ctx, `SELECT last_offset FROM ingest_watermarks WHERE kafka_topic='auth.raw' AND kafka_partition=0`).Scan(&lastOffset); err != nil {
		t.Fatalf("watermark: %v", err)
	}
	if lastOffset != 2 {
		t.Fatalf("expected watermark 2, got %d", lastOffset)
	}

	var payload sql.NullString
	if err := db.QueryRowContext(ctx, `SELECT payload::text FROM raw_events WHERE kafka_offset=2`).Scan(&payload); err != nil {
		t.Fatalf("payload: %v", err)
	}
	if !payload.Valid {
		t.Fatalf("expected non-null payload for JSON row")
	}
}

func TestSourceFromTopic(t *testing.T) {
	if got := sourceFromTopic("auth.raw"); got != "auth" {
		t.Fatalf("got %q", got)
	}
}
