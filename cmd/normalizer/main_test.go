package main

import (
	"context"
	"database/sql"
	"os"
	"testing"

	_ "github.com/lib/pq"
)

// TestNormalizeBatch exercises the full normalizer loop against a real
// Postgres instance. Set TEST_DATABASE_URL to run it:
//
//	TEST_DATABASE_URL=postgres://postgres:postgres@localhost:5432/detection?sslmode=disable go test ./...
func TestNormalizeBatch(t *testing.T) {
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

	for _, stmt := range []string{
		`TRUNCATE events, entities, parse_failures, raw_events RESTART IDENTITY CASCADE`,
		`UPDATE normalizer_cursor SET last_raw_event_id = 0 WHERE id = 1`,
	} {
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			t.Fatalf("reset: %v (%s)", err, stmt)
		}
	}

	// Insert a realistic mix: two auth lines (a failed login that should
	// parse, and a malformed line that should not), one auditd EXECVE
	// event, and one DNS query - all as Phase 1's consumer would have
	// written them.
	type seedRow struct {
		source, host, rawLine string
		payload               interface{}
	}
	seeds := []seedRow{
		{"auth", "lab-host-1", "Oct 18 10:27:40 lab-host-1 sshd[1001]: Failed password for admin from 198.51.100.23 port 40001 ssh2", nil},
		{"auth", "lab-host-1", "not a valid syslog line", nil},
		{"auditd", "lab-host-1", `{"type":"EXECVE","timestamp":"2026-10-18T10:27:08Z","host":"lab-host-1","uid":"www-data","pid":4321,"ppid":4100,"exe":"/bin/bash","argv":["bash","-c","evil"],"parent_exe":"/usr/sbin/apache2"}`, nil},
		{"dns", "lab-host-1", "2026-10-18T10:27:08Z client=127.0.0.1 query=x7qz9f.bad-c2-example.net type=A", nil},
	}
	seeds[2].payload = seeds[2].rawLine // auditd line is itself valid JSON

	for i, s := range seeds {
		_, err := db.ExecContext(ctx, `
			INSERT INTO raw_events (source, host, kafka_topic, kafka_partition, kafka_offset, raw_line, payload)
			VALUES ($1, $2, 'test-topic', 0, $3, $4, $5)
		`, s.source, s.host, i, s.rawLine, s.payload)
		if err != nil {
			t.Fatalf("seed raw_events[%d]: %v", i, err)
		}
	}

	n, err := normalizeBatch(ctx, db, 100)
	if err != nil {
		t.Fatalf("normalizeBatch: %v", err)
	}
	if n != len(seeds) {
		t.Fatalf("expected %d raw rows processed, got %d", len(seeds), n)
	}

	// 3 of the 4 seeds should have parsed into events; the malformed auth
	// line should have landed in parse_failures instead.
	var eventCount, failureCount int
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM events`).Scan(&eventCount); err != nil {
		t.Fatalf("count events: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT count(*) FROM parse_failures`).Scan(&failureCount); err != nil {
		t.Fatalf("count parse_failures: %v", err)
	}
	if eventCount != 3 {
		t.Errorf("expected 3 events, got %d", eventCount)
	}
	if failureCount != 1 {
		t.Errorf("expected 1 parse_failures row, got %d", failureCount)
	}

	// The auth.login_failure event should have extracted a user entity
	// ("admin") and an ip entity ("198.51.100.23"), both resolvable via
	// the deterministic entity id.
	var eventType string
	var userEntity, srcIPEntity sql.NullString
	err = db.QueryRowContext(ctx, `
		SELECT event_type, user_entity, src_ip_entity FROM events WHERE source = 'auth'
	`).Scan(&eventType, &userEntity, &srcIPEntity)
	if err != nil {
		t.Fatalf("query auth event: %v", err)
	}
	if eventType != "auth.login_failure" {
		t.Errorf("expected event_type auth.login_failure, got %s", eventType)
	}
	if !userEntity.Valid || !srcIPEntity.Valid {
		t.Fatalf("expected user_entity and src_ip_entity to be set")
	}

	var userValue string
	if err := db.QueryRowContext(ctx, `SELECT value FROM entities WHERE id = $1`, userEntity.String).Scan(&userValue); err != nil {
		t.Fatalf("look up user entity: %v", err)
	}
	if userValue != "admin" {
		t.Errorf("expected user entity value 'admin', got %q", userValue)
	}

	// Cursor must have advanced to the last raw_events id, including past
	// the row that failed to parse - a bad line must never block progress.
	var cursor int64
	if err := db.QueryRowContext(ctx, `SELECT last_raw_event_id FROM normalizer_cursor WHERE id = 1`).Scan(&cursor); err != nil {
		t.Fatalf("read cursor: %v", err)
	}
	if cursor != int64(len(seeds)) {
		t.Errorf("expected cursor at %d, got %d", len(seeds), cursor)
	}

	// Re-running normalizeBatch must be a no-op: cursor already past
	// everything, so nothing new is read or written.
	n2, err := normalizeBatch(ctx, db, 100)
	if err != nil {
		t.Fatalf("normalizeBatch (second run): %v", err)
	}
	if n2 != 0 {
		t.Errorf("expected second run to process 0 rows, got %d", n2)
	}
}

func TestParseRowUnknownSource(t *testing.T) {
	_, err := parseRow(rawRow{Source: "nope", RawLine: "x"})
	if err == nil {
		t.Fatal("expected an error for an unknown source")
	}
}
