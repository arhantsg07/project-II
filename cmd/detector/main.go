// Command detector evaluates normalized events and writes rule/IOC alerts.
// It polls Postgres and advances a transactional cursor, just like the normalizer.
package main

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/lib/pq"

	"detection-platform/internal/rules"
)

func main() {
	var (
		pgDSN     = flag.String("pg", envOr("DATABASE_URL", "postgres://postgres:postgres@localhost:5433/detection?sslmode=disable"), "Postgres connection string")
		rulesDir  = flag.String("rules", "./rules", "directory of rule YAML files")
		batchMax  = flag.Int("batch-max", 500, "maximum events per poll")
		pollEvery = flag.Duration("poll-interval", 2*time.Second, "poll interval")
		runOnce   = flag.Bool("once", false, "process all currently available events and exit")
	)
	flag.Parse()
	if *batchMax < 1 {
		log.Fatal("-batch-max must be positive")
	}
	if *pollEvery <= 0 {
		log.Fatal("-poll-interval must be positive")
	}

	loadedRules, err := rules.LoadRules(*rulesDir)
	if err != nil {
		log.Fatalf("load rules: %v", err)
	}

	db, err := sql.Open("postgres", *pgDSN)
	if err != nil {
		log.Fatalf("open Postgres: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		log.Fatalf("ping Postgres: %v", err)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("detector starting: rules=%d directory=%s batch-max=%d poll-interval=%s", len(loadedRules), *rulesDir, *batchMax, *pollEvery)
	for {
		processed, alertCount, err := detectBatch(ctx, db, loadedRules, *batchMax)
		if err != nil && *runOnce {
			log.Fatalf("detect batch: %v", err)
		}
		if err != nil && !errors.Is(err, context.Canceled) {
			log.Printf("ERROR detecting batch: %v", err)
		} else if processed > 0 {
			log.Printf("evaluated %d events, raised %d alerts", processed, alertCount)
		}

		if *runOnce {
			if processed == 0 {
				return
			}
			continue
		}
		select {
		case <-ctx.Done():
			log.Println("shutting down")
			return
		case <-time.After(*pollEvery):
		}
	}
}

type eventRow struct {
	ID            int64
	EventTime     time.Time
	Source        string
	Host          string
	EventType     string
	Outcome       sql.NullString
	UserEntity    sql.NullString
	ProcessEntity sql.NullString
	ParentEntity  sql.NullString
	SrcIPEntity   sql.NullString
	DomainEntity  sql.NullString
	UserValue     sql.NullString
	ProcessValue  sql.NullString
	ParentValue   sql.NullString
	SrcIPValue    sql.NullString
	DomainValue   sql.NullString
	Fields        []byte
}

// detectBatch evaluates one ordered batch and commits alerts with cursor progress.
func detectBatch(ctx context.Context, db *sql.DB, loadedRules []rules.Rule, batchMax int) (int, int, error) {
	if batchMax < 1 {
		return 0, 0, fmt.Errorf("batch size must be positive")
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, 0, err
	}
	defer tx.Rollback()

	var cursor int64
	if err := tx.QueryRowContext(ctx, `SELECT last_event_id FROM alert_cursor WHERE id = 1 FOR UPDATE`).Scan(&cursor); err != nil {
		return 0, 0, fmt.Errorf("read alert cursor: %w", err)
	}

	rows, err := tx.QueryContext(ctx, `
		SELECT e.id, e.event_time, e.source, e.host, e.event_type, e.outcome,
		       e.user_entity, e.process_entity, e.parent_process_entity, e.src_ip_entity, e.domain_entity,
		       ue.value, pe.value, ppe.value, se.value, de.value, e.fields
		FROM events e
		LEFT JOIN entities ue ON ue.id = e.user_entity
		LEFT JOIN entities pe ON pe.id = e.process_entity
		LEFT JOIN entities ppe ON ppe.id = e.parent_process_entity
		LEFT JOIN entities se ON se.id = e.src_ip_entity
		LEFT JOIN entities de ON de.id = e.domain_entity
		WHERE e.id > $1
		ORDER BY e.id
		LIMIT $2
	`, cursor, batchMax)
	if err != nil {
		return 0, 0, fmt.Errorf("read events: %w", err)
	}

	var events []eventRow
	for rows.Next() {
		var event eventRow
		if err := rows.Scan(
			&event.ID, &event.EventTime, &event.Source, &event.Host, &event.EventType, &event.Outcome,
			&event.UserEntity, &event.ProcessEntity, &event.ParentEntity, &event.SrcIPEntity, &event.DomainEntity,
			&event.UserValue, &event.ProcessValue, &event.ParentValue, &event.SrcIPValue, &event.DomainValue,
			&event.Fields,
		); err != nil {
			rows.Close()
			return 0, 0, fmt.Errorf("scan event: %w", err)
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return 0, 0, fmt.Errorf("iterate events: %w", err)
	}
	if err := rows.Close(); err != nil {
		return 0, 0, fmt.Errorf("close event rows: %w", err)
	}
	if len(events) == 0 {
		return 0, 0, nil
	}

	alertStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO alerts (
			source, rule_id, title, severity, attack_techniques, host, event_id,
			group_key, evidence_event_ids, entities, confidence, details, dedup_key
		) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
		ON CONFLICT (dedup_key) DO NOTHING
	`)
	if err != nil {
		return 0, 0, fmt.Errorf("prepare alert insert: %w", err)
	}
	defer alertStmt.Close()

	var alertCount int
	var maxID int64
	for _, event := range events {
		maxID = event.ID
		matchContext, err := buildMatchContext(event)
		if err != nil {
			return 0, 0, fmt.Errorf("build match context for event %d: %w", event.ID, err)
		}
		for _, rule := range loadedRules {
			if !rule.Matches(matchContext) {
				continue
			}
			var raised bool
			if rule.Aggregation != nil {
				raised, err = evaluateAggregation(ctx, tx, alertStmt, rule, matchContext, event)
			} else {
				raised, err = raiseRuleAlert(ctx, alertStmt, rule, matchContext, event)
			}
			if err != nil {
				return 0, 0, fmt.Errorf("evaluate rule %q on event %d: %w", rule.ID, event.ID, err)
			}
			if raised {
				alertCount++
			}
		}

		iocAlerts, err := evaluateIOCs(ctx, tx, alertStmt, matchContext, event)
		if err != nil {
			return 0, 0, fmt.Errorf("evaluate IOCs on event %d: %w", event.ID, err)
		}
		alertCount += iocAlerts
	}

	if _, err := tx.ExecContext(ctx, `
		UPDATE alert_cursor SET last_event_id = $1, updated_at = now() WHERE id = 1
	`, maxID); err != nil {
		return 0, 0, fmt.Errorf("advance alert cursor: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return 0, 0, fmt.Errorf("commit detection batch: %w", err)
	}
	return len(events), alertCount, nil
}

func buildMatchContext(event eventRow) (rules.MatchContext, error) {
	matchContext := rules.MatchContext{
		EventID:       event.ID,
		EventType:     event.EventType,
		Outcome:       event.Outcome.String,
		Host:          event.Host,
		User:          event.UserValue.String,
		Process:       event.ProcessValue.String,
		ParentProcess: event.ParentValue.String,
		SrcIP:         event.SrcIPValue.String,
		Domain:        event.DomainValue.String,
		Fields:        make(map[string]interface{}),
		EntityIDs:     make(map[string]string),
	}
	matchContext.DomainEntropy = rules.LeftmostLabelEntropy(matchContext.Domain)
	for role, entity := range map[string]sql.NullString{
		"user":           event.UserEntity,
		"process":        event.ProcessEntity,
		"parent_process": event.ParentEntity,
		"src_ip":         event.SrcIPEntity,
		"domain":         event.DomainEntity,
	} {
		if entity.Valid {
			matchContext.EntityIDs[role] = entity.String
		}
	}
	if len(event.Fields) != 0 {
		if err := json.Unmarshal(event.Fields, &matchContext.Fields); err != nil {
			return rules.MatchContext{}, fmt.Errorf("decode event fields JSON: %w", err)
		}
		if matchContext.Fields == nil {
			matchContext.Fields = make(map[string]interface{})
		}
	}
	return matchContext, nil
}

func raiseRuleAlert(ctx context.Context, stmt *sql.Stmt, rule rules.Rule, matchContext rules.MatchContext, event eventRow) (bool, error) {
	attackJSON, err := json.Marshal(rule.Attack)
	if err != nil {
		return false, fmt.Errorf("marshal attack techniques: %w", err)
	}
	evidenceJSON, err := json.Marshal([]int64{event.ID})
	if err != nil {
		return false, fmt.Errorf("marshal evidence IDs: %w", err)
	}
	entitiesJSON, err := json.Marshal(entitySnapshot(matchContext))
	if err != nil {
		return false, fmt.Errorf("marshal entity snapshot: %w", err)
	}
	return insertAlert(ctx, stmt, alertValues{
		source: "rule", ruleID: rule.ID, title: rule.Title, severity: rule.Severity,
		attack: string(attackJSON), host: event.Host, eventID: event.ID,
		evidence: string(evidenceJSON), entities: string(entitiesJSON), confidence: "rule",
		details: `{}`, dedupKey: sha256Hex(fmt.Sprintf("rule|%s|%d", rule.ID, event.ID)),
	})
}

func evaluateAggregation(ctx context.Context, tx *sql.Tx, stmt *sql.Stmt, rule rules.Rule, matchContext rules.MatchContext, event eventRow) (bool, error) {
	aggregation := rule.Aggregation
	window, err := time.ParseDuration(aggregation.Window)
	if err != nil {
		return false, fmt.Errorf("parse aggregation window: %w", err)
	}
	if window <= 0 {
		return false, fmt.Errorf("aggregation window must be positive")
	}
	groupID, groupValue := groupKeyFor(aggregation.GroupBy, matchContext)
	if groupValue == "" || (aggregation.GroupBy != "host" && groupID == "") {
		return false, nil
	}
	bucket := event.EventTime.UTC().Truncate(window)
	bucketEnd := bucket.Add(window)
	column, err := entityColumnFor(aggregation.GroupBy)
	if err != nil {
		return false, err
	}
	eventType := rule.Detection[0]["event_type"]

	var count int
	countQuery := fmt.Sprintf(`
		SELECT count(*) FROM events
		WHERE event_type = $1 AND %s = $2 AND event_time >= $3 AND event_time < $4
	`, column)
	if err := tx.QueryRowContext(ctx, countQuery, eventType, groupDatabaseValue(aggregation.GroupBy, groupID, groupValue), bucket, bucketEnd).Scan(&count); err != nil {
		return false, fmt.Errorf("count aggregation events: %w", err)
	}
	if count < aggregation.CountGTE {
		return false, nil
	}

	evidenceQuery := fmt.Sprintf(`
		SELECT id FROM events
		WHERE event_type = $1 AND %s = $2 AND event_time >= $3 AND event_time < $4
		ORDER BY id LIMIT 20
	`, column)
	rows, err := tx.QueryContext(ctx, evidenceQuery, eventType, groupDatabaseValue(aggregation.GroupBy, groupID, groupValue), bucket, bucketEnd)
	if err != nil {
		return false, fmt.Errorf("read aggregation evidence: %w", err)
	}
	var evidenceIDs []int64
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return false, fmt.Errorf("scan aggregation evidence: %w", err)
		}
		evidenceIDs = append(evidenceIDs, id)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return false, fmt.Errorf("iterate aggregation evidence: %w", err)
	}
	if err := rows.Close(); err != nil {
		return false, fmt.Errorf("close aggregation evidence: %w", err)
	}

	attackJSON, err := json.Marshal(rule.Attack)
	if err != nil {
		return false, fmt.Errorf("marshal attack techniques: %w", err)
	}
	evidenceJSON, err := json.Marshal(evidenceIDs)
	if err != nil {
		return false, fmt.Errorf("marshal evidence IDs: %w", err)
	}
	entitiesJSON, err := json.Marshal(entitySnapshot(matchContext))
	if err != nil {
		return false, fmt.Errorf("marshal entity snapshot: %w", err)
	}
	detailsJSON, err := json.Marshal(map[string]interface{}{
		"count": count, "window": aggregation.Window, "bucket_start": bucket,
	})
	if err != nil {
		return false, fmt.Errorf("marshal aggregation details: %w", err)
	}
	dedupKey := sha256Hex(fmt.Sprintf("rule|%s|%s|%s", rule.ID, groupValue, bucket.Format(time.RFC3339)))
	return insertAlert(ctx, stmt, alertValues{
		source: "rule", ruleID: rule.ID, title: rule.Title, severity: rule.Severity,
		attack: string(attackJSON), host: event.Host, eventID: event.ID,
		groupKey: groupValue, evidence: string(evidenceJSON), entities: string(entitiesJSON),
		confidence: "rule", details: string(detailsJSON), dedupKey: dedupKey,
	})
}

func groupKeyFor(groupBy string, matchContext rules.MatchContext) (entityID, value string) {
	switch groupBy {
	case "src_ip":
		return matchContext.EntityIDs["src_ip"], matchContext.SrcIP
	case "user":
		return matchContext.EntityIDs["user"], matchContext.User
	case "domain":
		return matchContext.EntityIDs["domain"], matchContext.Domain
	case "process":
		return matchContext.EntityIDs["process"], matchContext.Process
	case "host":
		return matchContext.Host, matchContext.Host
	default:
		return "", ""
	}
}

func entityColumnFor(groupBy string) (string, error) {
	switch groupBy {
	case "src_ip":
		return "src_ip_entity", nil
	case "user":
		return "user_entity", nil
	case "domain":
		return "domain_entity", nil
	case "process":
		return "process_entity", nil
	case "host":
		return "host", nil
	default:
		return "", fmt.Errorf("unsupported aggregation group_by %q", groupBy)
	}
}

func groupDatabaseValue(groupBy, entityID, value string) string {
	if groupBy == "host" {
		return value
	}
	return entityID
}

func evaluateIOCs(ctx context.Context, tx *sql.Tx, stmt *sql.Stmt, matchContext rules.MatchContext, event eventRow) (int, error) {
	type candidate struct {
		iocType string
		value   string
	}
	var candidates []candidate
	if matchContext.SrcIP != "" {
		candidates = append(candidates, candidate{iocType: "ip", value: matchContext.SrcIP})
	}
	if matchContext.Domain != "" {
		candidates = append(candidates, candidate{iocType: "domain", value: matchContext.Domain})
	}

	raised := 0
	for _, candidate := range candidates {
		var source, confidence string
		var contextText sql.NullString
		err := tx.QueryRowContext(ctx, `
			SELECT source, confidence, context FROM iocs
			WHERE ioc_type = $1 AND value = $2 AND (expires_at IS NULL OR expires_at > now())
		`, candidate.iocType, candidate.value).Scan(&source, &confidence, &contextText)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return raised, fmt.Errorf("lookup %s IOC: %w", candidate.iocType, err)
		}

		detailsJSON, err := json.Marshal(map[string]string{
			"ioc_source": source, "ioc_context": contextText.String,
		})
		if err != nil {
			return raised, fmt.Errorf("marshal IOC details: %w", err)
		}
		entitiesJSON, err := json.Marshal(entitySnapshot(matchContext))
		if err != nil {
			return raised, fmt.Errorf("marshal entity snapshot: %w", err)
		}
		evidenceJSON, err := json.Marshal([]int64{event.ID})
		if err != nil {
			return raised, fmt.Errorf("marshal evidence IDs: %w", err)
		}
		attackJSON, err := json.Marshal([]string{})
		if err != nil {
			return raised, fmt.Errorf("marshal attack techniques: %w", err)
		}
		inserted, err := insertAlert(ctx, stmt, alertValues{
			source: "ioc", title: "Indicator match: " + candidate.iocType,
			severity: confidence, attack: string(attackJSON), host: event.Host, eventID: event.ID,
			groupKey: candidate.value, evidence: string(evidenceJSON), entities: string(entitiesJSON),
			confidence: confidence, details: string(detailsJSON),
			dedupKey: sha256Hex(fmt.Sprintf("ioc|%s|%s|%d", candidate.iocType, candidate.value, event.ID)),
		})
		if err != nil {
			return raised, err
		}
		if inserted {
			raised++
		}
	}
	return raised, nil
}

type alertValues struct {
	source, ruleID, title, severity, attack, host string
	eventID                                       int64
	groupKey, evidence, entities, confidence      string
	details, dedupKey                             string
}

func insertAlert(ctx context.Context, stmt *sql.Stmt, alert alertValues) (bool, error) {
	var ruleID interface{}
	if alert.ruleID != "" {
		ruleID = alert.ruleID
	}
	var groupKey interface{}
	if alert.groupKey != "" {
		groupKey = alert.groupKey
	}
	result, err := stmt.ExecContext(ctx,
		alert.source, ruleID, alert.title, alert.severity, alert.attack, alert.host, alert.eventID,
		groupKey, alert.evidence, alert.entities, alert.confidence, alert.details, alert.dedupKey,
	)
	if err != nil {
		return false, err
	}
	affected, err := result.RowsAffected()
	if err != nil {
		return false, fmt.Errorf("read inserted alert count: %w", err)
	}
	return affected > 0, nil
}

func entitySnapshot(matchContext rules.MatchContext) map[string]string {
	snapshot := make(map[string]string)
	for role, value := range map[string]string{
		"user": matchContext.User, "process": matchContext.Process,
		"parent_process": matchContext.ParentProcess, "src_ip": matchContext.SrcIP,
		"domain": matchContext.Domain,
	} {
		if value != "" {
			snapshot[role] = value
		}
	}
	return snapshot
}

func sha256Hex(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
