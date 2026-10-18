// Command consumer reads raw log events from one or more Redpanda topics and
// writes them, unparsed, into the raw_events table in Postgres.
//
// This is deliberately dumb: it does not parse fields, extract entities, or
// deduplicate. That is Phase 2 (the normalizer). Phase 1's only job is to
// prove the path collector -> Redpanda -> consumer -> Postgres works, end to
// end, without losing data and without crashing on bad input.
//
// Usage:
//
//	go run ./cmd/consumer \
//	    -brokers localhost:9092 \
//	    -topics auth.raw,auditd.raw,dns.raw \
//	    -group raw-ingest \
//	    -pg "postgres://postgres:postgres@localhost:5433/detection?sslmode=disable"
package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"log"
	"os"
	"os/signal"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	_ "github.com/lib/pq"
	"github.com/twmb/franz-go/pkg/kgo"
)

// rawEvent is one row we insert into raw_events. source and host are
// inferred from the topic name and, if present, a "host" field in a JSON
// payload; both can be refined once the collector is sending richer
// metadata (see docs/COLLECTOR_NOTES.md).
type rawEvent struct {
	Source    string
	Host      string
	Topic     string
	Partition int32
	Offset    int64
	RawLine   string
	Payload   []byte // nil if the line is not JSON
}

func main() {
	var (
		brokers   = flag.String("brokers", "localhost:9092", "comma-separated Redpanda/Kafka broker addresses")
		topicsRaw = flag.String("topics", "auth.raw,auditd.raw,dns.raw", "comma-separated topics to consume")
		group     = flag.String("group", "raw-ingest", "Kafka consumer group id")
		pgDSN     = flag.String("pg", envOr("DATABASE_URL", "postgres://postgres:postgres@localhost:5433/detection?sslmode=disable"), "Postgres connection string")
		batchMax  = flag.Int("batch-max", 500, "max rows to batch before a single INSERT")
		batchWait = flag.Duration("batch-wait", 2*time.Second, "max time to wait before flushing a partial batch")
	)
	flag.Parse()

	topics := strings.Split(*topicsRaw, ",")
	for i := range topics {
		topics[i] = strings.TrimSpace(topics[i])
	}

	db, err := sql.Open("postgres", *pgDSN)
	if err != nil {
		log.Fatalf("open postgres: %v", err)
	}
	defer db.Close()
	db.SetMaxOpenConns(4)
	if err := db.Ping(); err != nil {
		log.Fatalf("ping postgres (is it running and reachable at %s?): %v", *pgDSN, err)
	}

	cl, err := kgo.NewClient(
		kgo.SeedBrokers(strings.Split(*brokers, ",")...),
		kgo.ConsumerGroup(*group),
		kgo.ConsumeTopics(topics...),
		// Commit offsets ourselves, after a batch is durably written to
		// Postgres, so a crash mid-batch re-reads instead of losing events.
		kgo.DisableAutoCommit(),
		kgo.ConsumeResetOffset(kgo.NewOffset().AtStart()),
	)
	if err != nil {
		log.Fatalf("create kafka client: %v", err)
	}
	defer cl.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("consumer starting: brokers=%s topics=%v group=%s", *brokers, topics, *group)

	var totalInserted int64
	batch := make([]rawEvent, 0, *batchMax)

	flush := func(flushCtx context.Context) {
		if len(batch) == 0 {
			return
		}
		n, err := insertBatch(flushCtx, db, batch)
		if err != nil {
			// Do not commit offsets on failure: the batch will be re-read
			// on the next poll since we never advanced the consumer.
			log.Printf("ERROR inserting batch of %d: %v (will retry, offsets not committed)", len(batch), err)
			return
		}
		if err := cl.CommitUncommittedOffsets(flushCtx); err != nil {
			log.Printf("ERROR committing offsets after insert: %v", err)
			return
		}
		atomic.AddInt64(&totalInserted, int64(n))
		log.Printf("inserted %d rows (total %d)", n, atomic.LoadInt64(&totalInserted))
		batch = batch[:0]
	}

	for {
		if ctx.Err() != nil {
			log.Println("shutting down, flushing final batch")
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			flush(flushCtx)
			cancel()
			return
		}

		pollCtx, cancelPoll := context.WithTimeout(ctx, *batchWait)
		fetches := cl.PollFetches(pollCtx)
		pollErr := pollCtx.Err()
		cancelPoll()
		if ctx.Err() != nil {
			log.Println("shutting down, flushing final batch")
			flushCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			flush(flushCtx)
			cancel()
			return
		}
		fetches.EachError(func(topic string, partition int32, err error) {
			if errors.Is(err, context.DeadlineExceeded) && errors.Is(pollErr, context.DeadlineExceeded) {
				return
			}
			log.Printf("fetch error topic=%s partition=%d: %v", topic, partition, err)
		})

		fetches.EachRecord(func(r *kgo.Record) {
			ev := rawEvent{
				Source:    sourceFromTopic(r.Topic),
				Topic:     r.Topic,
				Partition: r.Partition,
				Offset:    r.Offset,
				RawLine:   string(r.Value),
			}
			ev.Host = hostFromRecord(r)
			if json.Valid(r.Value) {
				ev.Payload = r.Value
			}
			batch = append(batch, ev)
		})

		if len(batch) >= *batchMax || errors.Is(pollErr, context.DeadlineExceeded) {
			flush(ctx)
		}
	}
}

// sourceFromTopic maps a topic name like "auth.raw" to a short source tag
// like "auth". Keep topic names and source tags in sync as you add sources;
// see docs/COLLECTOR_NOTES.md.
func sourceFromTopic(topic string) string {
	return strings.TrimSuffix(topic, ".raw")
}

// hostFromRecord looks for a "host" header set by the collector (preferred),
// and falls back to a "host" field inside a JSON payload, and finally to
// "unknown" so a bad record never blocks the batch.
func hostFromRecord(r *kgo.Record) string {
	for _, h := range r.Headers {
		if h.Key == "host" && len(h.Value) > 0 {
			return string(h.Value)
		}
	}
	var probe struct {
		Host string `json:"host"`
	}
	if json.Valid(r.Value) {
		if err := json.Unmarshal(r.Value, &probe); err == nil && probe.Host != "" {
			return probe.Host
		}
	}
	return "unknown"
}

// insertBatch writes a batch inside a single transaction using multi-row
// VALUES, and relies on the UNIQUE(topic, partition, offset) constraint plus
// ON CONFLICT DO NOTHING so a replayed batch (e.g. after a crash before the
// offset commit) is idempotent.
func insertBatch(ctx context.Context, db *sql.DB, batch []rawEvent) (int, error) {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()

	stmt, err := tx.PrepareContext(ctx, `
		INSERT INTO raw_events (source, host, kafka_topic, kafka_partition, kafka_offset, raw_line, payload)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		ON CONFLICT (kafka_topic, kafka_partition, kafka_offset) DO NOTHING
	`)
	if err != nil {
		return 0, err
	}
	defer stmt.Close()

	watermarkStmt, err := tx.PrepareContext(ctx, `
		INSERT INTO ingest_watermarks (kafka_topic, kafka_partition, last_offset, updated_at)
		VALUES ($1, $2, $3, now())
		ON CONFLICT (kafka_topic, kafka_partition)
		DO UPDATE SET last_offset = EXCLUDED.last_offset, updated_at = now()
		WHERE ingest_watermarks.last_offset < EXCLUDED.last_offset
	`)
	if err != nil {
		return 0, err
	}
	defer watermarkStmt.Close()

	inserted := 0
	for _, ev := range batch {
		var payload interface{}
		if ev.Payload != nil {
			payload = ev.Payload
		}
		res, err := stmt.ExecContext(ctx, ev.Source, ev.Host, ev.Topic, ev.Partition, ev.Offset, ev.RawLine, payload)
		if err != nil {
			return 0, err
		}
		if n, _ := res.RowsAffected(); n > 0 {
			inserted++
		}
		// The watermark upsert's WHERE clause only advances last_offset
		// forward, so it is safe to call once per event, in any order.
		if _, err := watermarkStmt.ExecContext(ctx, ev.Topic, ev.Partition, ev.Offset); err != nil {
			return 0, err
		}
	}

	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return inserted, nil
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
