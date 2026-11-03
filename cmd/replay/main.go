// Command replay republishes recorded log lines to the Phase 1 Kafka topics.
package main

import (
	"bufio"
	"context"
	"flag"
	"fmt"
	"log"
	"math"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/twmb/franz-go/pkg/kgo"
)

var topicForFile = map[string]string{
	"auth.log":   "auth.raw",
	"auditd.log": "auditd.raw",
	"dns.log":    "dns.raw",
}

type replayRecord struct {
	topic string
	line  string
}

func main() {
	var (
		dir     = flag.String("dir", "", "directory of recorded logs (required)")
		brokers = flag.String("brokers", "localhost:9092", "comma-separated Kafka broker addresses")
		rate    = flag.Float64("rate", 20, "maximum lines per second across all files")
	)
	flag.Parse()
	if *dir == "" {
		log.Fatal("-dir is required")
	}
	if math.IsNaN(*rate) || math.IsInf(*rate, 0) || *rate <= 0 {
		log.Fatal("-rate must be a finite positive number")
	}
	interval := time.Duration(float64(time.Second) / *rate)
	if interval <= 0 {
		log.Fatal("-rate is too high to represent a positive send interval")
	}

	brokerList := strings.Split(*brokers, ",")
	for index := range brokerList {
		brokerList[index] = strings.TrimSpace(brokerList[index])
		if brokerList[index] == "" {
			log.Fatal("-brokers must contain non-empty addresses")
		}
	}

	records, err := readRecordedRecords(*dir)
	if err != nil {
		log.Fatalf("read recording: %v", err)
	}
	if len(records) == 0 {
		log.Fatalf("no log lines found in %s (expected auth.log, auditd.log, and/or dns.log)", *dir)
	}

	client, err := kgo.NewClient(kgo.SeedBrokers(brokerList...))
	if err != nil {
		log.Fatalf("create Kafka client: %v", err)
	}
	defer client.Close()

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	log.Printf("replaying %d lines from %s to %v at %.1f lines/sec", len(records), *dir, brokerList, *rate)
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for index, record := range records {
		if index > 0 {
			select {
			case <-ctx.Done():
				log.Printf("replay interrupted after %d of %d lines", index, len(records))
				return
			case <-ticker.C:
			}
		}
		kafkaRecord := &kgo.Record{Topic: record.topic, Value: []byte(record.line)}
		if err := client.ProduceSync(ctx, kafkaRecord).FirstErr(); err != nil {
			log.Fatalf("produce to %s: %v", record.topic, err)
		}
		if (index+1)%50 == 0 {
			log.Printf("sent %d/%d", index+1, len(records))
		}
	}
	log.Printf("done: replayed %d lines", len(records))
}

func readRecordedRecords(dir string) ([]replayRecord, error) {
	info, err := os.Stat(dir)
	if err != nil {
		return nil, fmt.Errorf("stat directory %s: %w", dir, err)
	}
	if !info.IsDir() {
		return nil, fmt.Errorf("%s is not a directory", dir)
	}

	filenames := []string{"auth.log", "auditd.log", "dns.log"}
	var records []replayRecord
	for _, filename := range filenames {
		topic, known := topicForFile[filename]
		if !known {
			return nil, fmt.Errorf("no topic configured for %s", filename)
		}
		path := filepath.Join(dir, filename)
		file, err := os.Open(path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("open %s: %w", path, err)
		}

		scanner := bufio.NewScanner(file)
		scanner.Buffer(make([]byte, 64*1024), 1024*1024)
		for scanner.Scan() {
			line := strings.TrimSuffix(scanner.Text(), "\r")
			if line != "" {
				records = append(records, replayRecord{topic: topic, line: line})
			}
		}
		scanErr := scanner.Err()
		closeErr := file.Close()
		if scanErr != nil {
			return nil, fmt.Errorf("read %s: %w", path, scanErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close %s: %w", path, closeErr)
		}
	}
	return records, nil
}
