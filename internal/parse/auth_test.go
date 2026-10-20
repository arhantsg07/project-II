package parse

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// update regenerates all golden files from the parser's current output.
// Run it after a deliberate change to parsing behavior, then diff the
// golden files in git to review exactly what changed:
//
//	go test ./internal/parse/... -run TestParseAuthGolden -update
var update = flag.Bool("update", false, "regenerate golden files instead of checking against them")

// fixedReceivedAt stands in for the Phase 1 consumer's raw_events.received_at.
// Using a fixed value keeps golden files stable across test runs.
var fixedReceivedAt = time.Date(2026, 10, 18, 10, 30, 0, 0, time.UTC)

func runGoldenCase(t *testing.T, dir, name string, parseFn func(line string) (*ParsedEvent, error)) {
	t.Helper()

	inputPath := filepath.Join(dir, name+".txt")
	goldenPath := filepath.Join(dir, name+".golden.json")

	inputBytes, err := os.ReadFile(inputPath)
	if err != nil {
		t.Fatalf("read input: %v", err)
	}
	line := strings.TrimRight(string(inputBytes), "\n")

	ev, parseErr := parseFn(line)

	var got string
	if parseErr != nil {
		got = "ERROR: " + parseErr.Error()
	} else {
		got = formatEvent(t, ev)
	}

	if *update {
		if err := os.WriteFile(goldenPath, []byte(got), 0o644); err != nil {
			t.Fatalf("write golden: %v", err)
		}
		return
	}

	wantBytes, err := os.ReadFile(goldenPath)
	if err != nil {
		t.Fatalf("read golden (run with -update to create it): %v", err)
	}
	want := string(wantBytes)

	if got != want {
		t.Errorf("mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", name, got, want)
	}
}

func TestParseAuthGolden(t *testing.T) {
	dir := "testdata/auth"
	cases := []string{
		"01_failed_password",
		"02_accepted_password",
		"03_session_opened",
		"04_sudo",
		"05_unrecognized",
		"06_malformed",
	}
	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			runGoldenCase(t, dir, name, func(line string) (*ParsedEvent, error) {
				return ParseAuth(line, "lab-host-1", fixedReceivedAt)
			})
		})
	}
}
