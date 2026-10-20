package parse

import (
	"os"
	"path/filepath"
	"testing"
)

func TestParseAuditdGolden(t *testing.T) {
	dir := "testdata/auditd"
	cases := []string{
		"01_execve_reverse_shell",
		"02_path_read_shadow",
		"03_path_write_sudoers",
		"04_malformed",
		"05_missing_fields",
	}
	for _, name := range cases {
		name := name
		t.Run(name, func(t *testing.T) {
			inputPath := filepath.Join(dir, name+".json")
			goldenPath := filepath.Join(dir, name+".golden.json")

			payload, err := os.ReadFile(inputPath)
			if err != nil {
				t.Fatalf("read input: %v", err)
			}

			ev, parseErr := ParseAuditd(payload, "lab-host-1", fixedReceivedAt)

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
			if got != string(wantBytes) {
				t.Errorf("mismatch for %s\n--- got ---\n%s\n--- want ---\n%s", name, got, string(wantBytes))
			}
		})
	}
}
