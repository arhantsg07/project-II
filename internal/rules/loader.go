package rules

import (
	"bytes"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"time"

	"gopkg.in/yaml.v3"
)

var validSeverity = map[string]bool{"low": true, "medium": true, "high": true}

// LoadRules reads and validates all top-level .yaml files in dir.
func LoadRules(dir string) ([]Rule, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("read rules directory %s: %w", dir, err)
	}

	var paths []string
	for _, entry := range entries {
		if entry.IsDir() || filepath.Ext(entry.Name()) != ".yaml" {
			continue
		}
		paths = append(paths, filepath.Join(dir, entry.Name()))
	}
	if len(paths) == 0 {
		return nil, fmt.Errorf("no .yaml rule files found in %s", dir)
	}
	sort.Strings(paths)

	loaded := make([]Rule, 0, len(paths))
	seenIDs := make(map[string]string, len(paths))
	for _, path := range paths {
		rule, err := readRule(path)
		if err != nil {
			return nil, err
		}
		if previous, exists := seenIDs[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate rule id %q in %s (already defined in %s)", rule.ID, path, previous)
		}
		seenIDs[rule.ID] = path
		loaded = append(loaded, rule)
	}
	return loaded, nil
}

func readRule(path string) (Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Rule{}, fmt.Errorf("read %s: %w", path, err)
	}

	var rule Rule
	decoder := yaml.NewDecoder(bytes.NewReader(data))
	decoder.KnownFields(true)
	if err := decoder.Decode(&rule); err != nil {
		return Rule{}, fmt.Errorf("parse %s: %w", path, err)
	}
	if err := validateRule(rule); err != nil {
		return Rule{}, fmt.Errorf("invalid rule in %s: %w", path, err)
	}
	return rule, nil
}

func validateRule(rule Rule) error {
	if rule.ID == "" {
		return fmt.Errorf("missing id")
	}
	if rule.Title == "" {
		return fmt.Errorf("missing title")
	}
	if !validSeverity[rule.Severity] {
		return fmt.Errorf("severity must be low, medium, or high; got %q", rule.Severity)
	}
	if len(rule.Detection) == 0 {
		return fmt.Errorf("detection must have at least one selection")
	}

	for index, selection := range rule.Detection {
		if len(selection) == 0 {
			return fmt.Errorf("detection[%d] is empty", index)
		}
		for key, value := range selection {
			if !allowedSelectionKeys[key] {
				return fmt.Errorf("detection[%d] uses unknown key %q", index, key)
			}
			switch key {
			case "path_regex":
				pattern, ok := value.(string)
				if !ok {
					return fmt.Errorf("detection[%d].path_regex must be a string", index)
				}
				if pattern == "" {
					return fmt.Errorf("detection[%d].path_regex must not be empty", index)
				}
				if _, err := regexp.Compile(pattern); err != nil {
					return fmt.Errorf("detection[%d].path_regex is invalid: %w", index, err)
				}
			case "domain_entropy_gte":
				threshold := asFloat(value)
				if threshold <= 0 || math.IsNaN(threshold) || math.IsInf(threshold, 0) {
					return fmt.Errorf("detection[%d].domain_entropy_gte must be positive", index)
				}
			default:
				text, ok := value.(string)
				if !ok {
					return fmt.Errorf("detection[%d].%s must be a string", index, key)
				}
				if text == "" {
					return fmt.Errorf("detection[%d].%s must not be empty", index, key)
				}
			}
		}
	}

	if rule.Aggregation != nil {
		aggregation := rule.Aggregation
		switch aggregation.GroupBy {
		case "src_ip", "user", "domain", "process", "host":
		default:
			return fmt.Errorf("aggregation.group_by must be src_ip, user, domain, process, or host; got %q", aggregation.GroupBy)
		}
		window, err := time.ParseDuration(aggregation.Window)
		if err != nil {
			return fmt.Errorf("aggregation.window is invalid: %w", err)
		}
		if window <= 0 {
			return fmt.Errorf("aggregation.window must be positive")
		}
		if aggregation.CountGTE < 2 {
			return fmt.Errorf("aggregation.count_gte must be at least 2")
		}
		if len(rule.Detection) != 1 || len(rule.Detection[0]) != 1 {
			return fmt.Errorf("aggregation requires exactly one selection containing only event_type")
		}
		if _, ok := rule.Detection[0]["event_type"]; !ok {
			return fmt.Errorf("aggregation selection must include event_type")
		}
	}
	return nil
}
