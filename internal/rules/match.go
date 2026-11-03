package rules

import (
	"fmt"
	"regexp"
	"strings"
)

var allowedSelectionKeys = map[string]bool{
	"event_type":         true,
	"outcome":            true,
	"host":               true,
	"user":               true,
	"process":            true,
	"parent_process":     true,
	"src_ip":             true,
	"domain":             true,
	"domain_entropy_gte": true,
	"argv_contains":      true,
	"command_contains":   true,
	"path":               true,
	"path_regex":         true,
}

func selectionMatches(selection Selection, ctx MatchContext) bool {
	for key, want := range selection {
		if !matchOne(key, want, ctx) {
			return false
		}
	}
	return true
}

func matchOne(key string, want interface{}, ctx MatchContext) bool {
	switch key {
	case "event_type":
		return ctx.EventType == asString(want)
	case "outcome":
		return ctx.Outcome == asString(want)
	case "host":
		return ctx.Host == asString(want)
	case "user":
		return ctx.User == asString(want)
	case "process":
		return ctx.Process == asString(want)
	case "parent_process":
		return ctx.ParentProcess == asString(want)
	case "src_ip":
		return ctx.SrcIP == asString(want)
	case "domain":
		return ctx.Domain == asString(want)
	case "domain_entropy_gte":
		return ctx.Domain != "" && ctx.DomainEntropy >= asFloat(want)
	case "argv_contains":
		return fieldContains(ctx.Fields["argv"], asString(want))
	case "command_contains":
		command, _ := ctx.Fields["command"].(string)
		return strings.Contains(command, asString(want))
	case "path":
		path, _ := ctx.Fields["path"].(string)
		return path == asString(want)
	case "path_regex":
		path, _ := ctx.Fields["path"].(string)
		re, err := regexp.Compile(asString(want))
		return err == nil && re.MatchString(path)
	default:
		return false
	}
}

func fieldContains(field interface{}, want string) bool {
	switch value := field.(type) {
	case []interface{}:
		for _, item := range value {
			if strings.Contains(asString(item), want) {
				return true
			}
		}
	case []string:
		for _, item := range value {
			if strings.Contains(item, want) {
				return true
			}
		}
	case string:
		return strings.Contains(value, want)
	}
	return false
}

func asString(value interface{}) string {
	if value == nil {
		return ""
	}
	if text, ok := value.(string); ok {
		return text
	}
	return fmt.Sprint(value)
}

func asFloat(value interface{}) float64 {
	switch number := value.(type) {
	case int:
		return float64(number)
	case int64:
		return float64(number)
	case float32:
		return float64(number)
	case float64:
		return number
	default:
		return 0
	}
}
