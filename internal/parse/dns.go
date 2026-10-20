package parse

import (
	"fmt"
	"regexp"
	"time"
)

// reDNSLine matches lines written by lab/common.sh's log_dns, e.g.:
//
//	2026-10-18T10:27:08Z client=127.0.0.1 query=x7qz9f.bad-c2-example.net type=A
var reDNSLine = regexp.MustCompile(`^(\S+) client=(\S+) query=(\S+) type=(\S+)$`)

// ParseDNS parses one DNS query log line.
func ParseDNS(rawLine, host string, receivedAt time.Time) (*ParsedEvent, error) {
	m := reDNSLine.FindStringSubmatch(rawLine)
	if m == nil {
		return nil, fmt.Errorf("dns: line does not match expected format: %q", rawLine)
	}

	eventTime := receivedAt
	if t, err := time.Parse(time.RFC3339, m[1]); err == nil {
		eventTime = t
	}

	ev := newParsedEvent("dns.query", eventTime)
	ev.Entities[RoleSrcIP] = Entity{Type: EntityTypeIP, Value: m[2]}
	ev.Entities[RoleDomain] = Entity{Type: EntityTypeDomain, Value: m[3]}
	ev.Fields["query_type"] = m[4]
	return ev, nil
}
