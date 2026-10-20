// Package parse turns one raw_events row into zero or one normalized event
// in the common schema described in docs/EVENT_SCHEMA_V1.md.
//
// Each source gets its own parser (ParseAuth, ParseAuditd, ParseDNS), all
// returning the same ParsedEvent shape so the normalizer (cmd/normalizer)
// doesn't need to know source-specific details.
package parse

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"
)

// Role names used as keys in ParsedEvent.Entities. The normalizer maps each
// role to one fixed column on the events table (see
// pipeline/schema/002_normalize.sql); adding a new role means adding a new
// column, not changing this list casually.
const (
	RoleUser          = "user"
	RoleProcess       = "process"
	RoleParentProcess = "parent_process"
	RoleSrcIP         = "src_ip"
	RoleDomain        = "domain"
)

// Entity types. Kept distinct from role names: a role is "what part this
// entity plays in this event", a type is "what kind of thing it is" - the
// same type (ip) can fill different roles in different event types.
const (
	EntityTypeHost         = "host"
	EntityTypeUser         = "user"
	EntityTypeProcessImage = "process_image"
	EntityTypeIP           = "ip"
	EntityTypeDomain       = "domain"
)

// Entity is one participant in an event: its type and its value. ID() is
// deterministic, so the same (type, value) pair always resolves to the same
// row in the entities table, with no coordination between parsers,
// processes, or restarts.
type Entity struct {
	Type  string
	Value string
}

// ID returns a stable, deterministic identifier for this entity. It is a
// content hash, not a sequence number, specifically so that:
//   - re-processing the same raw_events row twice (e.g. after a crash)
//     yields the same entity id, not a duplicate row;
//   - the normalizer needs no shared counter or lookup-then-insert race
//     (upserts are safe to run concurrently without a round trip first).
func (e Entity) ID() string {
	return EntityID(e.Type, e.Value)
}

// EntityID computes the deterministic id for a given type and value.
// Exported separately from Entity.ID so callers (tests, the normalizer, a
// future rules engine) can compute an id to look up without constructing an
// Entity first.
func EntityID(entityType, value string) string {
	sum := sha256.Sum256([]byte(entityType + "|" + value))
	return hex.EncodeToString(sum[:])[:16]
}

// ParsedEvent is the common shape every parser produces.
type ParsedEvent struct {
	EventTime time.Time
	EventType string // e.g. "auth.login_failure", "process.exec", "dns.query"
	Outcome   string // "success" | "failure" | "" if not applicable
	Entities  map[string]Entity
	Fields    map[string]interface{} // event-type-specific extras: port, pid, argv, ...
}

func newParsedEvent(eventType string, eventTime time.Time) *ParsedEvent {
	return &ParsedEvent{
		EventTime: eventTime,
		EventType: eventType,
		Entities:  map[string]Entity{},
		Fields:    map[string]interface{}{},
	}
}

// DedupKey computes the content-hash-plus-time-bucket key used to collapse
// exact repeats of the same line within the same minute into one event row
// (UNIQUE(dedup_key) on the events table enforces this). Truncating to the
// minute means the identical line reappearing an hour later - a repeat SSH
// brute-force wave, say - is still recorded as a new event, which is the
// behavior later rule/correlation logic depends on.
func DedupKey(source, host, rawLine string, eventTime time.Time) string {
	bucket := eventTime.UTC().Truncate(time.Minute).Format(time.RFC3339)
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%s", source, host, rawLine, bucket)))
	return hex.EncodeToString(sum[:])
}
