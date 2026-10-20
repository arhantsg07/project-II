package parse

import (
	"encoding/json"
	"fmt"
	"time"
)

// auditdRecord mirrors the JSON shape the lab scripts emit (see
// lab/common.sh's log_auditd and lab/attacks/*.sh). A real auditd/eBPF
// source would need a richer adapter in front of this parser to reach the
// same shape; see docs/NORMALIZER_NOTES.md.
type auditdRecord struct {
	Type      string   `json:"type"`      // "EXECVE" | "PATH_WRITE" | "PATH_READ"
	Timestamp string   `json:"timestamp"` // RFC3339
	Host      string   `json:"host"`
	UID       string   `json:"uid"`
	PID       int      `json:"pid"`
	PPID      int      `json:"ppid"`
	Exe       string   `json:"exe"`
	Argv      []string `json:"argv"`
	ParentExe string   `json:"parent_exe"`
	Path      string   `json:"path"` // present on PATH_READ / PATH_WRITE
}

// ParseAuditd parses one auditd-style JSON payload. payload is expected to
// be the JSONB raw_events.payload captured by the Phase 1 consumer (nil
// when the raw line wasn't valid JSON, in which case the caller should
// treat it as a parse failure before calling this).
func ParseAuditd(payload []byte, host string, receivedAt time.Time) (*ParsedEvent, error) {
	var rec auditdRecord
	if err := json.Unmarshal(payload, &rec); err != nil {
		return nil, fmt.Errorf("auditd: invalid JSON: %w", err)
	}
	if rec.Type == "" || rec.Exe == "" {
		return nil, fmt.Errorf("auditd: missing required fields (type, exe) in %s", string(payload))
	}

	eventTime := receivedAt
	if rec.Timestamp != "" {
		if t, err := time.Parse(time.RFC3339, rec.Timestamp); err == nil {
			eventTime = t
		}
	}

	var eventType string
	switch rec.Type {
	case "EXECVE":
		eventType = "process.exec"
	case "PATH_WRITE":
		eventType = "file.write"
	case "PATH_READ":
		eventType = "file.read"
	default:
		return nil, fmt.Errorf("auditd: unknown record type %q", rec.Type)
	}

	ev := newParsedEvent(eventType, eventTime)
	ev.Entities[RoleUser] = Entity{Type: EntityTypeUser, Value: rec.UID}
	ev.Entities[RoleProcess] = Entity{Type: EntityTypeProcessImage, Value: rec.Exe}
	if rec.ParentExe != "" {
		ev.Entities[RoleParentProcess] = Entity{Type: EntityTypeProcessImage, Value: rec.ParentExe}
	}
	ev.Fields["pid"] = rec.PID
	ev.Fields["ppid"] = rec.PPID
	if len(rec.Argv) > 0 {
		ev.Fields["argv"] = rec.Argv
	}
	if rec.Path != "" {
		ev.Fields["path"] = rec.Path
	}
	return ev, nil
}
