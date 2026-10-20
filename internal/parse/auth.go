package parse

import (
	"fmt"
	"regexp"
	"time"
)

// syslogPrefix strips the leading "<mon> <day> <time> <host>" that every
// line in auth.log carries, leaving the program/message part to match
// against below. The timestamp in this prefix has no year (standard
// syslog), so it is intentionally not used as the event's time - see
// docs/NORMALIZER_NOTES.md for why ParseAuth uses receivedAt instead.
var syslogPrefix = regexp.MustCompile(`^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}\s+\S+\s+(.*)$`)

var (
	reFailedPassword = regexp.MustCompile(`^sshd\[(\d+)\]: Failed password for (\S+) from (\S+) port (\d+) ssh2$`)
	reAccepted       = regexp.MustCompile(`^sshd\[(\d+)\]: Accepted (password|publickey) for (\S+) from (\S+) port (\d+) ssh2$`)
	reSessionOpened  = regexp.MustCompile(`^sshd\[(\d+)\]: pam_unix\(sshd:session\): session opened for user (\S+) by \(uid=\d+\)$`)
	reSudo           = regexp.MustCompile(`^sudo: (\S+) : TTY=(\S+) ; PWD=(\S+) ; USER=(\S+) ; COMMAND=(.+)$`)
)

// ParseAuth parses one auth.log line. receivedAt (the time the Phase 1
// consumer wrote the raw_events row) is used as the event's timestamp,
// since the syslog prefix has no year and this is a lab, not a host with a
// trusted, synced clock - see docs/NORMALIZER_NOTES.md.
//
// It returns an error only when the line doesn't even match the syslog
// prefix (genuinely malformed input, which goes to parse_failures). A line
// that matches the prefix but no known message pattern still parses
// successfully, as event type "auth.unrecognized", so a benign log format
// you haven't written a pattern for yet doesn't dead-letter the whole line.
func ParseAuth(rawLine, host string, receivedAt time.Time) (*ParsedEvent, error) {
	m := syslogPrefix.FindStringSubmatch(rawLine)
	if m == nil {
		return nil, fmt.Errorf("auth: line does not match syslog prefix format: %q", rawLine)
	}
	rest := m[1]

	if fp := reFailedPassword.FindStringSubmatch(rest); fp != nil {
		ev := newParsedEvent("auth.login_failure", receivedAt)
		ev.Outcome = "failure"
		ev.Entities[RoleUser] = Entity{Type: EntityTypeUser, Value: fp[2]}
		ev.Entities[RoleSrcIP] = Entity{Type: EntityTypeIP, Value: fp[3]}
		ev.Fields["pid"] = fp[1]
		ev.Fields["port"] = fp[4]
		return ev, nil
	}

	if ac := reAccepted.FindStringSubmatch(rest); ac != nil {
		ev := newParsedEvent("auth.login_success", receivedAt)
		ev.Outcome = "success"
		ev.Entities[RoleUser] = Entity{Type: EntityTypeUser, Value: ac[3]}
		ev.Entities[RoleSrcIP] = Entity{Type: EntityTypeIP, Value: ac[4]}
		ev.Fields["pid"] = ac[1]
		ev.Fields["auth_method"] = ac[2]
		ev.Fields["port"] = ac[5]
		return ev, nil
	}

	if so := reSessionOpened.FindStringSubmatch(rest); so != nil {
		ev := newParsedEvent("auth.session_opened", receivedAt)
		ev.Entities[RoleUser] = Entity{Type: EntityTypeUser, Value: so[2]}
		ev.Fields["pid"] = so[1]
		return ev, nil
	}

	if su := reSudo.FindStringSubmatch(rest); su != nil {
		ev := newParsedEvent("auth.sudo", receivedAt)
		ev.Entities[RoleUser] = Entity{Type: EntityTypeUser, Value: su[1]}
		ev.Fields["tty"] = su[2]
		ev.Fields["pwd"] = su[3]
		ev.Fields["run_as"] = su[4]
		ev.Fields["command"] = su[5]
		return ev, nil
	}

	// Matched the syslog envelope but no known message pattern: record it
	// rather than dead-letter it. Tighten this over time by adding patterns
	// above as you see event_type = 'auth.unrecognized' show up in events.
	ev := newParsedEvent("auth.unrecognized", receivedAt)
	ev.Fields["message"] = rest
	return ev, nil
}
