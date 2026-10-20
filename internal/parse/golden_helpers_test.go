package parse

import (
	"encoding/json"
	"sort"
	"testing"
)

// formatEvent renders a ParsedEvent as deterministic, sorted-key JSON so
// golden files diff cleanly in git. Map iteration order in Go is randomized,
// so Entities and Fields are flattened into sorted slices first.
func formatEvent(t *testing.T, ev *ParsedEvent) string {
	t.Helper()

	type entityOut struct {
		Role  string `json:"role"`
		Type  string `json:"type"`
		Value string `json:"value"`
		ID    string `json:"id"`
	}

	entities := make([]entityOut, 0, len(ev.Entities))
	for role, e := range ev.Entities {
		entities = append(entities, entityOut{Role: role, Type: e.Type, Value: e.Value, ID: e.ID()})
	}
	sort.Slice(entities, func(i, j int) bool { return entities[i].Role < entities[j].Role })

	fieldKeys := make([]string, 0, len(ev.Fields))
	for k := range ev.Fields {
		fieldKeys = append(fieldKeys, k)
	}
	sort.Strings(fieldKeys)
	orderedFields := make([]map[string]interface{}, 0, len(fieldKeys))
	for _, k := range fieldKeys {
		orderedFields = append(orderedFields, map[string]interface{}{"key": k, "value": ev.Fields[k]})
	}

	out := struct {
		EventType string                   `json:"event_type"`
		EventTime string                   `json:"event_time"`
		Outcome   string                   `json:"outcome"`
		Entities  []entityOut              `json:"entities"`
		Fields    []map[string]interface{} `json:"fields"`
	}{
		EventType: ev.EventType,
		EventTime: ev.EventTime.UTC().Format("2006-01-02T15:04:05Z07:00"),
		Outcome:   ev.Outcome,
		Entities:  entities,
		Fields:    orderedFields,
	}

	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		t.Fatalf("marshal event: %v", err)
	}
	return string(b)
}
