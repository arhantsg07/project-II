package main

import (
	"encoding/json"
	"fmt"
)

func errNotJSON(source, rawLine string) error {
	return fmt.Errorf("%s: expected a JSON payload but raw_events.payload was NULL for line: %q", source, truncate(rawLine, 120))
}

func errUnknownSource(source string) error {
	return fmt.Errorf("no parser registered for source %q", source)
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// marshalFields renders the parser's Fields map as JSON for the events.fields
// JSONB column. An empty/nil map becomes "{}" rather than "null", so SQL
// queries like `fields->>'pid'` behave the same whether or not a given
// event type happens to have extra fields.
func marshalFields(fields map[string]interface{}) ([]byte, error) {
	if len(fields) == 0 {
		return []byte("{}"), nil
	}
	return json.Marshal(fields)
}
