package main

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestReadRecordedRecords(t *testing.T) {
	dir := t.TempDir()
	files := map[string]string{
		"auth.log":   "auth-one\n\n auth-two \r\n",
		"dns.log":    "dns-one\n",
		"auditd.log": "{\"type\":\"EXECVE\"}\n",
	}
	for name, content := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	got, err := readRecordedRecords(dir)
	if err != nil {
		t.Fatal(err)
	}
	want := []replayRecord{
		{topic: "auth.raw", line: "auth-one"},
		{topic: "auth.raw", line: " auth-two "},
		{topic: "auditd.raw", line: `{"type":"EXECVE"}`},
		{topic: "dns.raw", line: "dns-one"},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("readRecordedRecords() = %#v, want %#v", got, want)
	}
}

func TestReadRecordedRecordsMissingDirectory(t *testing.T) {
	if _, err := readRecordedRecords(filepath.Join(t.TempDir(), "missing")); err == nil {
		t.Fatal("expected an error for a missing recording directory")
	}
}
