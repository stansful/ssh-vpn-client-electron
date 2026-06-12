package protocol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestServeLinesWritesResponseAndEvents(t *testing.T) {
	input := strings.NewReader(`{"id":"1","type":"get-status"}` + "\n")
	var output bytes.Buffer

	err := ServeLines(context.Background(), input, &output, func(context.Context, Command) CommandResult {
		return CommandResult{
			Response: OK("1", map[string]string{"state": "Disconnected"}),
			Events:   []any{map[string]string{"type": "diagnostics-appended"}},
		}
	})
	if err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected response and event lines, got %d: %q", len(lines), output.String())
	}

	var response Response
	if err := json.Unmarshal([]byte(lines[0]), &response); err != nil {
		t.Fatal(err)
	}
	if !response.OK || response.ID != "1" {
		t.Fatalf("unexpected response: %+v", response)
	}

	var envelope EventEnvelope
	if err := json.Unmarshal([]byte(lines[1]), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Kind != "event" {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
}

func TestServeLinesStopsOnShutdown(t *testing.T) {
	input := strings.NewReader(`{"id":"1","type":"shutdown"}` + "\n")
	var output bytes.Buffer

	err := ServeLines(context.Background(), input, &output, func(context.Context, Command) CommandResult {
		return CommandResult{Response: OK("1", Accepted())}
	})
	if !errors.Is(err, ErrShutdown) {
		t.Fatalf("expected ErrShutdown, got %v", err)
	}
}
