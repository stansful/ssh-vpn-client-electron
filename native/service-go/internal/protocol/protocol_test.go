package protocol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net"
	"strings"
	"testing"
	"time"
)

func TestServeLinesWritesVersionedResponseAndEvents(t *testing.T) {
	input := strings.NewReader(`{"protocolVersion":1,"id":"1","type":"get-status"}` + "\n")
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
	if !response.OK || response.ID != "1" || response.ProtocolVersion != Version {
		t.Fatalf("unexpected response: %+v", response)
	}

	var envelope EventEnvelope
	if err := json.Unmarshal([]byte(lines[1]), &envelope); err != nil {
		t.Fatal(err)
	}
	if envelope.Kind != "event" || envelope.ProtocolVersion != Version {
		t.Fatalf("unexpected envelope: %+v", envelope)
	}
}

func TestServeLinesStopsOnlyOnAuthorizedHandlerDecision(t *testing.T) {
	input := strings.NewReader(
		`{"protocolVersion":1,"id":"1","type":"shutdown","authToken":"wrong"}` + "\n" +
			`{"protocolVersion":1,"id":"2","type":"get-status","authToken":"secret"}` + "\n",
	)
	var output bytes.Buffer
	handled := 0
	err := ServeLines(context.Background(), input, &output, func(_ context.Context, command Command) CommandResult {
		handled++
		if command.ID == "1" {
			return CommandResult{Response: Error(command.ID, errors.New("unauthorized service command")), Shutdown: true}
		}
		return CommandResult{Response: OK(command.ID, Accepted())}
	})
	if err != nil {
		t.Fatalf("unauthorized shutdown stopped service: %v", err)
	}
	if handled != 2 {
		t.Fatalf("expected both commands to be handled, got %d", handled)
	}
}

func TestDecodeCommandBoundsEnvelopeIdentifiers(t *testing.T) {
	for _, input := range []string{
		`{"protocolVersion":1,"id":"` + strings.Repeat("x", maxCommandIDLen+1) + `","type":"get-status"}`,
		`{"protocolVersion":1,"id":"1","type":"` + strings.Repeat("x", maxCommandTypeLen+1) + `"}`,
		`{"protocolVersion":1,"id":"1","type":"get-status","authToken":"` + strings.Repeat("x", maxAuthTokenLen+1) + `"}`,
	} {
		if _, err := DecodeCommand(input); err == nil {
			t.Fatalf("oversized command envelope was accepted")
		}
	}
}

func TestServeLinesStopsOnExplicitShutdownResult(t *testing.T) {
	input := strings.NewReader(`{"protocolVersion":1,"id":"1","type":"shutdown"}` + "\n")
	var output bytes.Buffer

	err := ServeLines(context.Background(), input, &output, func(context.Context, Command) CommandResult {
		return CommandResult{Response: OK("1", Accepted()), Shutdown: true}
	})
	if !errors.Is(err, ErrShutdown) {
		t.Fatalf("expected ErrShutdown, got %v", err)
	}
}

func TestEndpointConnectionLimiterRejectsExcessClients(t *testing.T) {
	limiter := newEndpointConnectionLimiter()
	for index := 0; index < MaxEndpointConnections; index++ {
		if !limiter.tryAcquire() {
			t.Fatalf("connection %d was rejected before the configured limit", index)
		}
	}
	if limiter.tryAcquire() {
		t.Fatal("connection above the configured endpoint limit was accepted")
	}
	limiter.release()
	if !limiter.tryAcquire() {
		t.Fatal("released endpoint slot was not reusable")
	}
	for index := 0; index < MaxEndpointConnections; index++ {
		limiter.release()
	}
	if MaxEndpointConnections*MaxEndpointWireLineBytes > 128*1024*1024 {
		t.Fatalf("configured endpoint buffering exceeds the 128 MiB global bound")
	}
}

func TestEndpointConnectionClosesStalledPartialFrame(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		done <- serveEndpointConnection(context.Background(), server, func(context.Context, Command) CommandResult {
			return CommandResult{Response: OK("unexpected", Accepted())}
		}, 25*time.Millisecond)
	}()
	if _, err := client.Write([]byte(`{"protocolVersion":1`)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("stalled partial endpoint frame was not closed by its deadline")
	}
}

func TestEndpointConnectionAllowsIdleBetweenCompleteFrames(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- serveEndpointConnection(ctx, server, func(_ context.Context, command Command) CommandResult {
			return CommandResult{Response: OK(command.ID, Accepted())}
		}, 25*time.Millisecond)
	}()

	time.Sleep(75 * time.Millisecond)
	_ = client.SetDeadline(time.Now().Add(time.Second))
	if _, err := client.Write([]byte(`{"protocolVersion":1,"id":"idle","type":"get-status"}` + "\n")); err != nil {
		t.Fatalf("complete command was rejected after an idle period: %v", err)
	}
	line, err := bufio.NewReader(client).ReadString('\n')
	if err != nil || !strings.Contains(line, `"id":"idle"`) {
		t.Fatalf("idle endpoint did not process the next complete frame: line=%q err=%v", line, err)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("idle endpoint did not stop after cancellation")
	}
}

func TestEndpointConnectionClosesStalledWrite(t *testing.T) {
	server, client := net.Pipe()
	defer client.Close()
	done := make(chan error, 1)
	go func() {
		done <- serveEndpointConnection(context.Background(), server, func(_ context.Context, command Command) CommandResult {
			return CommandResult{Response: OK(command.ID, Accepted())}
		}, 25*time.Millisecond)
	}()
	if _, err := client.Write([]byte(`{"protocolVersion":1,"id":"blocked","type":"get-status"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("endpoint write blocked indefinitely when the client stopped reading")
	}
}

func TestWriteJSONLineRejectsOversizedFrame(t *testing.T) {
	var output bytes.Buffer
	err := WriteJSONLine(&output, map[string]string{"value": strings.Repeat("x", MaxWireLineBytes)})
	if err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("expected oversized frame error, got %v", err)
	}
}

func TestWriteJSONLineHandlesShortWrites(t *testing.T) {
	var output bytes.Buffer
	writer := &shortWriter{destination: &output, maximum: 3}
	if err := WriteJSONLine(writer, map[string]string{"value": "complete"}); err != nil {
		t.Fatal(err)
	}
	if !strings.HasSuffix(output.String(), "\n") || !strings.Contains(output.String(), `"complete"`) {
		t.Fatalf("short write truncated the frame: %q", output.String())
	}
}

func TestValidateWindowsSIDRejectsSDDLInjection(t *testing.T) {
	if err := ValidateWindowsSID("S-1-5-21-1234"); err != nil {
		t.Fatalf("valid SID was rejected: %v", err)
	}
	for _, value := range []string{"", "IU", "S-1-5-21)(A;;GA;;;IU", "S-1-five-21"} {
		if err := ValidateWindowsSID(value); err == nil {
			t.Fatalf("invalid SID %q was accepted", value)
		}
	}
}

func TestWindowsPipeSecurityDescriptorIsPerUser(t *testing.T) {
	descriptor, err := WindowsPipeSecurityDescriptor("S-1-5-21-1234")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(descriptor, ";;;IU") || !strings.Contains(descriptor, ";;;S-1-5-21-1234") {
		t.Fatalf("pipe descriptor is not restricted to the selected user: %q", descriptor)
	}
}

type shortWriter struct {
	destination *bytes.Buffer
	maximum     int
}

func (writer *shortWriter) Write(value []byte) (int, error) {
	if len(value) > writer.maximum {
		value = value[:writer.maximum]
	}
	return writer.destination.Write(value)
}
