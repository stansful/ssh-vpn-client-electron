package protocol

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

const (
	Version                  = 1
	MaxWireLineBytes         = 8 * 1024 * 1024
	MaxEndpointWireLineBytes = 4 * 1024 * 1024
	MaxEndpointConnections   = 32
	EndpointFrameIdleTimeout = 30 * time.Second
	maxCommandIDLen          = 128
	maxCommandTypeLen        = 64
	maxAuthTokenLen          = 1024
	maxWindowsSIDLen         = 184
)

var ErrShutdown = errors.New("shutdown requested")

func ValidateWindowsSID(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return errors.New("Windows client SID is empty")
	}
	if len(value) > maxWindowsSIDLen {
		return errors.New("Windows client SID is too long")
	}
	parts := strings.Split(value, "-")
	if len(parts) < 3 || parts[0] != "S" {
		return errors.New("Windows client SID has an invalid format")
	}
	for _, part := range parts[1:] {
		if part == "" {
			return errors.New("Windows client SID has an invalid format")
		}
		for _, character := range part {
			if character < '0' || character > '9' {
				return errors.New("Windows client SID has an invalid format")
			}
		}
	}
	return nil
}

func WindowsPipeSecurityDescriptor(clientSID string) (string, error) {
	clientSID = strings.TrimSpace(clientSID)
	if err := ValidateWindowsSID(clientSID); err != nil {
		return "", err
	}
	return `D:P(A;;GA;;;SY)(A;;GA;;;BA)(A;;GRGW;;;` + clientSID + `)`, nil
}

type Command struct {
	ProtocolVersion int             `json:"protocolVersion"`
	ID              string          `json:"id"`
	Type            string          `json:"type"`
	AuthToken       string          `json:"authToken,omitempty"`
	Payload         json.RawMessage `json:"payload,omitempty"`
}

type Response struct {
	ProtocolVersion int    `json:"protocolVersion"`
	Kind            string `json:"kind"`
	ID              string `json:"id"`
	OK              bool   `json:"ok"`
	Payload         any    `json:"payload,omitempty"`
	Error           string `json:"error,omitempty"`
}

type EventEnvelope struct {
	ProtocolVersion int    `json:"protocolVersion"`
	Kind            string `json:"kind"`
	Event           any    `json:"event"`
}

type CommandResult struct {
	Response Response
	Events   []any
	Shutdown bool
}

type Handler func(context.Context, Command) CommandResult

type endpointConnection interface {
	io.Reader
	io.Writer
	io.Closer
}

type endpointConnectionLimiter struct {
	slots chan struct{}
}

func newEndpointConnectionLimiter() *endpointConnectionLimiter {
	return &endpointConnectionLimiter{slots: make(chan struct{}, MaxEndpointConnections)}
}

func (limiter *endpointConnectionLimiter) tryAcquire() bool {
	select {
	case limiter.slots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (limiter *endpointConnectionLimiter) release() {
	<-limiter.slots
}

func DecodeCommand(line string) (Command, error) {
	var command Command
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &command); err != nil {
		return Command{}, err
	}
	if command.ID == "" {
		return Command{}, errors.New("command id is required")
	}
	if len(command.ID) > maxCommandIDLen {
		return Command{}, errors.New("command id is too long")
	}
	if command.Type == "" {
		return Command{}, errors.New("command type is required")
	}
	if len(command.Type) > maxCommandTypeLen {
		return Command{}, errors.New("command type is too long")
	}
	if len(command.AuthToken) > maxAuthTokenLen {
		return Command{}, errors.New("command auth token is too long")
	}
	return command, nil
}

func OK(id string, payload any) Response {
	return Response{ProtocolVersion: Version, Kind: "response", ID: id, OK: true, Payload: payload}
}

func Error(id string, err error) Response {
	message := "unknown service error"
	if err != nil {
		message = err.Error()
	}
	return Response{ProtocolVersion: Version, Kind: "response", ID: id, OK: false, Error: message}
}

func Accepted() map[string]bool {
	return map[string]bool{"accepted": true}
}

func WriteJSONLine(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	if len(encoded) > MaxWireLineBytes {
		return fmt.Errorf("service wire message exceeds %d bytes", MaxWireLineBytes)
	}
	encoded = append(encoded, '\n')
	for len(encoded) > 0 {
		written, writeErr := writer.Write(encoded)
		if writeErr != nil {
			return writeErr
		}
		if written <= 0 || written > len(encoded) {
			return io.ErrShortWrite
		}
		encoded = encoded[written:]
	}
	return nil
}

func ServeLines(ctx context.Context, reader io.Reader, writer io.Writer, handler Handler) error {
	return serveLines(ctx, reader, writer, handler, MaxWireLineBytes)
}

func ServeEndpointConnection(ctx context.Context, connection endpointConnection, handler Handler) error {
	return serveEndpointConnection(ctx, connection, handler, EndpointFrameIdleTimeout)
}

func serveEndpointConnection(ctx context.Context, connection endpointConnection, handler Handler, timeout time.Duration) error {
	events := make(chan endpointDeadlineEvent, 4)
	watcherDone := make(chan struct{})
	tracked := &endpointDeadlineReadWriter{
		reader:      connection,
		writer:      connection,
		events:      events,
		watcherDone: watcherDone,
	}
	serveDone := make(chan struct{})
	go watchEndpointDeadline(ctx, connection, events, serveDone, watcherDone, timeout)
	err := serveLines(ctx, tracked, tracked, handler, MaxEndpointWireLineBytes)
	close(serveDone)
	<-watcherDone
	return err
}

func serveLines(ctx context.Context, reader io.Reader, writer io.Writer, handler Handler, maxWireLineBytes int) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), maxWireLineBytes)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		command, err := DecodeCommand(line)
		var result CommandResult
		if err != nil {
			result = CommandResult{Response: Error("", fmt.Errorf("invalid command: %w", err))}
		} else {
			result = handler(ctx, command)
		}

		if err := WriteJSONLine(writer, result.Response); err != nil {
			return err
		}
		for _, event := range result.Events {
			if err := WriteJSONLine(writer, EventEnvelope{ProtocolVersion: Version, Kind: "event", Event: event}); err != nil {
				return err
			}
		}

		if result.Shutdown && result.Response.OK {
			return ErrShutdown
		}
	}

	return scanner.Err()
}

type endpointDeadlineEvent uint8

const (
	endpointReadComplete endpointDeadlineEvent = iota
	endpointReadPartial
	endpointWriteStarted
	endpointWriteCompleted
)

type endpointDeadlineReadWriter struct {
	reader      io.Reader
	writer      io.Writer
	events      chan<- endpointDeadlineEvent
	watcherDone <-chan struct{}
}

func (connection *endpointDeadlineReadWriter) Read(buffer []byte) (int, error) {
	read, err := connection.reader.Read(buffer)
	if read > 0 {
		event := endpointReadPartial
		if bytes.LastIndexByte(buffer[:read], '\n') == read-1 {
			event = endpointReadComplete
		}
		connection.notify(event)
	}
	return read, err
}

func (connection *endpointDeadlineReadWriter) Write(buffer []byte) (int, error) {
	connection.notify(endpointWriteStarted)
	written, err := connection.writer.Write(buffer)
	connection.notify(endpointWriteCompleted)
	return written, err
}

func (connection *endpointDeadlineReadWriter) notify(event endpointDeadlineEvent) {
	select {
	case connection.events <- event:
	case <-connection.watcherDone:
	}
}

func watchEndpointDeadline(
	ctx context.Context,
	connection io.Closer,
	events <-chan endpointDeadlineEvent,
	serveDone <-chan struct{},
	watcherDone chan<- struct{},
	timeout time.Duration,
) {
	defer close(watcherDone)
	if timeout <= 0 {
		select {
		case <-ctx.Done():
			_ = connection.Close()
		case <-serveDone:
		}
		return
	}

	timer := time.NewTimer(time.Hour)
	if !timer.Stop() {
		<-timer.C
	}
	var timerChannel <-chan time.Time
	readPartial := false
	writeInProgress := false
	resetTimer := func() {
		if !timer.Stop() && timerChannel != nil {
			select {
			case <-timer.C:
			default:
			}
		}
		timer.Reset(timeout)
		timerChannel = timer.C
	}
	stopTimer := func() {
		if !timer.Stop() && timerChannel != nil {
			select {
			case <-timer.C:
			default:
			}
		}
		timerChannel = nil
	}
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			_ = connection.Close()
			return
		case <-serveDone:
			return
		case event := <-events:
			switch event {
			case endpointReadComplete:
				readPartial = false
			case endpointReadPartial:
				readPartial = true
			case endpointWriteStarted:
				writeInProgress = true
			case endpointWriteCompleted:
				writeInProgress = false
			}
			if readPartial || writeInProgress {
				resetTimer()
			} else {
				stopTimer()
			}
		case <-timerChannel:
			_ = connection.Close()
			return
		}
	}
}
