package protocol

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
)

const MaxWireLineBytes = 2 * 1024 * 1024

var ErrShutdown = errors.New("shutdown requested")

type Command struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	AuthToken string          `json:"authToken,omitempty"`
	Payload   json.RawMessage `json:"payload,omitempty"`
}

type Response struct {
	Kind    string `json:"kind"`
	ID      string `json:"id"`
	OK      bool   `json:"ok"`
	Payload any    `json:"payload,omitempty"`
	Error   string `json:"error,omitempty"`
}

type EventEnvelope struct {
	Kind  string `json:"kind"`
	Event any    `json:"event"`
}

type CommandResult struct {
	Response Response
	Events   []any
}

type Handler func(context.Context, Command) CommandResult

func DecodeCommand(line string) (Command, error) {
	var command Command
	if err := json.Unmarshal([]byte(strings.TrimSpace(line)), &command); err != nil {
		return Command{}, err
	}
	if command.ID == "" {
		return Command{}, errors.New("command id is required")
	}
	if command.Type == "" {
		return Command{}, errors.New("command type is required")
	}
	return command, nil
}

func OK(id string, payload any) Response {
	return Response{Kind: "response", ID: id, OK: true, Payload: payload}
}

func Error(id string, err error) Response {
	message := "unknown service error"
	if err != nil {
		message = err.Error()
	}
	return Response{Kind: "response", ID: id, OK: false, Error: message}
}

func Accepted() map[string]bool {
	return map[string]bool{"accepted": true}
}

func WriteJSONLine(writer io.Writer, value any) error {
	encoded, err := json.Marshal(value)
	if err != nil {
		return err
	}
	encoded = append(encoded, '\n')
	_, err = writer.Write(encoded)
	return err
}

func ServeLines(ctx context.Context, reader io.Reader, writer io.Writer, handler Handler) error {
	scanner := bufio.NewScanner(reader)
	scanner.Buffer(make([]byte, 0, 64*1024), MaxWireLineBytes)

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
			if err := WriteJSONLine(writer, EventEnvelope{Kind: "event", Event: event}); err != nil {
				return err
			}
		}

		if command.Type == "shutdown" {
			return ErrShutdown
		}
	}

	return scanner.Err()
}
