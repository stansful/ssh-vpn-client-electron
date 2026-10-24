package app

import (
	"context"
	"errors"
	"fmt"
	"runtime"

	"shadowssh/service/internal/protocol"
	"shadowssh/service/internal/winnet"
	"shadowssh/service/internal/winroute"
)

// A helper that was killed leaves its routing changes and their journal
// behind. A dataplane start undoes them first, but that waits for the next TUN
// connect - and in the meantime the transport server's host route can stay on
// the network card through a network change. `recover-routes` lets the
// application run the same recovery as soon as it starts.

// RouteRecoveryPayload is the `recover-routes` command body.
type RouteRecoveryPayload struct {
	JournalPath string `json:"journalPath"`
}

// RouteRecoveryResult is the `recover-routes` success payload.
type RouteRecoveryResult struct {
	// Recovered is the number of journal entries whose undo ran.
	Recovered int `json:"recovered"`
}

var errRouteRecoveryNotElevated = errors.New("undoing routing changes requires the application to be started as administrator")

func (a *App) handleRecoverRoutes(ctx context.Context, command protocol.Command) protocol.CommandResult {
	var payload RouteRecoveryPayload
	if err := decodePayload(command.Payload, &payload); err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}
	journalPath, err := winroute.ResolveJournalPath(payload.JournalPath)
	if err != nil {
		return protocol.CommandResult{Response: protocol.Error(command.ID, err)}
	}

	a.dataplaneMu.Lock()
	defer a.dataplaneMu.Unlock()
	if a.dataplane != nil {
		// Its journal describes routes that are in use, not left over.
		return protocol.CommandResult{Response: protocol.Error(command.ID,
			errors.New("the TUN dataplane is running; its routing is in use, not left over"))}
	}
	recovered, err := a.recoverRoutes(ctx, journalPath, a.logDiagnostic)
	if err != nil {
		return protocol.CommandResult{
			Response: protocol.Error(command.ID, err),
			Events:   []any{diagnostic("warning", "Routing changes left by a previous run were not all undone: "+err.Error())},
		}
	}
	var events []any
	if recovered > 0 {
		events = append(events, diagnostic("info", fmt.Sprintf("Undid %d routing changes left by a previous run.", recovered)))
	}
	return a.ok(command.ID, RouteRecoveryResult{Recovered: recovered}, events...)
}

// recoverRoutes runs the journal recovery a dataplane start runs, without
// starting one.
func recoverRoutes(ctx context.Context, journalPath string, log func(level string, message string)) (int, error) {
	if runtime.GOOS != "windows" {
		return 0, winroute.ErrNotSupported
	}
	if !winnet.IsElevated() {
		return 0, errRouteRecoveryNotElevated
	}
	return winroute.RecoverJournal(ctx, journalPath, log)
}
