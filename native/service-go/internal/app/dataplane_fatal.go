package app

import (
	"fmt"
	"io"
	"os"
	"strings"

	"shadowssh/service/internal/dataplane"
	"shadowssh/service/internal/routing"
)

// dataplaneFatalExitCode is the helper's exit status when its dataplane
// stopped on its own. Electron reads an exit while TUN is active as "TUN
// stopped unexpectedly" and fails safe; a reply to some later command could
// not say that, because nothing would ask.
const dataplaneFatalExitCode = 3

// dataplaneFatalPrefix starts the one stderr line written before that exit.
const dataplaneFatalPrefix = "dataplane fatal: "

// exitProcess and fatalOutput are how a failed dataplane ends the helper.
// Variables only so tests can watch it happen without the test binary
// exiting.
var (
	exitProcess           = os.Exit
	fatalOutput io.Writer = os.Stderr
)

// dataplaneFailed is the runner's OnFatal: its dataplane stopped on its own,
// and it has already taken itself down. If it is still the dataplane this
// service runs, the helper says why on one line and exits, which is the
// signal Electron acts on. A runner already stopped or replaced - a
// stop-dataplane or a restart got to it first - has been answered for by
// that command, and nothing more happens.
func (a *App) dataplaneFailed(runner *dataplane.Runner, cause error) {
	a.dataplaneMu.Lock()
	current := runner != nil && a.dataplane == runner
	if current {
		a.dataplane = nil
		a.dataplanePolicy = nil
		a.dataplaneSignature = ""
	}
	a.dataplaneMu.Unlock()
	if !current {
		return
	}
	fmt.Fprintln(fatalOutput, dataplaneFatalPrefix+singleLine(cause.Error()))
	exitProcess(dataplaneFatalExitCode)
}

// reportSkippedRules warns about enabled rules the dataplane leaves out
// because they cannot be compiled. Each costs only itself; the revision is
// refused only when nothing valid is left to select by (validateRouting).
func (a *App) reportSkippedRules(rules []routing.Rule) {
	skipped := routing.NewMatcher(routing.ModeSelectedRules, rules).InvalidRules()
	if len(skipped) == 0 {
		return
	}
	const listed = 5
	described := make([]string, 0, min(len(skipped), listed))
	for _, rule := range skipped[:min(len(skipped), listed)] {
		described = append(described, fmt.Sprintf("%s %q", rule.Type, rule.Value))
	}
	more := ""
	if len(skipped) > listed {
		more = fmt.Sprintf(" and %d more", len(skipped)-listed)
	}
	a.logDiagnostic("warning", fmt.Sprintf(
		"TUN routing ignores %d invalid rule(s): %s%s.", len(skipped), strings.Join(described, ", "), more))
}

// singleLine keeps a message on one stderr line, which is how Electron reads
// the helper's diagnostics.
func singleLine(value string) string {
	return strings.Join(strings.Fields(value), " ")
}
