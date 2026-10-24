package app

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"shadowssh/service/internal/dataplane"
)

// captureFatalExit stands in for os.Exit and stderr while a test runs.
func captureFatalExit(t *testing.T) (*bytes.Buffer, *[]int) {
	t.Helper()
	var output bytes.Buffer
	var codes []int
	previousExit, previousOutput := exitProcess, fatalOutput
	exitProcess = func(code int) { codes = append(codes, code) }
	fatalOutput = &output
	t.Cleanup(func() { exitProcess, fatalOutput = previousExit, previousOutput })
	return &output, &codes
}

func TestAFailedDataplaneEndsTheHelperWithStatusThree(t *testing.T) {
	output, codes := captureFatalExit(t)
	service := New(Options{Driver: &fakeDriver{}})
	runner := &dataplane.Runner{}
	service.dataplane = runner
	service.dataplaneSignature = "127.0.0.1:10808|443"

	service.dataplaneFailed(runner, errors.New("the TUN adapter stopped delivering packets (receive packet: The data is invalid.)\r\nsecond line"))

	if len(*codes) != 1 || (*codes)[0] != 3 {
		t.Fatalf("expected one exit with status 3, got %v", *codes)
	}
	lines := strings.Split(strings.TrimSuffix(output.String(), "\n"), "\n")
	if len(lines) != 1 || !strings.HasPrefix(lines[0], "dataplane fatal: ") {
		t.Fatalf("expected one line starting with the fatal prefix, got %q", output.String())
	}
	if !strings.Contains(lines[0], "The data is invalid.") || !strings.Contains(lines[0], "second line") {
		t.Fatalf("the cause was lost: %q", lines[0])
	}
	service.dataplaneMu.Lock()
	defer service.dataplaneMu.Unlock()
	if service.dataplane != nil || service.dataplanePolicy != nil || service.dataplaneSignature != "" {
		t.Fatal("the failed dataplane was left as the running one")
	}
}

func TestAFailureOfARunnerNoLongerInUseDoesNotEndTheHelper(t *testing.T) {
	// A stop-dataplane or a restart got to the runner first and has answered
	// for it; the helper is still serving.
	output, codes := captureFatalExit(t)
	service := New(Options{Driver: &fakeDriver{}})
	stale := &dataplane.Runner{}
	current := &dataplane.Runner{}

	service.dataplane = current
	service.dataplaneFailed(stale, errors.New("replaced"))
	service.dataplaneMu.Lock()
	kept := service.dataplane == current
	service.dataplaneMu.Unlock()
	if !kept {
		t.Fatal("a replaced runner's failure cleared the current one")
	}

	service.dataplane = nil
	service.dataplaneFailed(stale, errors.New("stopped"))

	if len(*codes) != 0 || output.Len() != 0 {
		t.Fatalf("expected nothing, got exits %v and output %q", *codes, output.String())
	}
}
