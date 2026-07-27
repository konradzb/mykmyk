package binary

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"os/exec"
	"strings"
)

// stderrTailBytes caps how much of a failing tool's stderr reaches the log. Enough to see the
// reason, not enough to bury the rest of the run.
const stderrTailBytes = 512

// Run runs binaryName with args and stdin optionally.
//
// A non-zero exit is an error. It used to be discarded along with stderr, which made a tool that
// refused to start indistinguishable from one that found nothing - the caller got an empty buffer
// and a nil error either way, and the task went on to report a clean result.
func Run(binaryName string, args []string, stdin io.Reader) (*bytes.Buffer, *bytes.Buffer, error) {

	var stdout bytes.Buffer
	var stderr bytes.Buffer

	binaryPath, err := exec.LookPath(binaryName)
	if err != nil {
		log.Printf("binary: %s not found in PATH: %s", binaryName, err)
		return nil, nil, err
	}

	cmd := exec.Command(binaryPath, args...)
	if stdin != nil {
		cmd.Stdin = stdin
	}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	log.Printf("binary: exec %s %s", binaryPath, strings.Join(args, " "))

	err = cmd.Start()
	if err != nil {
		log.Printf("binary: %s failed to start: %s", binaryName, err)
		return nil, nil, err
	}

	if err := cmd.Wait(); err != nil {
		log.Printf("binary: %s exited %d: %s: %s",
			binaryName, cmd.ProcessState.ExitCode(), err, tail(stderr.String()))
		return &stdout, &stderr, fmt.Errorf("%s exited %d: %s", binaryName, cmd.ProcessState.ExitCode(), tail(stderr.String()))
	}

	return &stdout, &stderr, nil
}

func tail(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no stderr output"
	}
	if len(s) > stderrTailBytes {
		return "..." + s[len(s)-stderrTailBytes:]
	}
	return s
}
