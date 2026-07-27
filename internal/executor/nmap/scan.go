package nmap

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	nmapWrapper "github.com/Ullaakut/nmap/v3"
	nettarget "github.com/kosmosec/mykmyk/internal/target"
)

var ErrEmptyNmapScanResult = errors.New("nmap does not found anything")

// targetLabel turns a target into something usable as a directory name. A CIDR target such as
// 10.113.9.0/24 - which a host-discovery sweep needs - would otherwise be treated as a nested
// path and make nmap's -oA fail. Targets without a slash (every IP and domain) are returned
// unchanged, so existing output paths and cache keys are untouched.
func targetLabel(target string) string {
	return strings.ReplaceAll(target, "/", "_")
}

func scan(target string, ports []string, scanOptions []string, scanName string, iface string) (*nmapWrapper.Run, *[]string, error) {

	label := targetLabel(target)
	if _, err := os.Stat(label); os.IsNotExist(err) {
		os.Mkdir(label, 0775)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 1440*time.Minute)
	defer cancel()
	nmapArgs := buildScanOptions(scanOptions, label, scanName)
	if nettarget.IsIPv6(target) {
		// An IPv6 target needs -6; the config's own flags (port list, timing, output) are left as
		// written. Prepended, so the -oA filename buildOutput appended stays the last positional.
		nmapArgs = append([]string{"-6"}, nmapArgs...)
	}
	// Attach the zone for a link-local target (fe80::5 -> fe80::5%eth0), which is what nmap needs to
	// reach it alongside -e; a no-op for global v6 and IPv4. The output directory stays the bare
	// address (label, above), so cache keys and report links do not move.
	scanTarget := nettarget.Zoned(target, iface)
	result, warnings, err := doScan(ctx, scanTarget, label, ports, nmapArgs, scanName, iface)
	if err != nil {
		return nil, nil, err
	}
	return result, warnings, nil
}

func doScan(ctx context.Context, target string, label string, ports []string, scanArgs []string, scanName string, iface string) (*nmapWrapper.Run, *[]string, error) {

	scanner, err := createScanner(ctx, target, ports, scanArgs, iface)
	if err != nil {
		return nil, nil, err
	}
	result, warnings, err := scanner.Run()
	if err != nil {
		return nil, nil, err
	}
	result.ToFile(fmt.Sprintf("./%s/%s.xml", label, scanName))
	return result, warnings, nil

}

func createScanner(ctx context.Context, target string, ports []string, scanArgs []string, iface string) (*nmapWrapper.Scanner, error) {
	options := []nmapWrapper.Option{
		nmapWrapper.WithTargets(target),
		nmapWrapper.WithCustomArguments(scanArgs...),
	}
	if len(ports) != 0 {
		options = append(options, nmapWrapper.WithPorts(ports...))
	}
	// Sent as an option rather than appended to scanArgs on purpose: buildOutput appends the -oA
	// value as a bare positional element, so anything added to that slice afterwards would be
	// consumed by -oA as its filename.
	if iface != "" {
		options = append(options, nmapWrapper.WithInterface(iface))
	}
	return nmapWrapper.NewScanner(ctx, options...)
}

func buildScanOptions(scanOptions []string, label string, scanName string) []string {
	scanOptions = buildOutput(scanOptions, label, scanName)

	return scanOptions
}

func buildOutput(scanOptions []string, label string, name string) []string {
	// Copy rather than append in place: scanOptions is the task's shared args slice and every
	// concurrent scan appends its own -oA path to it. Appending directly would let two workers
	// write the same backing array slot whenever it has spare capacity, handing one scan the
	// other's output path.
	out := make([]string, len(scanOptions), len(scanOptions)+1)
	copy(out, scanOptions)
	return append(out, fmt.Sprintf("%s/%s", label, name))
}
