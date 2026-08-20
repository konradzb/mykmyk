package sslscan

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/kosmosec/mykmyk/internal/binary"
	"github.com/kosmosec/mykmyk/internal/status"
	nettarget "github.com/kosmosec/mykmyk/internal/target"
)

func scan(host string, targets []string, ports []string, portToScan int, iface string, args []string, db *sql.DB, taskName string) (string, []string, error) {
	if _, err := os.Stat(host); os.IsNotExist(err) {
		os.Mkdir(host, 0775)
	}

	var serviceToCheck string
	pathsToReport := make([]string, 0)
	if len(ports) == 0 {
		for _, u := range targets {
			// sslscan is a TLS scanner and httpx already told cleartext from TLS apart. A cleartext
			// http:// URL has no TLS to scan and sslscan rejects the scheme outright ("Invalid
			// target specified"), so skip it: record the unit skipped (not failed), never pending.
			sslscanTarget, ok := sslTarget(u, iface)
			if !ok {
				if err := status.MarkSkipped(db, taskName, host, u, "not a TLS endpoint"); err != nil {
					return "", nil, err
				}
				continue
			}
			actualArgs := make([]string, 0)
			actualArgs = append(actualArgs, args...)
			sslReportName := reportPath(host, taskName, u)
			sslReportArg := fmt.Sprintf("--xml=%s", sslReportName)
			actualArgs = append(actualArgs, sslReportArg)
			actualArgs = append(actualArgs, sslscanTarget)
			output, _, err := binary.Run("sslscan", actualArgs, nil)
			if err != nil {
				// One URL failing must not abort the host's other URLs: a broken http:// probe used
				// to return here and skip a live https:// one behind it. Record this unit failed and
				// carry on; a bare return is reserved for the DB errors below.
				if markErr := status.MarkFailed(db, taskName, host, u, err.Error()); markErr != nil {
					return "", nil, markErr
				}
				continue
			}
			if err := status.UpdateDoneTaskInStatus(db, taskName, host, u); err != nil {
				return "", nil, err
			}
			pathsToReport = append(pathsToReport, sslReportName)
			serviceToCheck += output.String()
		}
	} else {
		for _, p := range ports {
			port, err := strconv.Atoi(p)
			if err != nil {
				return "", nil, err
			}
			if port == portToScan {
				actualArgs := make([]string, 0)
				actualArgs = append(actualArgs, args...)
				finalTarget := nettarget.DialAddr(targets[0], iface, p)
				sslReportName := fmt.Sprintf("./%s/%s-%s-%s.xml", host, taskName, targets[0], p)
				sslReportArg := fmt.Sprintf("--xml=%s", sslReportName)
				actualArgs = append(actualArgs, sslReportArg)
				actualArgs = append(actualArgs, finalTarget)
				output, _, err := binary.Run("sslscan", actualArgs, nil)
				if err != nil {
					return "", nil, err
				}
				err = status.UpdateDoneTaskInStatus(db, taskName, host, targets[0])
				if err != nil {
					return "", nil, err
				}
				pathsToReport = append(pathsToReport, sslReportName)
				serviceToCheck += output.String()
			}
		}
		// A port-filtered task records a unit for every target before it knows which ports are
		// open. Anything the filter rejected was never going to run, so retire it here - otherwise
		// every host without that port keeps a pending unit for the rest of the run and reads as
		// still being scanned.
		err := status.MarkTargetSkipped(db, taskName, host, fmt.Sprintf("port %d not open", portToScan))
		if err != nil {
			return "", nil, err
		}
	}

	return serviceToCheck, pathsToReport, nil
}

// reportPath names the per-URL XML report. url.Parse rejects a link-local URL carrying a raw zone
// (http://[fe80::1%eth0]:80) and returns nil, which used to be dereferenced here for the hostname
// and port - a panic in an executor goroutine ends the run and loses every other task's results.
// The fall-back keeps the scan running and still gives it a report to write.
func reportPath(host string, taskName string, rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return fmt.Sprintf("./%s/%s-%s-%s.xml", host, taskName, u.Hostname(), u.Port())
	}
	return fmt.Sprintf("./%s/%s-%s.xml", host, taskName, fileSafe(rawURL))
}

// fileSafe turns a URL into one usable filename component.
func fileSafe(rawURL string) string {
	return strings.Map(func(r rune) rune {
		if strings.ContainsRune("/:%[]?&=", r) {
			return '-'
		}
		return r
	}, rawURL)
}

// sslTarget turns an httpx URL into a target sslscan accepts, or reports that it should be skipped.
// sslscan is a TLS scanner: handed a scheme-qualified URL it answers "Invalid target specified", and
// a cleartext http:// endpoint has no TLS to scan, so only https:// URLs yield a target. The scheme
// is stripped to a bare host:port, zone-attached and bracketed for a link-local IPv6 host by
// DialAddr (fe80::1%eth0 -> [fe80::1%eth0]:8443). It is parsed by hand rather than with url.Parse,
// which rejects the raw '%' zone httpx passes through (https://[fe80::1%eth0]:8443).
func sslTarget(rawURL, iface string) (string, bool) {
	const httpsPrefix = "https://"
	if !strings.HasPrefix(rawURL, httpsPrefix) {
		return "", false
	}
	authority := strings.TrimPrefix(rawURL, httpsPrefix)
	// Drop any path/query/fragment after the authority.
	if i := strings.IndexAny(authority, "/?#"); i >= 0 {
		authority = authority[:i]
	}
	host, port := splitAuthority(authority)
	if host == "" {
		return "", false
	}
	if port == "" {
		port = "443"
	}
	return nettarget.DialAddr(host, iface, port), true
}

// splitAuthority separates a URL authority into host and port, tolerating a bracketed IPv6 literal
// carrying a raw zone ([fe80::1%eth0]:8443 -> "fe80::1%eth0", "8443") that net.SplitHostPort rejects.
func splitAuthority(authority string) (host, port string) {
	if strings.HasPrefix(authority, "[") {
		end := strings.IndexByte(authority, ']')
		if end < 0 {
			return "", ""
		}
		host = authority[1:end]
		if rest := authority[end+1:]; strings.HasPrefix(rest, ":") {
			port = rest[1:]
		}
		return host, port
	}
	if i := strings.LastIndexByte(authority, ':'); i >= 0 {
		return authority[:i], authority[i+1:]
	}
	return authority, ""
}
