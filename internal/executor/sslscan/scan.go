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
			actualArgs := make([]string, 0)
			actualArgs = append(actualArgs, args...)
			sslReportName := reportPath(host, taskName, u)
			sslReportArg := fmt.Sprintf("--xml=%s", sslReportName)
			actualArgs = append(actualArgs, sslReportArg)
			actualArgs = append(actualArgs, u)
			output, _, err := binary.Run("sslscan", actualArgs, nil)
			if err != nil {
				return "", nil, err
			}
			err = status.UpdateDoneTaskInStatus(db, taskName, host, u)
			if err != nil {
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
