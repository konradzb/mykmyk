package ffuf

import (
	"database/sql"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/kosmosec/mykmyk/internal/binary"
	"github.com/kosmosec/mykmyk/internal/status"
)

func scan(host string, urls []string, args []string, prefix string, db *sql.DB, taskName string) (string, []string, error) {
	if _, err := os.Stat(host); os.IsNotExist(err) {
		os.Mkdir(host, 0775)
	}

	var fuzzedURLs string
	pathsToReport := make([]string, 0)
	for _, u := range urls {
		urlToFUZZ := prepareURL(u, prefix)
		actualArgs := make([]string, 0)
		actualArgs = append(actualArgs, args...)
		actualArgs = append(actualArgs, "-u", urlToFUZZ)
		actualArgs = append(actualArgs, "-of", "html")
		ffufReportName := reportPath(host, taskName, u)
		actualArgs = append(actualArgs, "-o", ffufReportName)
		output, _, err := binary.Run("ffuf", actualArgs, nil)
		if err != nil {
			return "", nil, err
		}
		err = status.UpdateDoneTaskInStatus(db, taskName, host, u)
		if err != nil {
			return "", nil, err
		}
		pathsToReport = append(pathsToReport, ffufReportName)
		fuzzedURLs += output.String()
	}

	return fuzzedURLs, pathsToReport, nil
}

// reportPath names the per-URL HTML report. url.Parse rejects a link-local URL carrying a raw zone
// (http://[fe80::1%eth0]:80) and returns nil, which used to be dereferenced here for the hostname
// and port - a panic in an executor goroutine ends the run and loses every other task's results.
// The fall-back keeps the scan running and still gives it a report to write.
func reportPath(host string, taskName string, rawURL string) string {
	if u, err := url.Parse(rawURL); err == nil {
		return fmt.Sprintf("./%s/ffufReport-%s-%s-%s.html", host, taskName, u.Hostname(), u.Port())
	}
	return fmt.Sprintf("./%s/ffufReport-%s-%s.html", host, taskName, fileSafe(rawURL))
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

func prepareURL(url string, prefix string) string {
	var urlWithFUZZ string
	if prefix != "" {
		urlWithFUZZ = fmt.Sprintf("%s%s/%s", url, prefix, "FUZZ")
		return urlWithFUZZ
	}
	urlWithFUZZ = fmt.Sprintf("%s/%s", url, "FUZZ")
	return urlWithFUZZ
}
