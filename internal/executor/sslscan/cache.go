package sslscan

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

type cache struct{}

// cachePath is where a task's result for a target lives. It doubles as the cache key: the file
// existing is the whole test, so the path is worth naming in the log when a scan is skipped.
func cachePath(target string, key string) string {
	return fmt.Sprintf("./%s/%s", target, key)
}

func (c *cache) get(target string, key string) (string, []string, bool) {
	path := cachePath(target, key)
	output, err := os.ReadFile(path)
	if err != nil {
		return "", nil, false
	}
	if len(output) == 0 {
		return "", nil, false
	}
	reportPaths := findFileStartsWith("./"+target, key)
	return string(output), reportPaths, true
}

func findFileStartsWith(root string, pattern string) []string {
	a := make([]string, 0)
	filepath.WalkDir(root, func(s string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if strings.HasPrefix(d.Name(), pattern) {
			a = append(a, s)
		}
		return nil
	})
	return a
}
