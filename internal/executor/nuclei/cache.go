package nuclei

import (
	"fmt"
	"io/ioutil"
)

type cache struct{}

// cachePath is where a task's result for a target lives. It doubles as the cache key: the file
// existing is the whole test, so the path is worth naming in the log when a scan is skipped.
func cachePath(target string, key string) string {
	return fmt.Sprintf("./%s/%s", target, key)
}

func (c *cache) get(target string, key string) (string, bool) {
	path := cachePath(target, key)
	output, err := ioutil.ReadFile(path)
	if err != nil {
		return "", false
	}
	return string(output), true

}
