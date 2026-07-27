package nmap

import (
	"fmt"
	"os"

	nmapWrapper "github.com/Ullaakut/nmap/v3"
)

type cache struct{}

func (c *cache) get(target string, key string) (*nmapWrapper.Run, bool) {
	path := fmt.Sprintf("./%s/%s.xml", targetLabel(target), key)
	cachedResult, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	var scanResult nmapWrapper.Run
	err = nmapWrapper.Parse(cachedResult, &scanResult)
	if err != nil {
		return nil, false
	}
	// Only reuse a scan nmap actually finished. A run killed part-way through still leaves a
	// parseable XML behind, and treating that as a cache hit would freeze a partial result in
	// place forever - worst of all for a discovery sweep, where it silently shrinks the target
	// list for every task downstream.
	if scanResult.Stats.Finished.Exit != "success" {
		return nil, false
	}
	return &scanResult, true
}
