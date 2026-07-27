package finder

import (
	"context"
	"fmt"
	"os"
	"strconv"

	nmapWrapper "github.com/Ullaakut/nmap/v3"

	"github.com/kosmosec/mykmyk/internal/scope"
)

func Find(ctx context.Context, targetFile string, portFilter string) error {
	entries, err := scope.Load(targetFile)
	if err != nil {
		return err
	}
	for _, e := range entries {
		t := e.Spec
		nmapScan, err := loadScan(t, "ST-scan")
		if err != nil {
			return err
		}
		for _, host := range nmapScan.Hosts {
			for _, p := range host.Ports {
				scannedPort := strconv.Itoa(int(p.ID))
				if scannedPort == portFilter {
					fmt.Println(t)
				}
			}
		}
	}
	return nil
}

func loadScan(target string, key string) (*nmapWrapper.Run, error) {
	path := fmt.Sprintf("./%s/%s.xml", target, key)
	cachedResult, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var scanResult nmapWrapper.Run
	err = nmapWrapper.Parse(cachedResult, &scanResult)
	if err != nil {
		return nil, err
	}
	return &scanResult, err
}
