package httpx

import (
	"bytes"
	"os"

	"github.com/kosmosec/mykmyk/internal/binary"
	nettarget "github.com/kosmosec/mykmyk/internal/target"
)

func scan(host string, ports []string, iface string, args []string) (string, error) {
	if _, err := os.Stat(host); os.IsNotExist(err) {
		os.Mkdir(host, 0775)
	}
	input := createInput(host, iface, ports)

	output, _, err := binary.Run("httpx", args, &input)
	if err != nil {
		return "", err
	}
	return output.String(), nil
}

func createInput(host string, iface string, ports []string) bytes.Buffer {
	input := bytes.Buffer{}
	for _, p := range ports {
		// DialAddr brackets an IPv6 host and attaches the zone for a link-local one, so httpx gets
		// a target it can actually reach; for IPv4 it is the old host:port unchanged.
		input.WriteString(nettarget.DialAddr(host, iface, p) + "\n")
	}
	return input
}
