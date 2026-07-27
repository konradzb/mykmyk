package model

import (
	"github.com/kosmosec/mykmyk/internal/api"
)

type Output struct {
	Type    api.TaskType
	Name    string
	Target  string
	Results Results
}

type Results struct {
	Data        []string
	ReportPaths []string
}

type Message struct {
	Targets []string
	Ports   []string
	// Interface is the egress interface which reaches this target's segment, e.g. a VLAN
	// sub-interface like eth0.100 when scanning through a trunk port. Empty means "let the
	// kernel route it", which is how every scan behaved before trunk support was added.
	Interface string
}
