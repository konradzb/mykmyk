package nmap

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"sync"

	nmapWrapper "github.com/Ullaakut/nmap/v3"
	"github.com/kosmosec/mykmyk/internal/api"
	"github.com/kosmosec/mykmyk/internal/credsmanager"
	"github.com/kosmosec/mykmyk/internal/executor/abstract"
	"github.com/kosmosec/mykmyk/internal/model"
	"github.com/kosmosec/mykmyk/internal/sns"
	"github.com/kosmosec/mykmyk/internal/status"
	"gopkg.in/yaml.v2"
)

type Nmap struct {
	Type          api.TaskType
	Name          string
	Source        string
	Concurrency   int
	waitForSignal chan bool
	signalDone    chan bool
	waitFor       string
	output        []model.Output
	mu            sync.Mutex
	cache         cache
	isActive      bool
	isCacheActive bool
	sns           *sns.SNS
	consumer      chan model.Message
	args          []string
}

type scanResult struct {
	target string
	iface  string
	result *nmapWrapper.Run
	err    error
}

func (n *Nmap) scanTarget(target string, msg model.Message, db *sql.DB) (*nmapWrapper.Run, error) {
	fmt.Printf("[+] Nmap scanning for %s started\n", target)
	cached, found := n.cache.get(target, n.Name)
	if n.isCacheActive && found {
		return cached, nil
	}
	err := status.AddTaskToStatus(db, n.Name, target, target)
	if err != nil {
		return nil, err
	}
	result, warnings, err := scan(target, msg.Ports, n.args, n.Name, msg.Interface)
	if err != nil {
		return nil, err
	}
	err = status.UpdateDoneTaskInStatus(db, n.Name, target, target)
	if err != nil {
		return nil, err
	}
	log.Printf("nmap: %s for %s", warnings, target)
	return result, nil
}

func (n *Nmap) Run(ctx context.Context, in interface{}, db *sql.DB) error {
	n.waitForTask()
	task, err := n.unmarshal(in)
	if err != nil {
		return err
	}
	n.args = task.Args
	resultCh := make(chan scanResult, n.Concurrency)
	var wg sync.WaitGroup
	limiter := make(chan bool, n.Concurrency)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-n.consumer:
				if !ok {
					wg.Wait()
					close(resultCh)
					return
				}
				limiter <- true
				wg.Add(1)
				// nmap gets one IP with multiple ports
				target := msg.Targets[0]
				go func(ctx context.Context, target string, msg model.Message) {
					defer func() {
						wg.Done()
						<-limiter
					}()
					for {
						select {
						case <-ctx.Done():
							return
						default:
							result, err := n.scanTarget(target, msg, db)
							resultCh <- scanResult{target: target, iface: msg.Interface, result: result, err: err}
							return
						}
					}

				}(ctx, target, msg)
			}
		}
	}()

	for r := range resultCh {
		if r.err != nil {
			// One target failing must not end the task: draining the rest of resultCh is what
			// keeps the remaining hosts flowing downstream. This matters most behind a discovery
			// sweep, where the host has been *proven* to exist - dropping it silently would turn
			// a broken scan into an apparent clean bill of health.
			log.Printf("nmap: %s scan of %s failed: %s", n.Name, r.target, r.err)
			n.collectFailure(r.target, r.err)
			continue
		}
		if r.result == nil {
			continue
		}
		liveOutput(n.Name, r.target, r.result)
		if err := n.sendMessageToSNS(r.result, r.target, r.iface); err != nil {
			// Nothing usable found for this target - normal for a sweep over a sparse segment.
			log.Printf("nmap: %s found no live host for %s: %s", n.Name, r.target, err)
		}
		n.collectOutput(r.target, r.result)
	}
	n.sns.CloseTopic(n.Name)
	n.signalDoneTask()
	return nil
}

// collectFailure records a target whose scan errored, so the report names it explicitly. An
// absent host must never read as a host with nothing open.
func (n *Nmap) collectFailure(target string, scanErr error) {
	result := model.Output{
		Type:   n.Type,
		Name:   n.Name + " (FAILED - not scanned reliably)",
		Target: target,
		Results: model.Results{Data: []string{
			fmt.Sprintf("\tscan failed: %s\n", scanErr),
			"\tthis target's absence below is a gap in the scan, not an absence of open ports\n",
		}},
	}
	n.mu.Lock()
	n.output = append(n.output, result)
	n.mu.Unlock()
}

func liveOutput(taskName string, target string, result *nmapWrapper.Run) {
	output := convertNmapResultToString(result, target)
	fmt.Printf("Nmap scan %s, output for %s\n%s\n", taskName, target, output)
}

func (n *Nmap) collectOutput(target string, nmapResult *nmapWrapper.Run) {
	output := convertNmapResultToString(nmapResult, target)

	result := model.Output{
		Type:    n.Type,
		Name:    n.Name,
		Target:  target,
		Results: model.Results{Data: output},
	}
	n.mu.Lock()
	n.output = append(n.output, result)
	n.mu.Unlock()
}

func (n *Nmap) GetConcurrency() int {
	return n.Concurrency
}

func (n *Nmap) sendMessageToSNS(scanResult *nmapWrapper.Run, host string, iface string) error {
	messages, err := convertToNmapMessage(scanResult, host, iface)
	if err != nil {
		return err
	}
	for _, msg := range messages {
		n.sns.SendMessage(n.Name, msg)
	}

	return nil
}

// convertToNmapMessage turns one scan result into one message per live host it found.
//
// A scan of a single IP yields a single message, as it always has. A host-discovery sweep of a
// whole segment (nmap -sn -PR 10.113.9.0/24) yields one message per host that answered, which is
// what lets an ARP sweep gate the expensive port scans behind it: only addresses proven to exist
// are ever handed downstream.
func convertToNmapMessage(result *nmapWrapper.Run, target string, iface string) ([]model.Message, error) {
	if result.Hosts == nil {
		return nil, ErrEmptyNmapScanResult
	}
	messages := make([]model.Message, 0, len(result.Hosts))
	for _, host := range result.Hosts {
		if !isHostUsable(host) {
			continue
		}
		ports := make([]string, 0, len(host.Ports))
		for _, p := range host.Ports {
			ports = append(ports, strconv.Itoa(int(p.ID)))
		}
		messages = append(messages, model.Message{
			Targets:   []string{hostAddress(host, target)},
			Ports:     ports,
			Interface: iface,
		})
	}
	if len(messages) == 0 {
		return nil, ErrEmptyNmapScanResult
	}
	return messages, nil
}

// isHostUsable reports whether a host in a scan result is worth scanning further. Under -vvv nmap
// records the hosts it found *down* as well, so a sweep's result has to be filtered by status or
// every dead address in the range gets forwarded as a live target.
func isHostUsable(host nmapWrapper.Host) bool {
	if host.Status.State != "up" {
		return false
	}
	// Our own interface address answers a sweep with reason "localhost-response" (real hosts on
	// the segment answer "arp-response"). Port-scanning ourselves is never the intent and costs a
	// full host timeout.
	return host.Status.Reason != "localhost-response"
}

// hostAddress returns a host's own IPv4 address, falling back to the scanned target when the
// result carries no address. The fallback keeps a single-target scan working even if nmap omits
// the address element.
func hostAddress(host nmapWrapper.Host, target string) string {
	for _, addr := range host.Addresses {
		if addr.AddrType == "ipv4" {
			return addr.Addr
		}
	}
	return target
}

func convertNmapResultToString(result *nmapWrapper.Run, target string) []string {
	output := make([]string, 0)
	for _, host := range result.Hosts {
		if len(host.Ports) == 0 {
			// A host-discovery sweep (-sn) finds hosts but no ports. Report liveness instead, so
			// a discovery task shows what it found rather than rendering an empty block.
			if isHostUsable(host) {
				output = append(output, fmt.Sprintf("\t%-18s %s\n", hostAddress(host, target), "host up"))
			}
			continue
		}
		for _, p := range host.Ports {
			o := fmt.Sprintf("\t%-10s %-18s %-18s\n", strconv.Itoa(int(p.ID)), p.Service.Name, p.Service.Product)
			output = append(output, o)
		}
	}
	return output
}

func (n *Nmap) New(task api.Task, sns *sns.SNS, creds credsmanager.Credentials) abstract.Executor {
	return &Nmap{
		Type:          task.Type,
		Name:          task.Name,
		Source:        task.Source,
		Concurrency:   task.Concurrency,
		waitFor:       task.WaitFor,
		isActive:      task.Active,
		isCacheActive: task.UseCache,
		output:        make([]model.Output, 0),
		cache:         cache{},
		sns:           sns,
	}
}

func (n *Nmap) signalDoneTask() {
	if n.signalDone != nil {
		n.signalDone <- true
	}
}

func (n *Nmap) waitForTask() {
	if n.waitForSignal != nil {
		<-n.waitForSignal
	}
}

func (n *Nmap) SetDoneSignal(signalDone chan bool) {
	n.signalDone = signalDone
}

func (n *Nmap) SetWaitForSignal(waitForSignal chan bool) {
	n.waitForSignal = waitForSignal
}

func (n *Nmap) GetWaitForSignal() chan bool {
	return n.waitForSignal
}

func (n *Nmap) GetDoneSignal() chan bool {
	return n.signalDone
}

func (n *Nmap) GetWaitFor() string {
	return n.waitFor
}

func (n *Nmap) GetType() api.TaskType {
	return n.Type
}

func (n *Nmap) Output() []model.Output {
	return n.output
}

func (n *Nmap) GetSource() string {
	return n.Source
}

func (n *Nmap) HasSource() bool {
	if n.Source != "" {
		return true
	}
	return false
}

func (n *Nmap) GetName() string {
	return n.Name
}

func (n *Nmap) unmarshal(in interface{}) (*Task, error) {
	var task Task
	raw, err := yaml.Marshal(in)
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(raw, &task); err != nil {
		return nil, err
	}
	return &task, err
}

func (n *Nmap) SetConsumer(c chan model.Message) {
	n.consumer = c
}

func (n *Nmap) IsActive() bool {
	return n.isActive
}
