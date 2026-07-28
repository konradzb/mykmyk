package nmap

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"strconv"
	"sync"
	"time"

	nmapWrapper "github.com/Ullaakut/nmap/v3"
	"github.com/kosmosec/mykmyk/internal/api"
	"github.com/kosmosec/mykmyk/internal/credsmanager"
	"github.com/kosmosec/mykmyk/internal/executor/abstract"
	"github.com/kosmosec/mykmyk/internal/model"
	"github.com/kosmosec/mykmyk/internal/sns"
	"github.com/kosmosec/mykmyk/internal/status"
	nettarget "github.com/kosmosec/mykmyk/internal/target"
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

// scanTarget scans target and files the result under key. The two differ only for a link-local
// range, where the same fe80::/10 can appear once per VLAN: target is what nmap is pointed at, key
// is what the result is stored as. See target.ScopeKey.
func (n *Nmap) scanTarget(target string, key string, msg model.Message, db *sql.DB) (*nmapWrapper.Run, error) {
	fmt.Printf("[+] Nmap scanning for %s started\n", key)
	cached, found := n.cache.get(key, n.Name)
	if n.isCacheActive && found {
		// Recorded, not silently returned: without a row here a re-run over a warm cache leaves
		// status empty, and a task showing a plain count would not say whether anything ran.
		path := cachePath(key, n.Name)
		log.Printf("nmap: %s cached for %s (%s)", n.Name, key, path)
		return cached, status.MarkCached(db, n.Name, key, key, path)
	}
	err := status.AddTaskToStatus(db, n.Name, key, key)
	if err != nil {
		return nil, err
	}
	log.Printf("nmap: %s started for %s via %s", n.Name, key, describeInterface(msg.Interface))
	started := time.Now()
	result, err := n.runScan(target, key, msg)
	if err != nil {
		return nil, err
	}
	err = status.UpdateDoneTaskInStatus(db, n.Name, key, key)
	if err != nil {
		return nil, err
	}
	log.Printf("nmap: %s done for %s in %s", n.Name, key, time.Since(started).Round(time.Millisecond))
	return result, nil
}

// runScan picks the right nmap invocation for the target. A link-local range means IPv6 multicast
// discovery (there is no address space to sweep); anything else is an ordinary scan, which quietly
// gains -6 and a zoned target when the address is IPv6. The config never spells the family out - the
// address is enough to know it.
func (n *Nmap) runScan(target string, key string, msg model.Message) (*nmapWrapper.Run, error) {
	if nettarget.IsLinkLocalCIDR(target) {
		return discoverLinkLocal(msg.Interface, targetLabel(key), n.Name)
	}
	result, warnings, err := scan(target, msg.Ports, n.args, n.Name, msg.Interface)
	if err != nil {
		return nil, err
	}
	if warnings != nil && len(*warnings) > 0 {
		log.Printf("nmap: %s warnings for %s: %s", n.Name, target, *warnings)
	}
	return result, nil
}

func describeInterface(iface string) string {
	if iface == "" {
		return "kernel routing"
	}
	return iface
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
				// What the result is filed under. Identical to target for everything except a
				// link-local range, which two VLANs can both name - see target.ScopeKey.
				key := nettarget.ScopeKey(target, msg.Interface)
				go func(ctx context.Context, target string, key string, msg model.Message) {
					defer func() {
						wg.Done()
						<-limiter
					}()
					for {
						select {
						case <-ctx.Done():
							return
						default:
							result, err := n.scanTarget(target, key, msg, db)
							resultCh <- scanResult{target: key, iface: msg.Interface, result: result, err: err}
							return
						}
					}

				}(ctx, target, key, msg)
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
			if err := status.MarkFailed(db, n.Name, r.target, r.target, r.err.Error()); err != nil {
				log.Printf("nmap: unable to record failure of %s for %s: %s", n.Name, r.target, err)
			}
			n.collectFailure(r.target, r.err)
			continue
		}
		if r.result == nil {
			continue
		}
		liveOutput(n.Name, r.target, r.result)
		if err := n.sendMessageToSNS(db, r.result, r.target, r.iface); err != nil {
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

func (n *Nmap) sendMessageToSNS(db *sql.DB, scanResult *nmapWrapper.Run, parent string, iface string) error {
	if scanResult.Hosts == nil {
		return ErrEmptyNmapScanResult
	}
	entries := discoveredEntries(scanResult, parent)
	if len(entries) == 0 {
		return ErrEmptyNmapScanResult
	}

	// This is the only place that knows both halves of the discovery result: the scope entry that
	// was scanned and the addresses that answered inside it - along with the MAC each answered from.
	// Nothing downstream can reconstruct the link, because every task after this one is handed a bare
	// host and never learns which network, or which device, it came from. Recording it here is what
	// lets status expand a /24 into its live hosts and the report line up a device's v4 and v6 sides.
	discovered := make([]status.Discovered, 0, len(entries))
	for _, e := range entries {
		discovered = append(discovered, status.Discovered{Addr: e.addr, Mac: e.mac, Vendor: e.vendor})
	}
	log.Printf("nmap: %s found %d live %s under %s (from %d result entries)",
		n.Name, len(entries), plural(len(entries), "address", "addresses"), parent, len(scanResult.Hosts))
	if err := status.RecordHosts(db, parent, n.Name, discovered); err != nil {
		log.Printf("nmap: unable to record hosts found under %s: %s", parent, err)
	}

	// Persist open ports so the report can diff a device's IPv4 and IPv6 exposure. A discovery sweep
	// has none; a port scan records them against the address it scanned.
	for _, host := range scanResult.Hosts {
		if !isHostUsable(host) || len(host.Ports) == 0 {
			continue
		}
		for _, addr := range scanAddresses(host, parent) {
			if err := status.RecordPorts(db, addr, n.Name, toStatusPorts(host.Ports)); err != nil {
				log.Printf("nmap: unable to record ports for %s: %s", addr, err)
			}
		}
	}

	for _, e := range entries {
		n.sns.SendMessage(n.Name, model.Message{Targets: []string{e.addr}, Ports: e.ports, Interface: iface})
	}
	return nil
}

func plural(n int, one string, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// discoveredEntry is one scannable address from a result, with the MAC it answered from and the
// open ports found on its host. One usable host produces one entry per IPv4/IPv6 address it carries.
type discoveredEntry struct {
	addr   string
	mac    string
	vendor string
	ports  []string
}

// discoveredEntries turns one scan result into the addresses worth handing downstream, one entry per
// live address.
//
// A scan of a single IP yields a single entry, as it always has. A host-discovery sweep of a whole
// segment (nmap -sn -PR 10.113.9.0/24) yields one per host that answered, which is what lets an ARP
// sweep gate the expensive port scans behind it: only addresses proven to exist are ever handed
// downstream. An IPv6 host carrying both a link-local and a global address yields one each, so both
// get scanned.
func discoveredEntries(result *nmapWrapper.Run, target string) []discoveredEntry {
	entries := make([]discoveredEntry, 0, len(result.Hosts))
	for _, host := range result.Hosts {
		if !isHostUsable(host) {
			continue
		}
		mac, vendor := hostMacVendor(host)
		ports := portIDs(host.Ports)
		for _, addr := range scanAddresses(host, target) {
			entries = append(entries, discoveredEntry{addr: addr, mac: mac, vendor: vendor, ports: ports})
		}
	}
	return entries
}

// scanAddresses returns the IP addresses of a host worth scanning: its IPv4 address, and every IPv6
// address it carries (link-local plus any global/ULA the discovery surfaced). It falls back to the
// scanned target when the result has no address element, so a single-target scan never drops itself.
func scanAddresses(host nmapWrapper.Host, target string) []string {
	addrs := make([]string, 0, 1)
	for _, a := range host.Addresses {
		if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
			addrs = append(addrs, a.Addr)
		}
	}
	if len(addrs) == 0 {
		addrs = append(addrs, target)
	}
	return addrs
}

func hostMacVendor(host nmapWrapper.Host) (string, string) {
	for _, a := range host.Addresses {
		if a.AddrType == "mac" {
			return a.Addr, a.Vendor
		}
	}
	return "", ""
}

func hostMac(host nmapWrapper.Host) string {
	mac, _ := hostMacVendor(host)
	return mac
}

func portIDs(ports []nmapWrapper.Port) []string {
	out := make([]string, 0, len(ports))
	for _, p := range ports {
		out = append(out, strconv.Itoa(int(p.ID)))
	}
	return out
}

func toStatusPorts(ports []nmapWrapper.Port) []status.Port {
	out := make([]status.Port, 0, len(ports))
	for _, p := range ports {
		proto := p.Protocol
		if proto == "" {
			proto = "tcp"
		}
		out = append(out, status.Port{Number: int(p.ID), Proto: proto})
	}
	return out
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
