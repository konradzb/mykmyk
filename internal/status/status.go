// Package status records what a scan is doing and reads it back for the status command.
//
// Two tables carry that. Status holds one row per unit of work - a task against a target, where a
// unit is a host for most tasks but a host:port for nc and a URL for ffuf and sslscan. Hosts holds
// the mapping a scan discovers as it goes: which addresses answered under which scope entry. That
// mapping is what lets the status command expand a network from the hosts file into the hosts found
// inside it, because the Status table alone only ever names a task's own target and has no way to
// tie a discovered IP back to the CIDR it came from.
package status

import (
	"context"
	"database/sql"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"

	_ "github.com/mattn/go-sqlite3"

	"github.com/kosmosec/mykmyk/internal/api"
	"github.com/kosmosec/mykmyk/internal/scope"
	"github.com/kosmosec/mykmyk/internal/target"
)

// DBFile is the per-run progress database, written in the working directory alongside the scan
// output and the report.
const DBFile = "status.db"

// DSN opens the progress database in WAL mode. WAL is what allows `mykmyk status` to read while a
// scan is still writing - under the default rollback journal a reader collides with the writer, and
// checking on a run in progress is the main reason the command exists. The busy timeout covers the
// brief exclusive moments WAL still needs.
const DSN = "file:" + DBFile + "?_journal_mode=WAL&_busy_timeout=5000"

// States a unit of work can be in.
const (
	StatePending = "pending" // recorded, not finished - either running or interrupted
	StateDone    = "done"    // the tool ran and returned
	StateCached  = "cached"  // the tool did not run; a result file from an earlier run was reused
	StateFailed  = "failed"  // the tool ran and errored, or could not be run
	StateSkipped = "skipped" // deliberately not attempted, e.g. a port-filtered task on a host without that port
)

// Schema is dropped and recreated at the start of every scan, so status always describes the
// current run rather than accumulating across runs.
const Schema = `
DROP TABLE IF EXISTS Status;
CREATE TABLE Status (
	ID         INTEGER PRIMARY KEY AUTOINCREMENT,
	Target     TEXT,
	TaskName   TEXT,
	TaskTarget TEXT,
	State      TEXT NOT NULL DEFAULT 'pending',
	Detail     TEXT,
	StartedAt  DATETIME,
	FinishedAt DATETIME
);
DROP TABLE IF EXISTS Hosts;
CREATE TABLE Hosts (
	Parent   TEXT,
	Host     TEXT,
	TaskName TEXT,
	Mac      TEXT,
	Vendor   TEXT,
	FoundAt  DATETIME,
	UNIQUE(Parent, Host, TaskName)
);
DROP TABLE IF EXISTS Ports;
CREATE TABLE Ports (
	Host     TEXT,
	Port     INTEGER,
	Proto    TEXT,
	TaskName TEXT,
	FoundAt  DATETIME,
	UNIQUE(Host, Port, Proto, TaskName)
);
`

// AddTaskToStatus records a unit of work as started.
func AddTaskToStatus(db *sql.DB, taskName string, target string, taskTarget string) error {
	_, err := db.Exec(
		"INSERT INTO Status (Target, TaskName, TaskTarget, State, StartedAt) VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
		target, taskName, taskTarget, StatePending)
	return err
}

// UpdateDoneTaskInStatus records a unit of work as finished.
func UpdateDoneTaskInStatus(db *sql.DB, taskName string, target string, taskTarget string) error {
	return mark(db, taskName, target, taskTarget, StateDone, "")
}

// MarkCached records a unit of work whose result came off disk without running the tool. It is
// called instead of AddTaskToStatus, so unlike the other marks it usually has no row to update.
func MarkCached(db *sql.DB, taskName string, target string, taskTarget string, detail string) error {
	return mark(db, taskName, target, taskTarget, StateCached, detail)
}

// MarkFailed records a unit of work that errored. Without it a failed target keeps its pending row
// forever and reads as still running, which is the opposite of what a failure should look like.
func MarkFailed(db *sql.DB, taskName string, target string, taskTarget string, detail string) error {
	return mark(db, taskName, target, taskTarget, StateFailed, detail)
}

// MarkTargetFailed fails every unit of work a task still has outstanding against a target. This is
// what a drain loop wants: nc, ffuf and sslscan record one unit per port or URL, so failing a
// single row keyed on the target itself would leave the real units pending forever and add a row
// that matches none of them.
func MarkTargetFailed(db *sql.DB, taskName string, target string, detail string) error {
	res, err := db.Exec(
		"UPDATE Status SET State = ?, Detail = ?, FinishedAt = CURRENT_TIMESTAMP "+
			"WHERE TaskName = ? AND Target = ? AND State = ?",
		StateFailed, detail, taskName, target, StatePending)
	if err != nil {
		return err
	}
	updated, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if updated > 0 {
		return nil
	}
	// Nothing outstanding: the task failed before it recorded itself, so there is no unit to
	// update and the failure would otherwise leave no trace at all.
	return mark(db, taskName, target, target, StateFailed, detail)
}

// MarkTargetSkipped marks whatever a task still has outstanding against a target as deliberately
// not attempted. Unlike MarkTargetFailed it inserts nothing when there is no outstanding work:
// having skipped something that was never recorded is not worth a row.
func MarkTargetSkipped(db *sql.DB, taskName string, target string, reason string) error {
	_, err := db.Exec(
		"UPDATE Status SET State = ?, Detail = ?, FinishedAt = CURRENT_TIMESTAMP "+
			"WHERE TaskName = ? AND Target = ? AND State = ?",
		StateSkipped, reason, taskName, target, StatePending)
	return err
}

// MarkSkipped records a unit of work that was deliberately not attempted.
func MarkSkipped(db *sql.DB, taskName string, target string, taskTarget string, reason string) error {
	return mark(db, taskName, target, taskTarget, StateSkipped, reason)
}

// mark moves an existing row to a terminal state, inserting one if the work was never recorded as
// started. Both paths are needed: a failure usually updates the pending row an executor added
// before running the tool, but a cache hit skips that step entirely, and a task can fail before it
// ever gets to record itself.
func mark(db *sql.DB, taskName string, target string, taskTarget string, state string, detail string) error {
	res, err := db.Exec(
		"UPDATE Status SET State = ?, Detail = ?, FinishedAt = CURRENT_TIMESTAMP "+
			"WHERE TaskName = ? AND Target = ? AND TaskTarget = ? AND State = ?",
		state, detail, taskName, target, taskTarget, StatePending)
	if err != nil {
		return err
	}
	updated, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if updated > 0 {
		return nil
	}
	_, err = db.Exec(
		"INSERT INTO Status (Target, TaskName, TaskTarget, State, Detail, StartedAt, FinishedAt) "+
			"VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)",
		target, taskName, taskTarget, state, detail)
	return err
}

// Discovered is one address a discovery sweep turned up, with the MAC it answered from. The MAC is
// what ties a device's IPv4 and IPv6 addresses together in the report - a host has one NIC, so one
// MAC, but an address per family. Mac/Vendor are empty when the sweep could not learn them (a routed
// segment, or a tool that reports no hardware address).
type Discovered struct {
	Addr   string
	Mac    string
	Vendor string
}

// RecordHosts stores the addresses a task found live under the target it scanned. For a discovery
// sweep that is one row per host in the segment; for a single-host scan parent and host are the
// same address, which the reader ignores.
//
// The MAC is lower-cased on the way in, because the two sources disagree about case: nmap writes it
// uppercase in its XML, the kernel neighbour cache lowercase. Devices() groups on the string, so
// without this a device whose IPv6 MAC came from the neighbour cache and whose IPv4 MAC came from
// the ARP sweep would be two rows that never compare - which is exactly the host the neighbour-cache
// merge exists to rescue.
func RecordHosts(db *sql.DB, parent string, taskName string, hosts []Discovered) error {
	for _, h := range hosts {
		_, err := db.Exec(
			"INSERT OR IGNORE INTO Hosts (Parent, Host, TaskName, Mac, Vendor, FoundAt) "+
				"VALUES (?, ?, ?, ?, ?, CURRENT_TIMESTAMP)",
			parent, h.Addr, taskName, strings.ToLower(h.Mac), h.Vendor)
		if err != nil {
			return err
		}
	}
	return nil
}

// RecordPorts stores the open ports a port scan found on one address. The report diffs these across
// a device's IPv4 and IPv6 addresses - a service reachable over one family but not the other is the
// finding a dual-stack scan exists to surface.
func RecordPorts(db *sql.DB, host string, taskName string, ports []Port) error {
	for _, p := range ports {
		_, err := db.Exec(
			"INSERT OR IGNORE INTO Ports (Host, Port, Proto, TaskName, FoundAt) "+
				"VALUES (?, ?, ?, ?, CURRENT_TIMESTAMP)",
			host, p.Number, p.Proto, taskName)
		if err != nil {
			return err
		}
	}
	return nil
}

// Port is one open port on a host, as a port scan reports it.
type Port struct {
	Number int
	Proto  string
}

// Totals counts units of work by state, for the run summary in the log.
func Totals(db *sql.DB) (map[string]int, error) {
	rows, err := db.Query("SELECT State, COUNT(*) FROM Status GROUP BY State")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	totals := make(map[string]int)
	for rows.Next() {
		var state string
		var count int
		if err := rows.Scan(&state, &count); err != nil {
			return nil, err
		}
		totals[state] = count
	}
	return totals, rows.Err()
}

// Device is one physical device the scan touched, keyed by the MAC its addresses answered from. A
// host has one NIC, so one MAC, but an address per family; grouping by MAC is what lets the report
// put a device's IPv4 and IPv6 findings side by side. The diff fields are precomputed so the
// template only has to render them.
type Device struct {
	Mac         string
	Vendor      string
	V4Addrs     []string
	V6Addrs     []string
	PortsBoth   []string // "22/tcp", open over both families
	PortsV4Only []string // open over IPv4 but not IPv6 - or the reverse below
	PortsV6Only []string
	TasksV4Only []string // a task that ran against the v4 address but not the v6 one
	TasksV6Only []string
}

// Devices groups every discovered address by MAC and works out how the families differ - which
// ports are open on one but not the other, which tasks reached one but not the other. Addresses
// with no MAC (routed hosts, domains) cannot be correlated and are left out; they still appear in
// the per-family sections of the report.
func Devices(db *sql.DB) ([]Device, error) {
	addrs, vendors, err := loadDeviceAddresses(db)
	if err != nil {
		return nil, err
	}
	ports, err := loadPortsByHost(db)
	if err != nil {
		return nil, err
	}
	tasks, err := loadRanTasksByHost(db)
	if err != nil {
		return nil, err
	}

	devices := make([]Device, 0, len(addrs))
	for mac, hostSet := range addrs {
		d := Device{Mac: mac, Vendor: vendors[mac]}
		v4Ports, v6Ports := map[string]bool{}, map[string]bool{}
		v4Tasks, v6Tasks := map[string]bool{}, map[string]bool{}
		for host := range hostSet {
			if target.IsIPv6(host) {
				d.V6Addrs = append(d.V6Addrs, host)
				addAll(v6Ports, ports[host])
				addSet(v6Tasks, tasks[host])
			} else {
				d.V4Addrs = append(d.V4Addrs, host)
				addAll(v4Ports, ports[host])
				addSet(v4Tasks, tasks[host])
			}
		}
		sortTargets(d.V4Addrs)
		sortTargets(d.V6Addrs)
		d.PortsBoth = sortedPorts(intersect(v4Ports, v6Ports))
		d.PortsV4Only = sortedPorts(onlyIn(v4Ports, v6Ports))
		d.PortsV6Only = sortedPorts(onlyIn(v6Ports, v4Ports))
		d.TasksV4Only = sortedStrings(onlyIn(v4Tasks, v6Tasks))
		d.TasksV6Only = sortedStrings(onlyIn(v6Tasks, v4Tasks))
		devices = append(devices, d)
	}
	sortDevices(devices)
	return devices, nil
}

func loadDeviceAddresses(db *sql.DB) (map[string]map[string]bool, map[string]string, error) {
	rows, err := db.Query("SELECT DISTINCT Host, Mac, Vendor FROM Hosts WHERE Mac != ''")
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close()
	addrs := make(map[string]map[string]bool)
	vendors := make(map[string]string)
	for rows.Next() {
		var host, mac, vendor string
		if err := rows.Scan(&host, &mac, &vendor); err != nil {
			return nil, nil, err
		}
		if addrs[mac] == nil {
			addrs[mac] = make(map[string]bool)
		}
		addrs[mac][host] = true
		if vendor != "" {
			vendors[mac] = vendor
		}
	}
	return addrs, vendors, rows.Err()
}

func loadPortsByHost(db *sql.DB) (map[string][]string, error) {
	rows, err := db.Query("SELECT DISTINCT Host, Port, Proto FROM Ports")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ports := make(map[string][]string)
	for rows.Next() {
		var host, proto string
		var port int
		if err := rows.Scan(&host, &port, &proto); err != nil {
			return nil, err
		}
		ports[host] = append(ports[host], fmt.Sprintf("%d/%s", port, proto))
	}
	return ports, rows.Err()
}

func loadRanTasksByHost(db *sql.DB) (map[string]map[string]bool, error) {
	rows, err := db.Query(
		"SELECT DISTINCT Target, TaskName FROM Status WHERE State IN (?, ?)", StateDone, StateCached)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	tasks := make(map[string]map[string]bool)
	for rows.Next() {
		var host, taskName string
		if err := rows.Scan(&host, &taskName); err != nil {
			return nil, err
		}
		if tasks[host] == nil {
			tasks[host] = make(map[string]bool)
		}
		tasks[host][taskName] = true
	}
	return tasks, rows.Err()
}

func addAll(set map[string]bool, items []string) {
	for _, i := range items {
		set[i] = true
	}
}

func addSet(dst, src map[string]bool) {
	for k := range src {
		dst[k] = true
	}
}

func intersect(a, b map[string]bool) map[string]bool {
	out := make(map[string]bool)
	for k := range a {
		if b[k] {
			out[k] = true
		}
	}
	return out
}

func onlyIn(a, b map[string]bool) map[string]bool {
	out := make(map[string]bool)
	for k := range a {
		if !b[k] {
			out[k] = true
		}
	}
	return out
}

func sortedStrings(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// sortedPorts orders "port/proto" entries by port number, so 80 comes before 443 and neither is
// sorted as the string "443" < "80" would place them.
func sortedPorts(set map[string]bool) []string {
	out := sortedStrings(set)
	sort.SliceStable(out, func(i, j int) bool {
		return portNumber(out[i]) < portNumber(out[j])
	})
	return out
}

func portNumber(portProto string) int {
	slash := strings.Index(portProto, "/")
	if slash < 0 {
		slash = len(portProto)
	}
	n, _ := strconv.Atoi(portProto[:slash])
	return n
}

// sortDevices orders devices by their first IPv4 address, then IPv6, then MAC, so a dual-stack
// listing reads in the same order as the IPv4 section above it.
func sortDevices(devices []Device) {
	sort.Slice(devices, func(i, j int) bool {
		ki, kj := deviceSortKey(devices[i]), deviceSortKey(devices[j])
		if ki != kj {
			return lessTarget(ki, kj)
		}
		return devices[i].Mac < devices[j].Mac
	})
}

func deviceSortKey(d Device) string {
	if len(d.V4Addrs) > 0 {
		return d.V4Addrs[0]
	}
	if len(d.V6Addrs) > 0 {
		return d.V6Addrs[0]
	}
	return d.Mac
}

type unit struct {
	taskName   string
	taskTarget string
	state      string
}

// Status prints what has happened to every target in the scope file. A target that is a network is
// expanded into the hosts discovered inside it, each shown with its own task lines - the same shape
// the output would have had if those hosts had been listed in the file individually.
func Status(ctx context.Context, targetFile string, cfg api.Config) error {
	if _, err := os.Stat(DBFile); err != nil {
		return fmt.Errorf("no %s in this directory - run mykmyk scan here first: %w", DBFile, err)
	}
	db, err := sql.Open("sqlite3", DSN)
	if err != nil {
		return err
	}
	defer db.Close()

	entries, err := scope.Load(targetFile)
	if err != nil {
		return err
	}

	units, err := loadUnits(db)
	if err != nil {
		return err
	}
	discovered, err := loadDiscoveredHosts(db)
	if err != nil {
		return err
	}

	order := taskOrder(cfg)
	printed := make(map[string]bool)

	for _, e := range entries {
		// Results are filed under the scope key, not the bare spec: two hosts-file lines can name
		// the same fe80::/10 on different VLANs, and each has its own results.
		key := target.ScopeKey(e.Spec, e.Interface)
		printTarget(key, 0, units[key], order)
		printed[key] = true

		hosts := discovered[key]
		if len(hosts) == 0 {
			fmt.Println()
			continue
		}
		fmt.Printf("%s%d %s up\n", strings.Repeat(" ", taskIndent), len(hosts), plural(len(hosts), "host", "hosts"))
		fmt.Println()
		for _, h := range hosts {
			printTarget(h, hostIndent, units[h], order)
			printed[h] = true
			fmt.Println()
		}
	}

	// Anything the scope file cannot account for still gets shown. A target that reached the
	// database but belongs to no listed network is a discrepancy worth seeing, not one to hide.
	orphans := make([]string, 0)
	for t := range units {
		if !printed[t] {
			orphans = append(orphans, t)
		}
	}
	if len(orphans) > 0 {
		sortTargets(orphans)
		fmt.Println("Other targets")
		fmt.Println()
		for _, o := range orphans {
			printTarget(o, hostIndent, units[o], order)
			fmt.Println()
		}
	}
	return nil
}

const (
	taskIndent = 7  // task lines under a network heading
	hostIndent = 4  // a discovered host's heading, nested under its network
	countCol   = 36 // where the counts line up, whatever the indent
)

func printTarget(target string, indent int, us []unit, order map[string]int) {
	pad := strings.Repeat(" ", indent)
	taskPad := strings.Repeat(" ", indent+taskIndent)
	fmt.Printf("%sStatus for target %s\n", pad, target)
	if len(us) == 0 {
		// Reached mid-scan this is the common case: discovery found the host and nothing has got
		// to it yet. Saying so beats a heading with nothing under it, which reads like a fault.
		fmt.Printf("%snot started\n", taskPad)
		return
	}

	byTask := make(map[string][]unit)
	for _, u := range us {
		byTask[u.taskName] = append(byTask[u.taskName], u)
	}

	nameWidth := countCol - len(taskPad) - 1
	if nameWidth < 1 {
		nameWidth = 1
	}
	for _, name := range sortTaskNames(byTask, order) {
		count, note := summarise(byTask[name])
		line := fmt.Sprintf("%s%-*s %s", taskPad, nameWidth, name, count)
		if note != "" {
			line += "  " + note
		}
		fmt.Println(line)
	}
}

// summarise turns the units of one task against one target into a count and an annotation. Cached
// and skipped units count as settled - the work is not outstanding - but they are called out,
// because "1/1" on a cached task means a result was read off disk, not that anything was scanned.
func summarise(us []unit) (string, string) {
	var done, cached, failed, skipped int
	for _, u := range us {
		switch u.state {
		case StateDone:
			done++
		case StateCached:
			cached++
		case StateFailed:
			failed++
		case StateSkipped:
			skipped++
		}
	}
	count := fmt.Sprintf("%d/%d", done+cached+skipped, len(us))

	notes := make([]string, 0, 3)
	if failed > 0 {
		if failed == len(us) {
			notes = append(notes, "FAILED")
		} else {
			notes = append(notes, fmt.Sprintf("%d FAILED", failed))
		}
	}
	if cached > 0 {
		if cached == len(us) {
			notes = append(notes, "(cached)")
		} else {
			notes = append(notes, fmt.Sprintf("(%d cached)", cached))
		}
	}
	if skipped > 0 {
		if skipped == len(us) {
			notes = append(notes, "(skipped)")
		} else {
			notes = append(notes, fmt.Sprintf("(%d skipped)", skipped))
		}
	}
	return count, strings.Join(notes, "  ")
}

func loadUnits(db *sql.DB) (map[string][]unit, error) {
	rows, err := db.Query("SELECT Target, TaskName, TaskTarget, State FROM Status")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	units := make(map[string][]unit)
	for rows.Next() {
		var target, taskName, taskTarget, state string
		if err := rows.Scan(&target, &taskName, &taskTarget, &state); err != nil {
			return nil, err
		}
		units[target] = append(units[target], unit{taskName: taskName, taskTarget: taskTarget, state: state})
	}
	return units, rows.Err()
}

// loadDiscoveredHosts returns, per scope entry, the addresses found live inside it. Rows where the
// host is the target itself come from scanning a single address and say nothing about discovery.
func loadDiscoveredHosts(db *sql.DB) (map[string][]string, error) {
	rows, err := db.Query("SELECT DISTINCT Parent, Host FROM Hosts WHERE Host != Parent")
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hosts := make(map[string][]string)
	for rows.Next() {
		var parent, host string
		if err := rows.Scan(&parent, &host); err != nil {
			return nil, err
		}
		hosts[parent] = append(hosts[parent], host)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	for parent := range hosts {
		sortTargets(hosts[parent])
	}
	return hosts, nil
}

// taskOrder maps a task name to its position in the workflow, so status lists tasks in the order
// the config runs them rather than in whatever order the map iterates.
func taskOrder(cfg api.Config) map[string]int {
	order := make(map[string]int, len(cfg.Workflow.Tasks))
	for i, t := range cfg.Workflow.Tasks {
		order[t.Name] = i
	}
	return order
}

func sortTaskNames(byTask map[string][]unit, order map[string]int) []string {
	names := make([]string, 0, len(byTask))
	for name := range byTask {
		names = append(names, name)
	}
	sort.Slice(names, func(i, j int) bool {
		pi, iKnown := order[names[i]]
		pj, jKnown := order[names[j]]
		switch {
		case iKnown && jKnown:
			return pi < pj
		case iKnown != jKnown:
			return iKnown // tasks the config knows about first, in workflow order
		default:
			return names[i] < names[j]
		}
	})
	return names
}

// sortTargets orders addresses numerically rather than as strings, so .2 comes before .10.
func sortTargets(targets []string) {
	sort.Slice(targets, func(i, j int) bool {
		return lessTarget(targets[i], targets[j])
	})
}

// lessTarget orders two targets numerically when both are addresses, putting addresses before
// names and falling back to string order otherwise. A zone suffix is stripped first so fe80::2%eth0
// sorts by its address, not by the interface name tacked on the end.
func lessTarget(ai, aj string) bool {
	a, b := net.ParseIP(stripZone(ai)), net.ParseIP(stripZone(aj))
	switch {
	case a != nil && b != nil:
		return bytesCompare(a.To16(), b.To16()) < 0
	case a != nil:
		return true // addresses before names
	case b != nil:
		return false
	default:
		return ai < aj
	}
}

func stripZone(addr string) string {
	if i := strings.Index(addr, "%"); i >= 0 {
		return addr[:i]
	}
	return addr
}

func bytesCompare(a, b []byte) int {
	for i := 0; i < len(a) && i < len(b); i++ {
		if a[i] != b[i] {
			return int(a[i]) - int(b[i])
		}
	}
	return len(a) - len(b)
}

func plural(n int, one string, many string) string {
	if n == 1 {
		return one
	}
	return many
}
