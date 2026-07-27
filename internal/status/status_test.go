package status

import (
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"

	"github.com/kosmosec/mykmyk/internal/api"
)

// inScanDirectory moves the test into an empty working directory. Both the database and the hosts
// file are resolved relative to the directory a scan ran in, so the tests have to stand where a
// user would.
func inScanDirectory(t *testing.T) {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %s", err)
	}
	if err := os.Chdir(t.TempDir()); err != nil {
		t.Fatalf("chdir: %s", err)
	}
	t.Cleanup(func() { os.Chdir(wd) })
}

func newDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite3", DSN)
	if err != nil {
		t.Fatalf("open db: %s", err)
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(Schema); err != nil {
		t.Fatalf("create schema: %s", err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

// discovered wraps bare addresses as Discovered records with no MAC, for the tests that only care
// about host attribution and not device correlation.
func discovered(addrs ...string) []Discovered {
	hosts := make([]Discovered, 0, len(addrs))
	for _, a := range addrs {
		hosts = append(hosts, Discovered{Addr: a})
	}
	return hosts
}

func writeHosts(t *testing.T, content string) string {
	t.Helper()
	p := filepath.Join(".", "hosts")
	if err := os.WriteFile(p, []byte(content), 0644); err != nil {
		t.Fatalf("write hosts: %s", err)
	}
	return p
}

func capture(t *testing.T, fn func() error) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %s", err)
	}
	stdout := os.Stdout
	os.Stdout = w
	runErr := fn()
	os.Stdout = stdout
	w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured output: %s", err)
	}
	if runErr != nil {
		t.Fatalf("Status: %s", runErr)
	}
	return string(out)
}

func config(taskNames ...string) api.Config {
	tasks := make([]api.Task, 0, len(taskNames))
	for _, n := range taskNames {
		tasks = append(tasks, api.Task{Name: n})
	}
	return api.Config{Workflow: api.Workflow{Tasks: tasks}}
}

func done(t *testing.T, db *sql.DB, task, target, taskTarget string) {
	t.Helper()
	if err := AddTaskToStatus(db, task, target, taskTarget); err != nil {
		t.Fatalf("add %s/%s: %s", task, target, err)
	}
	if err := UpdateDoneTaskInStatus(db, task, target, taskTarget); err != nil {
		t.Fatalf("done %s/%s: %s", task, target, err)
	}
}

func pending(t *testing.T, db *sql.DB, task, target, taskTarget string) {
	t.Helper()
	if err := AddTaskToStatus(db, task, target, taskTarget); err != nil {
		t.Fatalf("add %s/%s: %s", task, target, err)
	}
}

// The point of the whole change: a hosts file naming a network has to come back as the hosts found
// inside it, each with its own task lines, rather than a single line for the discovery sweep.
func TestStatusExpandsNetworkIntoDiscoveredHosts(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)

	done(t, db, "arp-discovery", "192.168.1.0/24", "192.168.1.0/24")
	if err := RecordHosts(db, "192.168.1.0/24", "arp-discovery", discovered("192.168.1.10", "192.168.1.2")); err != nil {
		t.Fatalf("record hosts: %s", err)
	}
	done(t, db, "ST-scan", "192.168.1.2", "192.168.1.2")
	done(t, db, "SV-scan", "192.168.1.2", "192.168.1.2")
	done(t, db, "ST-scan", "192.168.1.10", "192.168.1.10")
	pending(t, db, "SV-scan", "192.168.1.10", "192.168.1.10")

	hosts := writeHosts(t, "192.168.1.0/24 eth0.100\n")
	out := capture(t, func() error {
		return Status(context.Background(), hosts, config("arp-discovery", "ST-scan", "SV-scan"))
	})

	want := strings.Join([]string{
		"Status for target 192.168.1.0/24",
		"       arp-discovery                1/1",
		"       2 hosts up",
		"",
		"    Status for target 192.168.1.2",
		"           ST-scan                  1/1",
		"           SV-scan                  1/1",
		"",
		"    Status for target 192.168.1.10",
		"           ST-scan                  1/1",
		"           SV-scan                  0/1",
		"",
		"",
	}, "\n")
	if diff := cmp.Diff(want, out); diff != "" {
		t.Errorf("status output mismatch (-want +got):\n%s", diff)
	}
}

// Checking on a run in progress is the main reason the command exists, so a host discovery has
// found but nothing has reached yet has to say so rather than render an empty heading.
func TestStatusMarksDiscoveredHostsNotStarted(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)

	done(t, db, "arp-discovery", "192.168.1.0/24", "192.168.1.0/24")
	if err := RecordHosts(db, "192.168.1.0/24", "arp-discovery", discovered("192.168.1.7")); err != nil {
		t.Fatalf("record hosts: %s", err)
	}

	hosts := writeHosts(t, "192.168.1.0/24\n")
	out := capture(t, func() error {
		return Status(context.Background(), hosts, config("arp-discovery", "ST-scan"))
	})

	if !strings.Contains(out, "    Status for target 192.168.1.7\n           not started\n") {
		t.Errorf("host with no recorded work should read as not started:\n%s", out)
	}
}

// The two-column hosts file the ARP profile documents used to match nothing, because the reader
// kept its own parser that took the whole line - interface column and all - as the target.
func TestStatusReadsTheInterfaceColumn(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)
	done(t, db, "arp-discovery", "10.113.9.0/24", "10.113.9.0/24")

	hosts := writeHosts(t, "# internal\n10.113.9.0/24   eth0.100   # vlan 100\n")
	out := capture(t, func() error {
		return Status(context.Background(), hosts, config("arp-discovery"))
	})

	if !strings.Contains(out, "Status for target 10.113.9.0/24") {
		t.Errorf("scope entry not matched, output was:\n%s", out)
	}
	if !strings.Contains(out, "arp-discovery") {
		t.Errorf("task line missing, output was:\n%s", out)
	}
}

func TestStatusAnnotatesCachedFailedAndSkipped(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)

	if err := MarkCached(db, "SV-scan", "10.0.0.1", "10.0.0.1", "./10.0.0.1/SV-scan.xml"); err != nil {
		t.Fatalf("cached: %s", err)
	}
	if err := MarkFailed(db, "httpx-scan", "10.0.0.1", "10.0.0.1", "exit 2"); err != nil {
		t.Fatalf("failed: %s", err)
	}
	if err := MarkSkipped(db, "rdp-check", "10.0.0.1", "10.0.0.1", "port 3389 not open"); err != nil {
		t.Fatalf("skipped: %s", err)
	}
	// A fan-out task: three ports, one still running.
	done(t, db, "nc-fingerprint", "10.0.0.1", "10.0.0.1:22")
	done(t, db, "nc-fingerprint", "10.0.0.1", "10.0.0.1:80")
	pending(t, db, "nc-fingerprint", "10.0.0.1", "10.0.0.1:443")

	hosts := writeHosts(t, "10.0.0.1\n")
	out := capture(t, func() error {
		return Status(context.Background(), hosts, config("SV-scan", "httpx-scan", "nc-fingerprint", "rdp-check"))
	})

	for _, want := range []string{
		"SV-scan                      1/1  (cached)",
		"httpx-scan                   0/1  FAILED",
		"nc-fingerprint               2/3",
		"rdp-check                    1/1  (skipped)",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

// A cache hit records nothing today, so a re-run with useCache set on every task shows an empty
// status. The row has to exist, and has to say the tool did not run.
func TestStatusShowsFullyCachedRerun(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)

	if err := MarkCached(db, "arp-discovery", "192.168.1.0/24", "192.168.1.0/24", "./192.168.1.0_24/arp-discovery.xml"); err != nil {
		t.Fatalf("cached: %s", err)
	}
	if err := RecordHosts(db, "192.168.1.0/24", "arp-discovery", discovered("192.168.1.5")); err != nil {
		t.Fatalf("record hosts: %s", err)
	}
	if err := MarkCached(db, "ST-scan", "192.168.1.5", "192.168.1.5", "./192.168.1.5/ST-scan.xml"); err != nil {
		t.Fatalf("cached: %s", err)
	}

	hosts := writeHosts(t, "192.168.1.0/24\n")
	out := capture(t, func() error {
		return Status(context.Background(), hosts, config("arp-discovery", "ST-scan"))
	})

	for _, want := range []string{"1 host up", "192.168.1.5", "ST-scan", "(cached)"} {
		if !strings.Contains(out, want) {
			t.Errorf("missing %q in output:\n%s", want, out)
		}
	}
}

func TestStatusOrdersTasksByWorkflowThenName(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)

	// Inserted in an order that is neither the workflow's nor alphabetical.
	done(t, db, "zz-unconfigured", "10.0.0.1", "10.0.0.1")
	done(t, db, "SV-scan", "10.0.0.1", "10.0.0.1")
	done(t, db, "aa-unconfigured", "10.0.0.1", "10.0.0.1")
	done(t, db, "ST-scan", "10.0.0.1", "10.0.0.1")

	hosts := writeHosts(t, "10.0.0.1\n")
	out := capture(t, func() error {
		return Status(context.Background(), hosts, config("ST-scan", "SV-scan"))
	})

	got := make([]string, 0, 4)
	for _, line := range strings.Split(out, "\n") {
		if f := strings.Fields(line); len(f) == 2 && strings.Contains(f[1], "/") {
			got = append(got, f[0])
		}
	}
	// Configured tasks in workflow order first, then anything else alphabetically.
	want := []string{"ST-scan", "SV-scan", "aa-unconfigured", "zz-unconfigured"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("task order mismatch (-want +got):\n%s", diff)
	}
}

// A target that reached the database but belongs to no listed network is a discrepancy. Hiding it
// would make the output look complete when it is not.
func TestStatusReportsUnattributedTargets(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)

	done(t, db, "arp-discovery", "192.168.1.0/24", "192.168.1.0/24")
	done(t, db, "ST-scan", "10.9.9.9", "10.9.9.9")

	hosts := writeHosts(t, "192.168.1.0/24\n")
	out := capture(t, func() error {
		return Status(context.Background(), hosts, config("arp-discovery", "ST-scan"))
	})

	if !strings.Contains(out, "Other targets") {
		t.Errorf("unattributed target not reported:\n%s", out)
	}
	if !strings.Contains(out, "10.9.9.9") {
		t.Errorf("unattributed target address missing:\n%s", out)
	}
}

// A hosts file of individual addresses has to keep behaving exactly as it did before.
func TestStatusWithIndividualHosts(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)

	done(t, db, "ST-scan", "20.77.132.140", "20.77.132.140")
	pending(t, db, "SV-scan", "20.77.132.140", "20.77.132.140")

	hosts := writeHosts(t, "20.77.132.140\n")
	out := capture(t, func() error {
		return Status(context.Background(), hosts, config("ST-scan", "SV-scan"))
	})

	want := strings.Join([]string{
		"Status for target 20.77.132.140",
		"       ST-scan                      1/1",
		"       SV-scan                      0/1",
		"",
		"",
	}, "\n")
	if diff := cmp.Diff(want, out); diff != "" {
		t.Errorf("status output mismatch (-want +got):\n%s", diff)
	}
	if strings.Contains(out, "hosts up") {
		t.Errorf("a single address is not a discovery result:\n%s", out)
	}
}

func TestStatusWithoutDatabase(t *testing.T) {
	inScanDirectory(t)
	hosts := writeHosts(t, "10.0.0.1\n")
	err := Status(context.Background(), hosts, config())
	if err == nil {
		t.Fatal("expected an error when there is no status.db, got nil")
	}
	if !strings.Contains(err.Error(), DBFile) {
		t.Errorf("error should name the missing database, got: %s", err)
	}
}

// MarkTargetFailed has to retire every unit a fan-out task left outstanding, not just one.
func TestMarkTargetFailedRetiresAllPendingUnits(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)

	pending(t, db, "nc-fingerprint", "10.0.0.1", "10.0.0.1:22")
	pending(t, db, "nc-fingerprint", "10.0.0.1", "10.0.0.1:80")
	done(t, db, "nc-fingerprint", "10.0.0.1", "10.0.0.1:443")

	if err := MarkTargetFailed(db, "nc-fingerprint", "10.0.0.1", "connection reset"); err != nil {
		t.Fatalf("MarkTargetFailed: %s", err)
	}

	totals, err := Totals(db)
	if err != nil {
		t.Fatalf("Totals: %s", err)
	}
	if totals[StateFailed] != 2 {
		t.Errorf("want 2 failed units, got %d", totals[StateFailed])
	}
	if totals[StateDone] != 1 {
		t.Errorf("a finished unit must not be reopened, got %d done", totals[StateDone])
	}
	if totals[StatePending] != 0 {
		t.Errorf("want nothing left pending, got %d", totals[StatePending])
	}
}

// A task that fails before it records itself still has to leave a trace.
func TestMarkTargetFailedWithNothingRecorded(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)

	if err := MarkTargetFailed(db, "httpx-scan", "10.0.0.1", "httpx not found in PATH"); err != nil {
		t.Fatalf("MarkTargetFailed: %s", err)
	}
	totals, err := Totals(db)
	if err != nil {
		t.Fatalf("Totals: %s", err)
	}
	if totals[StateFailed] != 1 {
		t.Errorf("want 1 failed unit, got %d", totals[StateFailed])
	}
}

func TestSortTargetsOrdersAddressesNumerically(t *testing.T) {
	got := []string{"192.168.1.10", "pentest.co.uk", "192.168.1.2", "192.168.1.100"}
	sortTargets(got)
	want := []string{"192.168.1.2", "192.168.1.10", "192.168.1.100", "pentest.co.uk"}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Errorf("sort mismatch (-want +got):\n%s", diff)
	}
}

// The comparison is the whole reason MAC is recorded: a device answering on both families becomes a
// single row, and the port/task columns show only what differs between its IPv4 and IPv6 sides.
func TestDevicesComparesFamiliesByMac(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)

	// One device, one MAC, an address per family.
	if err := RecordHosts(db, "192.168.1.0/24", "discovery",
		[]Discovered{{Addr: "192.168.1.5", Mac: "aa:bb:cc:dd:ee:ff", Vendor: "Acme"}}); err != nil {
		t.Fatalf("record v4 host: %s", err)
	}
	if err := RecordHosts(db, "fe80::/10", "discovery",
		[]Discovered{{Addr: "fe80::5", Mac: "aa:bb:cc:dd:ee:ff", Vendor: "Acme"}}); err != nil {
		t.Fatalf("record v6 host: %s", err)
	}

	// 22 open on both, 80 only on v4, 443 only on v6.
	if err := RecordPorts(db, "192.168.1.5", "ST-scan", []Port{{22, "tcp"}, {80, "tcp"}}); err != nil {
		t.Fatalf("record v4 ports: %s", err)
	}
	if err := RecordPorts(db, "fe80::5", "ST-scan", []Port{{22, "tcp"}, {443, "tcp"}}); err != nil {
		t.Fatalf("record v6 ports: %s", err)
	}

	// httpx ran against the v4 address only.
	done(t, db, "ST-scan", "192.168.1.5", "192.168.1.5")
	done(t, db, "httpx-scan", "192.168.1.5", "192.168.1.5")
	done(t, db, "ST-scan", "fe80::5", "fe80::5")

	devices, err := Devices(db)
	if err != nil {
		t.Fatalf("Devices: %s", err)
	}
	want := []Device{{
		Mac:         "aa:bb:cc:dd:ee:ff",
		Vendor:      "Acme",
		V4Addrs:     []string{"192.168.1.5"},
		V6Addrs:     []string{"fe80::5"},
		PortsBoth:   []string{"22/tcp"},
		PortsV4Only: []string{"80/tcp"},
		PortsV6Only: []string{"443/tcp"},
		TasksV4Only: []string{"httpx-scan"},
		TasksV6Only: []string{},
	}}
	if diff := cmp.Diff(want, devices); diff != "" {
		t.Errorf("device comparison mismatch (-want +got):\n%s", diff)
	}
}

// A device with no MAC cannot be correlated across families and must be left out of the comparison
// rather than shown as a v4-only or v6-only mystery row.
func TestDevicesSkipsHostsWithoutMac(t *testing.T) {
	inScanDirectory(t)
	db := newDB(t)

	if err := RecordHosts(db, "192.168.1.0/24", "discovery",
		[]Discovered{{Addr: "192.168.1.9"}}); err != nil {
		t.Fatalf("record host: %s", err)
	}
	done(t, db, "ST-scan", "192.168.1.9", "192.168.1.9")

	devices, err := Devices(db)
	if err != nil {
		t.Fatalf("Devices: %s", err)
	}
	if len(devices) != 0 {
		t.Errorf("want no devices for a MAC-less host, got %d: %+v", len(devices), devices)
	}
}
