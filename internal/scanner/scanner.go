package scanner

import (
	"context"
	"database/sql"
	"fmt"
	"html/template"
	"io/fs"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"github.com/pkg/errors"

	"github.com/kosmosec/mykmyk/internal/api"
	"github.com/kosmosec/mykmyk/internal/credsmanager"
	"github.com/kosmosec/mykmyk/internal/executor"
	"github.com/kosmosec/mykmyk/internal/executor/abstract"
	"github.com/kosmosec/mykmyk/internal/model"
	"github.com/kosmosec/mykmyk/internal/sns"
	"github.com/kosmosec/mykmyk/internal/status"
	nettarget "github.com/kosmosec/mykmyk/internal/target"
)

func Scan(ctx context.Context, cfg api.Config) error {
	ctx, cancelCtx := context.WithCancel(ctx)
	tasks := make([]abstract.Executor, 0)
	tasksRunMap := make(map[string]api.Task)

	sns := sns.New()
	creds := credsmanager.New()
	creds.RequestForCredentials()

	sigs := make(chan os.Signal, 1)
	cleanup := make(chan bool)
	forceCanceled := make(chan bool)
	signal.Notify(sigs, syscall.SIGINT)
	go func() {
		<-sigs
		forceCanceled <- true
		cancelCtx()
		fmt.Println("[!] Aborted!")
		<-cleanup
		os.Exit(1)
	}()

	for _, task := range cfg.Workflow.Tasks {
		concreteExecutor, found := executor.Registered[task.Type]
		if !found {
			return errors.Errorf("unsupported task type %s", task.Type)
		}

		executor := concreteExecutor.New(task, &sns, *creds)
		tasks = append(tasks, executor)
		tasksRunMap[task.Name] = task
	}

	db, err := createStatusDatabase()
	if err != nil {
		return err
	}

	defer db.Close()

	createTopics(tasks, &sns)
	err = addConsumersToTopics(tasks, tasksRunMap, &sns)
	if err != nil {
		return err
	}
	createWaitForConnection(tasks)

	started := time.Now()
	logRunStart(cfg, tasks)

	var wg sync.WaitGroup
	go func() {
		for {
			if err := ctx.Err(); err != nil {
				<-forceCanceled
				fmt.Println(err)
				prettyOutput(cfg.OutputFile, tasks, db)
				cleanup <- true
				return
			}
		}
	}()
	var failedMu sync.Mutex
	failedTasks := make([]string, 0)
	for _, t := range tasks {
		wg.Add(1)
		go func(e abstract.Executor) {
			defer wg.Done()
			if !e.IsActive() {
				log.Printf("scanner: task %s is inactive, skipping", e.GetName())
				return
			}
			taskStarted := time.Now()
			log.Printf("scanner: task %s started", e.GetName())
			err := e.Run(ctx, tasksRunMap[e.GetName()].Run, db)
			if err != nil {
				// Not fatal. Killing the process here loses every other task's results and the
				// report along with them, and writes a single line to a log the user is not
				// watching. One task failing is a gap in the scan, not a reason to discard the
				// rest of it.
				log.Printf("scanner: task %s failed after %s: %s", e.GetName(), time.Since(taskStarted).Round(time.Second), err)
				failedMu.Lock()
				failedTasks = append(failedTasks, e.GetName())
				failedMu.Unlock()
				fmt.Printf("[!] task %s failed: %s\n", e.GetName(), err)
				return
			}
			log.Printf("scanner: task %s finished in %s", e.GetName(), time.Since(taskStarted).Round(time.Second))
		}(t)
	}
	wg.Wait()

	logRunFinish(db, started, failedTasks)

	prettyOutput(cfg.OutputFile, tasks, db)

	if _, err := os.Stat("./report-xml"); os.IsNotExist(err) {
		err := os.Mkdir("./report-xml", 0755)
		if err != nil {
			log.Fatalf("create report folder: %s", err)
		}
	}

	nmapScanName := firstNmapTaskName(cfg.Workflow.Tasks)
	if nmapScanName == "" {
		log.Fatalf("unable to find nmap task name for report")
	}
	nmapScans := findFile(".", nmapScanName+".xml")
	for i, ns := range nmapScans {
		bytesRead, err := os.ReadFile("./" + ns)

		if err != nil {
			log.Fatalf("try to find %s %s", ns, err)
		}

		dest := fmt.Sprintf("%s-%d.xml", "./report-xml/"+nmapScanName, i)
		err = os.WriteFile(dest, bytesRead, 0644)

		if err != nil {
			log.Fatalf("try to write copy content of %s %s", ns, err)
		}
	}

	return nil
}

// logRunStart writes the shape of the run to the log, so a log read later on can be matched against
// the config that produced it - which tasks existed, which were switched off, and how they feed
// each other.
func logRunStart(cfg api.Config, tasks []abstract.Executor) {
	active := 0
	for _, t := range tasks {
		if t.IsActive() {
			active++
		}
	}
	log.Printf("scanner: scan started, %d tasks (%d active), report %s", len(tasks), active, cfg.OutputFile)
	for _, t := range cfg.Workflow.Tasks {
		log.Printf("scanner: task %s type=%s active=%t source=%s waitFor=%s useCache=%t concurrency=%d",
			t.Name, t.Type, t.Active, orNone(t.Source), orNone(t.WaitFor), t.UseCache, t.Concurrency)
	}
}

func logRunFinish(db *sql.DB, started time.Time, failedTasks []string) {
	elapsed := time.Since(started).Round(time.Second)
	totals, err := status.Totals(db)
	if err != nil {
		log.Printf("scanner: scan finished in %s (unable to read totals: %s)", elapsed, err)
		return
	}
	log.Printf("scanner: scan finished in %s, %d done, %d cached, %d failed, %d skipped, %d still pending",
		elapsed, totals[status.StateDone], totals[status.StateCached], totals[status.StateFailed],
		totals[status.StateSkipped], totals[status.StatePending])
	if len(failedTasks) > 0 {
		log.Printf("scanner: tasks that did not complete: %s", strings.Join(failedTasks, ", "))
		fmt.Printf("[!] %d task(s) did not complete: %s - see mykmyk.log\n", len(failedTasks), strings.Join(failedTasks, ", "))
	}
}

func orNone(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// reportData is what the HTML template renders. IPv4 keeps the shape the report has always had -
// every non-IPv6 target, so an IPv4-only scan is unchanged. IPv6 is the same rendering for v6
// addresses, and Devices is the cross-family comparison, keyed by MAC.
type reportData struct {
	IPv4    map[string][]model.Output
	IPv6    map[string][]model.Output
	Devices []status.Device
}

func prettyOutput(reportName string, tasks []abstract.Executor, db *sql.DB) {
	data := reportData{
		IPv4: make(map[string][]model.Output),
		IPv6: make(map[string][]model.Output),
	}
	for _, t := range tasks {
		for _, o := range t.Output() {
			if nettarget.IsIPv6(o.Target) {
				data.IPv6[o.Target] = append(data.IPv6[o.Target], o)
			} else {
				data.IPv4[o.Target] = append(data.IPv4[o.Target], o)
			}
		}
	}
	if devices, err := status.Devices(db); err != nil {
		log.Printf("scanner: unable to build the device comparison: %s", err)
	} else {
		data.Devices = devices
	}

	f, err := os.Create(reportName)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()

	tmpl, err := template.New("").Funcs(template.FuncMap{"join": strings.Join}).Parse(htmlReport)
	if err != nil {
		log.Fatal(err)
	}
	err = tmpl.Execute(f, data)
	if err != nil {
		log.Fatal(err)
	}
}

func createTopics(tasks []abstract.Executor, sns *sns.SNS) {
	for i := range tasks {
		if tasks[i].IsActive() {
			sns.CreateTopic(tasks[i].GetName())
		}
	}
}

func firstNmapTaskName(tasks []api.Task) string {
	for _, t := range tasks {
		if t.Type == "nmap" {
			return t.Name
		}
	}
	return ""
}

// defaultQueueSize is how many messages a task can have waiting for it before its producer
// blocks. It is deliberately far larger than any realistic concurrency: SendMessage blocks until
// every consumer accepts, and a consumer stops reading while its worker pool is saturated, so a
// queue sized to concurrency lets one slow task (ffuf and nuclei run for minutes per target) stall
// port discovery for every host still waiting. Override per task with queueSize.
const defaultQueueSize = 256

func addConsumersToTopics(tasks []abstract.Executor, taskConfig map[string]api.Task, sns *sns.SNS) error {
	for i := range tasks {
		if tasks[i].HasSource() && tasks[i].IsActive() {
			if !isSourceExist(tasks[i].GetSource(), tasks) {
				return errors.Errorf("The task %s has a source %s which not exists", tasks[i].GetName(), tasks[i].GetSource())
			}
			if !isSourceOfTaskIsActive(tasks[i], tasks) {
				return errors.Errorf("The task %s has a inactive source %s", tasks[i].GetName(), tasks[i].GetSource())
			}
			queueSize := taskConfig[tasks[i].GetName()].QueueSize
			if queueSize < defaultQueueSize {
				queueSize = defaultQueueSize
			}
			consumer := make(chan model.Message, queueSize)
			sns.AddConsumer(tasks[i].GetSource(), tasks[i].GetName(), consumer)
			tasks[i].SetConsumer(consumer)
		}
	}
	return nil
}

func isSourceExist(currentTask string, tasks []abstract.Executor) bool {
	for _, t := range tasks {
		if currentTask == t.GetName() {
			return true
		}
	}
	return false
}

func isSourceOfTaskIsActive(currentTask abstract.Executor, tasks []abstract.Executor) bool {
	for _, t := range tasks {
		if currentTask.GetSource() == t.GetName() {
			if !t.IsActive() {
				return false
			}
		}
	}
	return true
}

func createWaitForConnection(tasks []abstract.Executor) {
	for i := range tasks {
		for j := range tasks {
			if tasks[j].GetName() == tasks[i].GetWaitFor() {
				// buffered because we do not know which gorutine runs first
				signal := make(chan bool, 1)
				tasks[i].SetWaitForSignal(signal)
				tasks[j].SetDoneSignal(signal)
			}
		}
	}
}

// return folder/fileName.ext
func findFile(root string, fileName string) []string {
	a := make([]string, 0)
	filepath.WalkDir(root, func(s string, d fs.DirEntry, e error) error {
		if e != nil {
			return e
		}
		if d.Name() == fileName {
			a = append(a, s)
		}
		return nil
	})
	return a
}

func createStatusDatabase() (*sql.DB, error) {
	db, err := sql.Open("sqlite3", status.DSN)
	if err != nil {
		return nil, err
	}
	// Every executor writes progress from its own goroutine. The writes are tiny and rare next to
	// the scans themselves, so serialising them on one connection costs nothing and removes any
	// chance of SQLITE_BUSY between tasks.
	db.SetMaxOpenConns(1)

	_, err = db.Exec(status.Schema)
	if err != nil {
		return nil, err
	}
	return db, nil
}

var htmlReport string = `
<!DOCTYPE html>
<html>
<head>
	<title>Report from scan</title>
	<style type="text/css">
	
body { background: #dedede; font-family: 'Droid sans', Helvetica, Arial, sans-serif; color: #404042; -webkit-font-smoothing: antialiased; }
#container { width: 930px; padding: 0 15px; margin: 20px auto; background-color: #ffffff; }
table { font-family: Arial, sans-serif; }
a:link, a:visited { color: #ff6633; text-decoration: none; }
a:hover, a:active { color: #e24920; text-decoration: underline; }
h1 { font-size: 1.6em; line-height: 1.4em; font-weight: normal; color: #404042; }
h2 { font-size: 1.3em; line-height: 1.2em; padding: 0; margin: 0.8em 0 0.3em 0; font-weight: normal; color: #404042;}
h4 { font-size: 1.0em; line-height: 1.2em; padding: 0; margin: 0.8em 0 0.3em 0; font-weight: bold; color: #404042;}
.rule { height: 0px; border-top: 1px solid #404042; padding: 0; margin: 20px -15px 0 -15px; }
.title { color: #ffffff; background: #1e517e; margin: 0 -15px 10px -15px; overflow: hidden; }
.title h1 { color: #ffffff; padding: 10px 15px; margin: 0; font-size: 1.8em; }
.title img { float: right; display: inline; padding: 1px; }
.heading { background: #404042; margin: 0 -15px 10px -15px; padding: 0; display: inline-block; overflow: hidden; }
.heading img { float: right; display: inline; margin: 8px 10px 0 10px; padding: 0; }
.code { font-family: 'Courier New', Courier, monospace; }
table.overview_table { border: 2px solid #e6e6e6; margin: 0; padding: 5px;}
table.overview_table td.info { padding: 5px; background: #dedede; text-align: right; border-top: 2px solid #ffffff; border-right: 2px solid #ffffff; }
table.overview_table td.info_end { padding: 5px; background: #dedede; text-align: right; border-top: 2px solid #ffffff; }
table.overview_table td.colour_holder { padding: 0px; border-top: 2px solid #ffffff; border-right: 2px solid #ffffff; }
table.overview_table td.colour_holder_end { padding: 0px; border-top: 2px solid #ffffff; }
table.overview_table td.label { padding: 5px; font-weight: bold; }
table.summary_table td { padding: 5px; background: #dedede; text-align: left; border-top: 2px solid #ffffff; border-right: 2px solid #ffffff; }
table.summary_table td.icon { background: #404042; }
.colour_block { padding: 5px; text-align: right; display: block; font-weight: bold; }
.high_certain { border: 2px solid #f32a4c; color: #ffffff; background: #f32a4c; }
.high_firm { border: 2px solid #f997a7; background: #f997a7; }
.high_tentative { border: 2px solid #fddadf; background: #fddadf; }
.medium_certain { border: 2px solid #ff6633; color: #ffffff; background: #ff6633; }
.medium_firm { border: 2px solid #ffb299; background: #ffb299; }
.medium_tentative { border: 2px solid #ffd9cc; background: #ffd9cc; }
.low_certain { border: 2px solid #0094ff; color: #ffffff; background: #0094ff; }
.low_firm { border: 2px solid #7fc9ff; background: #7fc9ff; }
.low_tentative { border: 2px solid #bfe4ff; background: #bfe4ff; }
.info_certain { border: 2px solid #7e8993; color: #ffffff; background: #7e8993; }
.info_firm { border: 2px solid #b9ced2; background: #b9ced2; }
.info_tentative { border: 2px solid #dae9ef; background: #dae9ef; }
.row_total { border: 1px solid #dedede; background: #fff; }
.grad_mark { padding: 4px; border-left: 1px solid #404042; display: inline-block; }
.bar { margin-top: 3px; }
.TOCH0 { font-size: 1.0em; font-weight: bold; word-wrap: break-word; }
.TOCH1 { font-size: 0.8em; text-indent: -20px; padding-left: 50px; margin: 0; word-wrap: break-word; }
.TOCH2 { font-size: 0.8em; text-indent: -20px; padding-left: 70px; margin: 0; word-wrap: break-word; }
.BODH0 { font-size: 1.6em; line-height: 1.2em; font-weight: normal; padding: 10px 15px; margin: 0 -15px 10px -15px; display: inline-block; color: #ffffff; background-color: #1e517e; width: 100%; word-wrap: break-word; }
.BODH0 a:link, .BODH0 a:visited, .BODH0 a:hover, .BODH0 a:active { color: #ffffff; text-decoration: none; }
.BODH1 { font-size: 1.3em; line-height: 1.2em; font-weight: normal; padding: 13px 15px; margin: 0 -15px 0 -15px; display: inline-block; width: 100%; word-wrap: break-word; }
.BODH1 a:link, .BODH1 a:visited, .BODH1 a:hover, .BODH1 a:active { color: #404042; text-decoration: none; }
.BODH2 { font-size: 1.0em; font-weight: bold; line-height: 2.0em; width: 100%; word-wrap: break-word; }
.PREVNEXT { font-size: 0.7em; font-weight: bold; color: #ffffff; padding: 3px 10px; border-radius: 10px;}
.PREVNEXT:link, .PREVNEXT:visited { color: #ff6633 !important; background: #ffffff !important; border: 1px solid #ff6633 !important; text-decoration: none; }
.PREVNEXT:hover, .PREVNEXT:active { color: #fff !important; background: #e24920 !important; border: 1px solid #e24920 !important; text-decoration: none; }
.TEXT { font-size: 0.8em; padding: 0; margin: 0; word-wrap: break-word; }
TD { font-size: 0.8em; }
.HIGHLIGHT { background-color: #fcf446; }
.rr_div { border: 2px solid #1e517e; width: 916px; word-wrap: break-word; -ms-word-wrap: break-word; margin: 0.8em 0; padding: 5px; font-size: 0.8em; max-height: 300px; overflow-y: auto; }

#table-of-content {
	position: fixed;
	top: 100px; /* Adjust this value to position the table of content */
	right: 0;
	width: 200px;
	background-color: #f8f8f8;
	border: 1px solid #ddd;
	padding: 10px;
  }
  
  #table-of-content ul {
	list-style: none;
	padding: 0;
	margin: 0;
  }
  
  #table-of-content li {
	margin-bottom: 5px;
  }
  
  #table-of-content a {
	text-decoration: none;
	color: #333;
  }
  
  #table-of-content a:hover {
	color: #000;
  }

</style>


</head>
<body>
	<div id="table-of-content">
	  <h2>Table of Contents</h2>
	  <ul>
		{{ if .Devices }}<li><a href="#device-comparison" tabindex="1">Device comparison</a></li>{{ end }}
		{{ range $target, $outputs := .IPv4}}
	    <li><a href="#{{ $target }}" tabindex="1">{{ $target }}</a></li>
		{{ end }}
		{{ range $target, $outputs := .IPv6}}
	    <li><a href="#{{ $target }}" tabindex="1">{{ $target }}</a></li>
		{{ end }}
	  </ul>
	</div>

	<div id="container">
	<div class="title">
		<h1>Mykmyk scanner report</h1>
	</div>

	{{ if .Devices }}
	<span class="BODH0" id="device-comparison">Device comparison</span>
	<p class="TEXT">One row per device, matched by MAC across address families. Port and task columns
	show only what differs between a device's IPv4 and IPv6 sides.</p>
	<table class="summary_table">
		<tr>
			<td><b>IPv4</b></td><td><b>IPv6</b></td><td><b>Vendor (MAC)</b></td>
			<td><b>Ports both</b></td><td><b>Ports IPv4 only</b></td><td><b>Ports IPv6 only</b></td>
			<td><b>Tasks IPv4 only</b></td><td><b>Tasks IPv6 only</b></td>
		</tr>
		{{ range $d := .Devices }}
		<tr>
			<td>{{ join $d.V4Addrs ", " }}</td>
			<td>{{ join $d.V6Addrs ", " }}</td>
			<td>{{ $d.Vendor }}<br><span class="code">{{ $d.Mac }}</span></td>
			<td>{{ join $d.PortsBoth ", " }}</td>
			<td>{{ join $d.PortsV4Only ", " }}</td>
			<td>{{ join $d.PortsV6Only ", " }}</td>
			<td>{{ join $d.TasksV4Only ", " }}</td>
			<td>{{ join $d.TasksV6Only ", " }}</td>
		</tr>
		{{ end }}
	</table>
	<div class="rule"></div>
	{{ end }}

	{{ if .IPv4 }}<span class="BODH1">IPv4</span>{{ end }}
	{{ template "targetOutputs" .IPv4 }}
	{{ if .IPv6 }}<span class="BODH1">IPv6</span>{{ end }}
	{{ template "targetOutputs" .IPv6 }}
	</div>
</body>
</html>

{{ define "targetOutputs" }}
	{{range $target, $outputs := .}}
		<span class="BODH0" id="{{ $target }}">{{ $target }}</span>
		{{ range $output := $outputs}}
			<span class="TEXT">

			<h2>{{ $output.Type }}</h2>
			<h3>{{ $output.Name }}</h3>
			</span>


			{{if eq $output.Type "httpx" }}
				<div class="rr_div">
				{{ range $d := $output.Results.Data}}
					<p><a href="{{ $d }}">{{ $d }}</a></p>
				{{ end }}
				</div>
			{{ else if eq $output.Type "ffuf" }}
				<p>Ffuf reports in html</p>
				{{ range $ffufReportPath := $output.Results.ReportPaths }}
					<p><a href="{{ $ffufReportPath }}">{{ $ffufReportPath }}</a></p>
				{{ end }}
			{{ else }}
				<div class="rr_div">
					{{ range $d := $output.Results.Data }}
						<p><span>{{ $d }}</span></p>
					{{ end }}
				</div>
			{{ end }}
			<div class="rule"></div>
		{{end}}
	{{end}}
{{ end }}
`
