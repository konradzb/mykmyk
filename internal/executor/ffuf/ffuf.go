package ffuf

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/kosmosec/mykmyk/internal/api"
	"github.com/kosmosec/mykmyk/internal/credsmanager"
	"github.com/kosmosec/mykmyk/internal/executor/abstract"
	"github.com/kosmosec/mykmyk/internal/model"
	"github.com/kosmosec/mykmyk/internal/sns"
	"github.com/kosmosec/mykmyk/internal/status"
	"gopkg.in/yaml.v2"
)

type Ffuf struct {
	Type          api.TaskType
	Name          string
	Source        string
	Concurrency   int
	prefix        string
	waitForSignal chan bool
	signalDone    chan bool
	waitFor       string
	output        []model.Output
	mu            sync.Mutex
	once          sync.Once
	cache         cache
	isActive      bool
	isCacheActive bool
	sns           *sns.SNS
	consumer      chan model.Message
	args          []string
}

type scanResult struct {
	target        string
	result        string
	pathsToReport []string
	err           error
}

func (f *Ffuf) Run(ctx context.Context, in interface{}, db *sql.DB) error {
	task, err := f.unmarshal(in)
	if err != nil {
		return err
	}

	f.args = task.Args

	resultCh := make(chan scanResult, f.Concurrency)
	var wg sync.WaitGroup
	limiter := make(chan bool, f.Concurrency)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-f.consumer:
				if !ok {
					wg.Wait()
					close(resultCh)
					return
				}
				f.once.Do(func() {
					f.waitForTask()
				})
				limiter <- true
				wg.Add(1)
				target, err := getHost(msg.Targets[0])
				if err != nil {
					resultCh <- scanResult{target: target, err: err}
					return
				}
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
							result, pathsToReport, err := f.scanTarget(target, msg, db)
							resultCh <- scanResult{target: target, result: result, pathsToReport: pathsToReport, err: err}
							return
						}
					}

				}(ctx, target, msg)
			}
		}

		// for msg := range f.consumer {
		// 	f.once.Do(func() {
		// 		f.waitForTask()
		// 	})
		// 	limiter <- true
		// 	wg.Add(1)
		// 	target, err := getHost(msg.Targets[0])
		// 	if err != nil {
		// 		resultCh <- scanResult{target: target, err: err}
		// 		return
		// 	}
		// 	go func(target string, msg model.Message) {
		// 		defer func() {
		// 			wg.Done()
		// 			<-limiter
		// 		}()
		// 		result, err := f.scanTarget(target, msg)
		// 		resultCh <- scanResult{target: target, result: result, err: err}
		// 	}(target, msg)
		// }
		// wg.Wait()
		// close(resultCh)
	}()

	outputToFile := make(map[string]string)
	for r := range resultCh {
		if r.err != nil {
			// Record and carry on. Returning here ended the whole task on one target's
			// failure - and returned the outer err, nil at this point, so the task went on
			// to report success.
			log.Printf("ffuf: %s scan of %s failed: %s", f.Name, r.target, r.err)
			if err := status.MarkTargetFailed(db, f.Name, r.target, r.err.Error()); err != nil {
				log.Printf("ffuf: unable to record failure of %s for %s: %s", f.Name, r.target, err)
			}
			continue
		}
		liveOutput(f.Name, r.target, r.result)
		outputToFile[r.target] = r.result
		f.collectOutput(r.target, r.result, r.pathsToReport)
	}
	f.saveToFile(outputToFile)
	f.signalDoneTask()
	return nil
}

func (f *Ffuf) New(task api.Task, sns *sns.SNS, creds credsmanager.Credentials) abstract.Executor {
	return &Ffuf{
		Type:          task.Type,
		Name:          task.Name,
		Source:        task.Source,
		Concurrency:   task.Concurrency,
		waitFor:       task.WaitFor,
		isActive:      task.Active,
		isCacheActive: task.UseCache,
		prefix:        task.Prefix,
		output:        make([]model.Output, 0),
		sns:           sns,
	}
}

func (f *Ffuf) GetConcurrency() int {
	return f.Concurrency
}

func (f *Ffuf) SetDoneSignal(signalDone chan bool) {
	f.signalDone = signalDone
}

func (f *Ffuf) SetWaitForSignal(waitForSignal chan bool) {
	f.waitForSignal = waitForSignal
}

func (f *Ffuf) GetWaitFor() string {
	return f.waitFor
}

func (f *Ffuf) GetWaitForSignal() chan bool {
	return f.waitForSignal
}

func (f *Ffuf) GetDoneSignal() chan bool {
	return f.signalDone
}

func (f *Ffuf) Output() []model.Output {
	return f.output
}

func (f *Ffuf) GetType() api.TaskType {
	return f.Type
}

func (f *Ffuf) GetSource() string {
	return f.Source
}
func (f *Ffuf) HasSource() bool {
	if f.Source != "" {
		return true
	}
	return false
}

func (f *Ffuf) GetName() string {
	return f.Name
}

func (f *Ffuf) SetConsumer(c chan model.Message) {
	f.consumer = c
}

func (f *Ffuf) IsActive() bool {
	return f.isActive
}

func (f *Ffuf) unmarshal(in interface{}) (*Task, error) {
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

func (f *Ffuf) waitForTask() {
	if f.waitForSignal != nil {
		<-f.waitForSignal
	}
}

func getHost(rawUrl string) (string, error) {
	u, err := url.Parse(rawUrl)
	if err != nil {
		return "", err
	}

	h := strings.Split(u.Host, ":")
	if len(h) == 1 {
		return h[0], nil
	} else {
		host, _, _ := net.SplitHostPort(u.Host)
		return host, nil
	}
}

func (f *Ffuf) scanTarget(target string, msg model.Message, db *sql.DB) (string, []string, error) {
	fmt.Printf("[+] Ffuf scanning for %s started\n", target)
	cached, reportPaths, found := f.cache.get(target, f.Name)
	if f.isCacheActive && found {
		// One unit per URL, matching how a real run records them, so a cached target reads the
		// same as a scanned one apart from the annotation.
		path := cachePath(target, f.Name)
		log.Printf("ffuf: %s cached for %s, %d %s (%s)", f.Name, target, len(msg.Targets), plural(len(msg.Targets), "url", "urls"), path)
		for _, targetToStatus := range msg.Targets {
			if err := status.MarkCached(db, f.Name, target, targetToStatus, path); err != nil {
				return "", nil, err
			}
		}
		return cached, reportPaths, nil
	}
	for _, targetToStatus := range msg.Targets {
		err := status.AddTaskToStatus(db, f.Name, target, targetToStatus)
		if err != nil {
			return "", nil, err
		}
	}
	log.Printf("ffuf: %s started for %s, %d %s", f.Name, target, len(msg.Targets), plural(len(msg.Targets), "url", "urls"))
	started := time.Now()
	result, pathsToReport, err := scan(target, msg.Targets, f.args, f.prefix, db, f.Name)
	if err != nil {
		return "", nil, err
	}
	log.Printf("ffuf: %s done for %s in %s", f.Name, target, time.Since(started).Round(time.Millisecond))
	return result, pathsToReport, nil
}

func plural(n int, one string, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func liveOutput(taskName string, target string, result string) {
	fmt.Printf("Ffuf scan %s, output for %s\n%s\n", taskName, target, result)
}

func (n *Ffuf) saveToFile(toSave map[string]string) error {
	for target, outputs := range toSave {
		path := fmt.Sprintf("./%s/%s", target, n.Name)
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		defer f.Close()
		if _, err = f.WriteString(outputs); err != nil {
			return err
		}
	}
	return nil
}

func (n *Ffuf) collectOutput(target string, fuzzed string, pathsToReport []string) {
	f := strings.Split(fuzzed, "\n")
	r := model.Results{
		Data:        f,
		ReportPaths: pathsToReport,
	}
	output := model.Output{
		Type:    n.Type,
		Name:    n.Name,
		Target:  target,
		Results: r,
	}
	n.mu.Lock()
	n.output = append(n.output, output)
	n.mu.Unlock()
}

func (n *Ffuf) signalDoneTask() {
	if n.signalDone != nil {
		n.signalDone <- true
	}
}
