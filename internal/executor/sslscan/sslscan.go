package sslscan

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

type SSLScan struct {
	Type          api.TaskType
	Name          string
	Source        string
	Port          int
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

func (s *SSLScan) Run(ctx context.Context, in interface{}, db *sql.DB) error {
	task, err := s.unmarshal(in)
	if err != nil {
		return err
	}
	s.args = task.Args

	resultCh := make(chan scanResult, s.Concurrency)
	var wg sync.WaitGroup
	limiter := make(chan bool, s.Concurrency)

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-s.consumer:
				if !ok {
					wg.Wait()
					close(resultCh)
					return
				}
				s.once.Do(func() {
					s.waitForTask()
				})
				limiter <- true
				wg.Add(1)
				var target string
				if len(msg.Ports) == 0 {
					target, err = getHost(msg.Targets[0])
					if err != nil {
						resultCh <- scanResult{target: target, err: err}
						return
					}
				} else {
					target = msg.Targets[0]
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
							result, pathsToReport, err := s.scanTarget(target, msg, db)
							resultCh <- scanResult{target: target, result: result, pathsToReport: pathsToReport, err: err}
							return
						}
					}

				}(ctx, target, msg)
			}
		}
	}()

	outputToFile := make(map[string]string)
	for r := range resultCh {
		if r.err != nil {
			// Record and carry on. Returning here ended the whole task on one target's
			// failure - and returned the outer err, nil at this point, so the task went on
			// to report success.
			log.Printf("sslscan: %s scan of %s failed: %s", s.Name, r.target, r.err)
			if err := status.MarkTargetFailed(db, s.Name, r.target, r.err.Error()); err != nil {
				log.Printf("sslscan: unable to record failure of %s for %s: %s", s.Name, r.target, err)
			}
			continue
		}
		liveOutput(s.Name, r.target, r.result)
		outputToFile[r.target] = r.result
		s.collectOutput(r.target, r.result, r.pathsToReport)
	}
	s.saveToFile(outputToFile)
	s.signalDoneTask()
	return nil
}

func (s *SSLScan) New(task api.Task, sns *sns.SNS, creds credsmanager.Credentials) abstract.Executor {
	return &SSLScan{
		Type:          task.Type,
		Name:          task.Name,
		Source:        task.Source,
		Port:          task.Port,
		Concurrency:   task.Concurrency,
		waitFor:       task.WaitFor,
		isActive:      task.Active,
		isCacheActive: task.UseCache,
		prefix:        task.Prefix,
		output:        make([]model.Output, 0),
		sns:           sns,
	}
}

func (s *SSLScan) GetConcurrency() int {
	return s.Concurrency
}

func (s *SSLScan) SetDoneSignal(signalDone chan bool) {
	s.signalDone = signalDone
}

func (s *SSLScan) SetWaitForSignal(waitForSignal chan bool) {
	s.waitForSignal = waitForSignal
}

func (s *SSLScan) GetWaitFor() string {
	return s.waitFor
}

func (s *SSLScan) GetWaitForSignal() chan bool {
	return s.waitForSignal
}

func (s *SSLScan) GetDoneSignal() chan bool {
	return s.signalDone
}

func (s *SSLScan) Output() []model.Output {
	return s.output
}

func (s *SSLScan) GetType() api.TaskType {
	return s.Type
}

func (s *SSLScan) GetSource() string {
	return s.Source
}
func (s *SSLScan) HasSource() bool {
	if s.Source != "" {
		return true
	}
	return false
}

func (s *SSLScan) GetName() string {
	return s.Name
}

func (s *SSLScan) SetConsumer(c chan model.Message) {
	s.consumer = c
}

func (s *SSLScan) IsActive() bool {
	return s.isActive
}

func (s *SSLScan) unmarshal(in interface{}) (*Task, error) {
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

func (s *SSLScan) waitForTask() {
	if s.waitForSignal != nil {
		<-s.waitForSignal
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

func (s *SSLScan) scanTarget(target string, msg model.Message, db *sql.DB) (string, []string, error) {
	fmt.Printf("[+] SSLscan scanning for %s started\n", target)
	cached, reportPaths, found := s.cache.get(target, s.Name)
	if s.isCacheActive && found {
		// One unit per URL, matching how a real run records them, so a cached target reads the
		// same as a scanned one apart from the annotation.
		path := cachePath(target, s.Name)
		log.Printf("sslscan: %s cached for %s, %d %s (%s)", s.Name, target, len(msg.Targets), plural(len(msg.Targets), "target", "targets"), path)
		for _, targetToStatus := range msg.Targets {
			if err := status.MarkCached(db, s.Name, target, targetToStatus, path); err != nil {
				return "", nil, err
			}
		}
		return cached, reportPaths, nil
	}
	for _, targetToStatus := range msg.Targets {
		err := status.AddTaskToStatus(db, s.Name, target, targetToStatus)
		if err != nil {
			return "", nil, err
		}
	}
	log.Printf("sslscan: %s started for %s, %d %s", s.Name, target, len(msg.Targets), plural(len(msg.Targets), "target", "targets"))
	started := time.Now()
	result, pathsToReport, err := scan(target, msg.Targets, msg.Ports, s.Port, msg.Interface, s.args, db, s.Name)
	if err != nil {
		return "", nil, err
	}
	log.Printf("sslscan: %s done for %s in %s", s.Name, target, time.Since(started).Round(time.Millisecond))
	return result, pathsToReport, nil
}

func plural(n int, one string, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func liveOutput(taskName string, target string, result string) {
	fmt.Printf("SSLScan scan %s, output for %s\n%s\n", taskName, target, result)
}

func (s *SSLScan) saveToFile(toSave map[string]string) error {
	for target, outputs := range toSave {
		path := fmt.Sprintf("./%s/%s", target, s.Name)
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

func (s *SSLScan) collectOutput(target string, scanned string, pathsToReport []string) {
	f := strings.Split(scanned, "\n")
	r := model.Results{
		Data:        f,
		ReportPaths: pathsToReport,
	}
	output := model.Output{
		Type:    s.Type,
		Name:    s.Name,
		Target:  target,
		Results: r,
	}
	s.mu.Lock()
	s.output = append(s.output, output)
	s.mu.Unlock()
}

func (s *SSLScan) signalDoneTask() {
	if s.signalDone != nil {
		s.signalDone <- true
	}
}
