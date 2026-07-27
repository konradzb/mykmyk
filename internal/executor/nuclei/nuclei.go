package nuclei

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

type Nuclei struct {
	Type          api.TaskType
	Name          string
	Source        string
	Concurrency   int
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
	target string
	result string
	err    error
}

func (n *Nuclei) scanTarget(target string, msg model.Message, db *sql.DB) (string, error) {
	fmt.Printf("[+] Nuclei scanning for %s started\n", target)
	cached, found := n.cache.get(target, n.Name)
	if n.isCacheActive && found {
		// Recorded, not silently returned: without a row here a re-run over a warm cache
		// leaves status empty, and a plain count would not say whether anything ran.
		path := cachePath(target, n.Name)
		log.Printf("nuclei: %s cached for %s (%s)", n.Name, target, path)
		return cached, status.MarkCached(db, n.Name, target, target, path)
	}
	err := status.AddTaskToStatus(db, n.Name, target, target)
	if err != nil {
		return "", err
	}
	log.Printf("nuclei: %s started for %s", n.Name, target)
	started := time.Now()
	result, err := scan(target, msg.Targets, n.args)
	if err != nil {
		return "", err
	}
	err = status.UpdateDoneTaskInStatus(db, n.Name, target, target)
	if err != nil {
		return "", err
	}
	log.Printf("nuclei: %s done for %s in %s", n.Name, target, time.Since(started).Round(time.Millisecond))
	return result, nil

}

func liveOutput(taskName string, target string, result string) {
	fmt.Printf("Nuclei scan %s, output for %s\n%s\n", taskName, target, result)
}

func (n *Nuclei) collectOutput(target string, result string) {
	r := strings.Split(result, "\n")
	output := model.Output{
		Type:    n.Type,
		Name:    n.Name,
		Target:  target,
		Results: model.Results{Data: r},
	}
	n.mu.Lock()
	n.output = append(n.output, output)
	n.mu.Unlock()
}

func (n *Nuclei) Run(ctx context.Context, in interface{}, db *sql.DB) error {
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
				n.once.Do(func() {
					n.waitForTask()
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
							result, err := n.scanTarget(target, msg, db)
							resultCh <- scanResult{target: target, result: result, err: err}
							return
						}
					}

				}(ctx, target, msg)
			}
		}

		// for msg := range n.consumer {
		// 	n.once.Do(func() {
		// 		n.waitForTask()
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
		// 		result, err := n.scanTarget(target, msg)
		// 		resultCh <- scanResult{target: target, result: result, err: err}
		// 	}(target, msg)
		// }
		// wg.Wait()
		// close(resultCh)
	}()

	for r := range resultCh {
		if r.err != nil {
			// Record and carry on. Returning here ended the whole task on one target's
			// failure - and returned the outer err, nil at this point, so the task went on
			// to report success.
			log.Printf("nuclei: %s scan of %s failed: %s", n.Name, r.target, r.err)
			if err := status.MarkTargetFailed(db, n.Name, r.target, r.err.Error()); err != nil {
				log.Printf("nuclei: unable to record failure of %s for %s: %s", n.Name, r.target, err)
			}
			continue
		}
		liveOutput(n.Name, r.target, r.result)
		n.saveToFile(r.target, r.result)
		n.collectOutput(r.target, r.result)
	}
	n.signalDoneTask()
	return nil
}

func (n *Nuclei) saveToFile(target string, output string) error {
	path := fmt.Sprintf("./%s/%s", target, n.Name)
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err = f.WriteString(output); err != nil {
		return err
	}

	return nil
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

func (h *Nuclei) New(task api.Task, sns *sns.SNS, creds credsmanager.Credentials) abstract.Executor {
	return &Nuclei{
		Type:          task.Type,
		Name:          task.Name,
		Source:        task.Source,
		Concurrency:   task.Concurrency,
		waitFor:       task.WaitFor,
		isActive:      task.Active,
		isCacheActive: task.UseCache,
		output:        make([]model.Output, 0),
		sns:           sns,
	}
}

func (n *Nuclei) GetConcurrency() int {
	return n.Concurrency
}

func (n *Nuclei) signalDoneTask() {
	if n.signalDone != nil {
		n.signalDone <- true
	}
}

func (n *Nuclei) waitForTask() {
	if n.waitForSignal != nil {
		<-n.waitForSignal
	}
}

func (n *Nuclei) SetDoneSignal(signalDone chan bool) {
	n.signalDone = signalDone
}

func (n *Nuclei) SetWaitForSignal(waitForSignal chan bool) {
	n.waitForSignal = waitForSignal
}

func (n *Nuclei) GetWaitFor() string {
	return n.waitFor
}

func (n *Nuclei) GetWaitForSignal() chan bool {
	return n.waitForSignal
}

func (n *Nuclei) GetDoneSignal() chan bool {
	return n.signalDone
}

func (n *Nuclei) Output() []model.Output {
	return n.output
}

func (n *Nuclei) GetType() api.TaskType {
	return n.Type
}

func (n *Nuclei) GetSource() string {
	return n.Source
}
func (n *Nuclei) HasSource() bool {
	if n.Source != "" {
		return true
	}
	return false
}

func (n *Nuclei) GetName() string {
	return n.Name
}

func (n *Nuclei) unmarshal(in interface{}) (*Task, error) {
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

func (n *Nuclei) SetConsumer(c chan model.Message) {
	n.consumer = c
}

func (n *Nuclei) IsActive() bool {
	return n.isActive
}
