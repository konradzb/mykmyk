package filesystem

import (
	"context"
	"database/sql"
	"log"

	"github.com/kosmosec/mykmyk/internal/api"
	"github.com/kosmosec/mykmyk/internal/credsmanager"
	"github.com/kosmosec/mykmyk/internal/executor/abstract"
	"github.com/kosmosec/mykmyk/internal/model"
	"github.com/kosmosec/mykmyk/internal/scope"
	"github.com/kosmosec/mykmyk/internal/sns"
	"github.com/pkg/errors"
	"gopkg.in/yaml.v2"
)

type Filesystem struct {
	Type          api.TaskType
	Name          string
	Source        string
	Concurrency   int
	waitForSignal chan bool
	waitFor       string
	signalDone    chan bool
	isActive      bool
	isCacheActive bool
	output        []model.Output
	sns           *sns.SNS
	consumer      chan model.Message
}

func (f *Filesystem) Run(ctx context.Context, in interface{}, db *sql.DB) error {
	f.waitForTask()
	task, err := f.unmarshal(in)
	if err != nil {
		return err
	}

	switch f.Name {
	case "scope":
		entries, err := scope.Load(task.Input)
		if err != nil {
			// Wrap, don't Errorf: scope.Load reports unreadable files and overlapping segments,
			// and Errorf with no verb would drop that detail on the floor.
			return errors.Wrap(err, "unable to load scope")
		}
		log.Printf("filesystem: loaded %d scope %s from %s", len(entries), plural(len(entries), "entry", "entries"), task.Input)
		for _, s := range entries {
			log.Printf("filesystem: scope entry %s via %s", s.Spec, describeInterface(s.Interface))
			m := model.Message{Targets: []string{s.Spec}, Interface: s.Interface}
			f.sns.SendMessage(f.Name, m)
		}
		f.sns.CloseTopic(f.Name)
	default:
		return errors.Errorf("unsupported filesystem task %q", f.Name)
	}
	f.signalDoneTask()

	return nil
}

func describeInterface(iface string) string {
	if iface == "" {
		return "kernel routing"
	}
	return iface
}

func plural(n int, one string, many string) string {
	if n == 1 {
		return one
	}
	return many
}

func (f *Filesystem) signalDoneTask() {
	if f.signalDone != nil {
		f.signalDone <- true
	}
}

func (f *Filesystem) waitForTask() {
	if f.waitForSignal != nil {
		<-f.waitForSignal
	}
}

func (f *Filesystem) New(task api.Task, sns *sns.SNS, creds credsmanager.Credentials) abstract.Executor {
	return &Filesystem{
		Type:          task.Type,
		Name:          task.Name,
		Source:        task.Source,
		waitFor:       task.WaitFor,
		Concurrency:   task.Concurrency,
		output:        make([]model.Output, 0),
		isActive:      task.Active,
		isCacheActive: task.UseCache,
		sns:           sns,
	}
}

func (f *Filesystem) GetConcurrency() int {
	return f.Concurrency
}

func (f *Filesystem) SetDoneSignal(signalDone chan bool) {
	f.signalDone = signalDone
}

func (f *Filesystem) SetWaitForSignal(waitForSignal chan bool) {
	f.waitForSignal = waitForSignal
}

func (f *Filesystem) GetWaitForSignal() chan bool {
	return f.waitForSignal
}

func (f *Filesystem) GetDoneSignal() chan bool {
	return f.signalDone
}

func (f *Filesystem) GetWaitFor() string {
	return f.waitFor
}

func (f *Filesystem) Output() []model.Output {
	return f.output
}

func (f *Filesystem) GetType() api.TaskType {
	return f.Type
}

func (f *Filesystem) GetSource() string {
	return f.Source
}

func (f *Filesystem) HasSource() bool {
	if f.Source != "" {
		return true
	}
	return false
}

func (f *Filesystem) GetName() string {
	return f.Name
}

func (f *Filesystem) unmarshal(in interface{}) (*Task, error) {
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

func (f *Filesystem) SetConsumer(c chan model.Message) {
	f.consumer = c
}

func (f *Filesystem) IsActive() bool {
	return f.isActive
}
