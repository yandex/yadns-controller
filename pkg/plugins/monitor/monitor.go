package monitor

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/slayer1366/yadns-controller/pkg/internal/config"
	"github.com/slayer1366/yadns-controller/pkg/plugins"
)

// check function to add in monitoring chain
type CheckFunction func(ctx context.Context, m *TMonitorPlugin) (*Check, error)

type CheckConfig struct {
	ID string `json:"id"`
	F  CheckFunction
}

// A check implements juggler check and some monitoring metrics
// used to send them into graphite collector?
type Check struct {
	ID    string `json:"id"`
	Class string `json:"class"`

	// timestamp and TTL
	Timestamp time.Time `json:"timestamp"`
	TTL       float64   `json:"ttl"`

	Code    int    `json:"code"`
	Message string `json:"message"`
}

func NewCheck(check *Check) *Check {
	var c Check
	c.ID = check.ID
	c.Class = check.Class
	c.Timestamp = check.Timestamp

	c.TTL = check.TTL
	c.Code = check.Code
	c.Message = check.Message
	return &c
}

const (
	// default timestamp format print
	DefaultTimeFormat = "2006-01-02 15:04:05.000000"
)

func (c *Check) Age() float64 {
	return time.Since(c.Timestamp).Seconds()
}

func (c *Check) String() string {
	t0 := time.Now()
	age := t0.Sub(c.Timestamp).Seconds()

	var out []string

	out = append(out, fmt.Sprintf("id:'%s'", c.ID))
	out = append(out, fmt.Sprintf("timestamp:'%s'",
		c.Timestamp.Format(DefaultTimeFormat)))
	out = append(out, fmt.Sprintf("ts:'%d'", c.Timestamp.UnixNano()))
	out = append(out, fmt.Sprintf("ttl:'%2.2f'", c.TTL))
	out = append(out, fmt.Sprintf("age:'%2.2f'", age))
	out = append(out, fmt.Sprintf("code:'%s'", MonitorCodeString(c.Code)))
	out = append(out, fmt.Sprintf("message:'%s'", c.Message))

	return strings.Join(out, ",")
}

func (c *Check) AsJSON() ([]byte, error) {
	return json.MarshalIndent(c, "", "  ")
}

func (c *Check) CodeString() string {
	return MonitorCodeString(c.Code)
}

func (c *Check) Color() int {
	colors := map[int]int{
		Ok:   config.ColorGreen,
		Warn: config.ColorYellow,
		Crit: config.ColorRed,
	}
	if _, ok := colors[c.Code]; ok {
		return colors[c.Code]
	}
	return config.ColorWhite
}

type MonitorJob struct {
	// check to run as job
	check CheckConfig
}

const (
	// default TTL value for check (if none is
	// set) in seconds (in external monitoring
	// juggler configuration)
	DefaultTTL = 120

	// garbage collector default TTL
	DefaultGarbageTTL = 1200

	// default TTL to clean garbage collector
	// OK, Warning and Critical constants
	Ok   = 0
	Warn = 1
	Crit = 2
)

var states = map[int]string{
	Ok:   "OK",
	Warn: "WARN",
	Crit: "CRIT",
}

func MonitorCodeString(code int) string {
	if _, ok := states[code]; !ok {
		return "UNKNOWN"
	}
	return states[code]
}

func (j *MonitorJob) execute(ctx context.Context, index int,
	g *config.TGlobal, m *TMonitorPlugin) MonitorResult {

	id := "(monitor) (job)"

	t0 := time.Now()
	var result MonitorResult
	result.job = j
	result.ID = index

	// running function and check the result
	check, err := j.check.F(ctx, m)
	if err != nil {
		result.err = err
		return result
	}

	if check == nil {
		result.err = fmt.Errorf("no check received")
		return result
	}

	// setting some check parameters and push it
	check.Timestamp = time.Now()
	if check.TTL == 0 {
		check.TTL = DefaultTTL
	}

	// pushing check result and executing garbage
	// collecting methods
	j.Push(g, m, check)

	result.processed = time.Since(t0).Milliseconds()

	g.L.Debugf("%s worker:'%d' check:'%s' as:'%s' executed job in '%d' ms",
		id, index, j.check.ID, check, result.processed)

	return result
}

func (j *MonitorJob) Push(g *config.TGlobal, m *TMonitorPlugin, check *Check) {
	id := "(monitor) (job) (push)"

	g.L.Debugf("%s pushing check:'%s'", id, check.String())

	t := check.Timestamp.UnixNano()

	w := m.worker
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if _, ok := w.checks[check.ID]; !ok {
		// no check ID map found creating new one
		w.checks[check.ID] = make(map[int64]*Check)
	}

	// check ID found, check object could be
	// set as timestamp entry
	w.checks[check.ID][t] = check
	w.refs[check.ID] = t

	// cleaning metrics as garbage collector
	j.GarbageCollector(g, m, DefaultGarbageTTL)
}

// gabage collector is execured under mutex
// set in push method
func (j *MonitorJob) GarbageCollector(g *config.TGlobal, m *TMonitorPlugin, ttl int64) {
	id := "(monitor) (garbage)"

	var outdated []int64

	t0 := time.Now()

	w := m.worker
	count := 0

	for k, s := range w.checks {
		for t, v := range s {
			count++
			age := t0.Sub(v.Timestamp).Seconds()
			if age > float64(ttl) {
				g.L.Debugf("%s id:'%s', ts:'%d', outdated: age:'%2.6f' seconds",
					id, k, t, age)
				outdated = append(outdated, t)
			}
		}
		for i, t := range outdated {
			delete(s, t)
			g.L.Debugf("%s [%d]/[%d]/[%d]: purge id:'%s' ts: %d",
				id, i+1, len(outdated), count, k, t)
		}
	}

	g.L.Debugf("%s garbage checks:'%d' entries:'%d' removed:'%d' w.r.t ttl:'%d'",
		id, len(w.checks), count, len(outdated), ttl)
}

type MonitorResult struct {
	ID int

	// job executed
	job *MonitorJob

	// processed in milliseconds
	processed int64

	// exucution error
	err error
}

// A Monitor Pool is a pooler for monitoring jobs
// we have at least N workers for monitoring (could
// be set in configuration)

const (
	// default number of workers in monitoring pool
	DefaultMonitorWorkers = 8
)

type MonitorPool struct {
	g *config.TGlobal

	// referece to monitor
	m *TMonitorPlugin

	// number of workers to run
	workers int

	// a channel of jobs supplied
	jobs chan MonitorJob

	// a channel of results done
	results chan MonitorResult
}

type MonitorWorker struct {
	g *config.TGlobal

	// checking configs from other plugins
	config map[string]CheckConfig

	mutex *sync.Mutex

	// new version of checks map without
	// sync.Map objects and last check timestamp
	// pointers map
	checks map[string]map[int64]*Check

	// references for last check value
	refs map[string]int64

	// a pool of workers to run
	pool *MonitorPool
}

func NewMonitorPool(g *config.TGlobal, m *TMonitorPlugin, workers int) *MonitorPool {
	var p MonitorPool

	p.g = g
	p.m = m
	p.workers = workers
	p.jobs = make(chan MonitorJob, workers)
	p.results = make(chan MonitorResult, workers)

	return &p
}

func (p *MonitorPool) Worker(ctx context.Context, index int, wg *sync.WaitGroup,
	jobs <-chan MonitorJob, results chan<- MonitorResult) {

	id := "(monitor) (pool)"
	defer wg.Done()

	for {
		select {
		case job, ok := <-jobs:
			if !ok {
				// finishing worker if we have some problems
				// with input channel
				return
			}
			results <- job.execute(ctx, index, p.g, p.m)

		case <-ctx.Done():
			p.g.L.Debugf("%s worker stopped", id)
			results <- MonitorResult{err: ctx.Err()}
			return
		}
	}
}

func (p *MonitorPool) PushJob(check CheckConfig) {
	var job MonitorJob
	job.check = check

	// pushing job into jobs
	// monitoring pool
	p.jobs <- job
}

func (p *MonitorPool) RunWorkers(ctx context.Context) error {
	var err error
	id := "(monitor) (workers)"

	var wg sync.WaitGroup
	for i := 0; i < p.workers; i++ {
		// starting workers forming pool
		// they will be run until the end
		wg.Add(1)
		go p.Worker(ctx, i, &wg, p.jobs, p.results)
	}

	// waiting all workers running
	wg.Wait()

	// closing all channels (done?)
	close(p.results)

	p.g.L.Debugf("%s worker pool stopped", id)

	return err
}

func (p *MonitorPool) Results() <-chan MonitorResult {
	return p.results
}

func (p *MonitorPool) Run(ctx context.Context) error {
	id := "(monitor) (pool)"

	p.g.L.Debugf("%s starting workers:'%d' in pool", id, p.workers)

	w, ctx := errgroup.WithContext(ctx)
	w.Go(func() error {
		// starting monitoring jobs workers pool
		return p.RunWorkers(ctx)
	})

	// waiting results
	w.Go(func() error {
		var err error
		for {
			select {
			case r, ok := <-p.Results():
				if !ok {
					// something wrong on channel
					p.g.L.Errorf("%s job channel failed", id)
					break
				}

				if r.err != nil {
					if r.job != nil {
						// some error on job
						p.g.L.Errorf("%s job id:'%s' failed, err:'%s'", id, r.job.check.ID, r.err)
						continue
					}
					p.g.L.Errorf("%s job channel, err:'%s'", id, r.err)
					break
				}

				p.g.L.Debugf("%s result on worker:'%d' job id:'%s' processed OK, time:'%d'",
					id, r.ID, r.job.check.ID, r.processed)
			case <-ctx.Done():
				p.g.L.Debugf("%s pool is stopped", id)
				return err

			}
			p.g.L.Debugf("%s waiting result select stopped", id)
		}
	})

	return w.Wait()
}

func NewMonitorWorker(g *config.TGlobal, m *TMonitorPlugin) (*MonitorWorker, error) {
	var j MonitorWorker
	j.g = g

	j.mutex = &sync.Mutex{}

	j.checks = make(map[string]map[int64]*Check)
	j.refs = make(map[string]int64)
	j.config = make(map[string]CheckConfig)

	// T.B.D. adding configuration option for workers
	workers := DefaultMonitorWorkers

	j.pool = NewMonitorPool(g, m, workers)

	return &j, nil
}

func (j *MonitorWorker) ProcessingChecks(ctx context.Context) error {
	id := "(monitor) (worker)"

	// T.B.D. each time seconds we push check calculations
	// w.r.t pool of workers that run checks, with randomization?

	// T.B.D. timer
	timer := time.NewTicker(10 * time.Second)
	defer timer.Stop()

	// T.B.D. each check could be run on its own schedule
	for {
		select {
		case <-timer.C:
			// time to push all checks into the pool of workers
			// do we need here random time sleep?
			j.g.L.Debugf("%s start processing monitoring checks", id)

			// scanning all configurations and push them into pool
			for _, check := range j.config {
				j.pool.PushJob(check)
			}

		case <-ctx.Done():
			j.g.L.Debugf("%s checks processors stopped", id)
			return ctx.Err()
		}
	}
}

func (t *TMonitorPlugin) AddConfig(c CheckConfig) {
	t.worker.mutex.Lock()
	defer t.worker.mutex.Unlock()

	// setting config check
	t.worker.config[c.ID] = c
}

func (t *TMonitorPlugin) GetCheckIDs() []string {
	w := t.worker
	w.mutex.Lock()
	defer w.mutex.Unlock()

	var out []string
	for k := range w.checks {
		out = append(out, k)
	}
	return out
}

func (t *TMonitorPlugin) GetCheck(tid string) (*Check, error) {
	id := "(monitor) (check)"

	w := t.worker
	w.mutex.Lock()
	defer w.mutex.Unlock()

	if v, ok := w.refs[tid]; ok {
		if _, ok := w.checks[tid]; ok {
			if w, ok := w.checks[tid][v]; ok {
				t.G().L.Debugf("%s check id:'%s' t:'%d' check'%s'", id,
					tid, v, w.String())
				return w, nil
			}
		}
	}
	return nil, fmt.Errorf("check not found")
}

type HistoryCheck struct {
	// statistics for all OK, WARN and CERT
	stats map[int]int
}

func NewHistoryCheck() *HistoryCheck {
	var h HistoryCheck
	h.stats = make(map[int]int)
	for k := range states {
		h.stats[k] = 0
	}
	return &h
}

const (
	// empty string if no history found
	DefaultEmptyHistory = "empty"

	// default max history
	DefaultHistory = 5
)

func (h *HistoryCheck) String() string {
	count := 0
	for k := range states {
		count += h.stats[k]
	}
	if count == 0 {
		// nothing is found
		return DefaultEmptyHistory
	}

	var out []string
	for k, v := range states {
		if h.stats[k] == 0 {
			continue
		}
		w := 100 * float64(h.stats[k]) / float64(count)
		p := fmt.Sprintf("%s:%2.2f%%", v, w)
		out = append(out, p)
	}
	return fmt.Sprintf("count:'%d' as %s", count,
		strings.Join(out, " "))
}

// we getting the last check and calculating
// past N counters for OK, CRIT and WARN
func (t *TMonitorPlugin) GetHistory(tid string) (*HistoryCheck, error) {
	id := "(monitor) (history)"

	w := t.worker
	w.mutex.Lock()
	defer w.mutex.Unlock()

	max := DefaultHistory
	if s, ok := w.checks[tid]; ok {
		h := NewHistoryCheck()

		var keys []int64
		for t := range s {
			keys = append(keys, t)
		}
		sort.Slice(keys, func(i, j int) bool { return keys[i] > keys[j] })

		for i, k := range keys {
			a := s[k]
			h.stats[a.Code]++

			if i < max {
				// logging some data for debug
				t.G().L.Debugf("%s [%d]/[%d]: key:'%d' check:'%s' history:'%d'",
					id, i, len(keys), k, a.String(), h.stats[a.Code])
			}
		}

		return h, nil
	}

	return nil, fmt.Errorf("check not found")
}

func (t *TMonitorPlugin) Run(ctx context.Context, overrides *plugins.OverrideOptions) error {
	id := "(monitor) (worker)"

	w, ctx := errgroup.WithContext(ctx)

	t.G().L.Debugf("%s starting worker", id)

	// starting monitoring workers jobs
	w.Go(func() error {
		// starting monitoring jobs workers pool
		return t.worker.pool.Run(ctx)
	})

	// metrics should done metrics push and metrics
	// garbage collecting
	w.Go(func() error {
		// some type of metrics should be calculated each
		// second, e.g. calculating rps
		return t.worker.ProcessingChecks(ctx)
	})

	t.G().L.Debugf("%s monitor plugin stopped", id)

	return w.Wait()
}
