package receiver

import (
	"context"
	"encoding/json"
	"fmt"
	"runtime"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/yandex/yadns-controller/pkg/plugins/offloader"
)

const (
	// default collector monitor intervals
	// for different types of collecting metrics:
	// merics, histograms
	DefaultMonitorMetricsInterval = 10

	// default watcher interval
	DefaultWatcherInterval = 17

	// if monitor should zero metrics after
	// fetching them from bpf maps
	DefaultMonitorZero = false

	// historgrams need some more time to
	// gather statistics
	DefaultMoniorHistogramsInterval = 60 * time.Second

	// current number of runtime goroutine
	MetricsRuntimeNumGoroutine = "runtime-goroutine"

	MeticsRuntimeMemHeapAlloc    = "runtime-mem-heapalloc"
	MeticsRuntimeMemTotalAlloc   = "runtime-mem-totalalloc"
	MeticsRuntimeMemSys          = "runtime-mem-sys"
	MeticsRuntimeMemLookups      = "runtime-mem-lookups"
	MeticsRuntimeMemMallocs      = "runtime-mem-mallocs"
	MeticsRuntimeMemFrees        = "runtime-mem-frees"
	MeticsRuntimeMemHeapSys      = "runtime-mem-heapsys"
	MeticsRuntimeMemHeapIdle     = "runtime-mem-heapidle"
	MeticsRuntimeMemHeapInuse    = "runtime-mem-heapinuse"
	MeticsRuntimeMemHeapReleased = "runtime-mem-heapreleased"
	MeticsRuntimeMemHeapObjects  = "runtime-mem-heapobjects"
	MeticsRuntimeMemStackInuse   = "runtime-mem-stackinuse"
	MeticsRuntimeMemStackSys     = "runtime-mem-stacksys"
	MeticsRuntimeMemMSpanInuse   = "runtime-mem-mspaninuse"
	MeticsRuntimeMemMSpanSys     = "runtime-mem-mspansys"
	MeticsRuntimeMemMCacheInuse  = "runtime-mem-mcacheinuse"
	MeticsRuntimeMemMCacheSys    = "runtime-mem-mcachesys"
	MeticsRuntimeMemBuckHashSys  = "runtime-mem-buckhashsys"
	MeticsRuntimeMemPauseTotalNs = "runtime-mem-pause-totalns"
	MeticsRuntimeMemNumGC        = "runtime-mem-numgc"
	MeticsRuntimeMemNumForcedGC  = "runtime-mem-numforcedgc"

	// a list of metrics gathering from different parts of program:
	// cooker, recevier, notifier

	MetricsCookerCookTime = "cooker-cooktime"

	// verify on cook stage
	MetricsCookerVerifyTotal       = "cooker-verifytotal"
	MetricsCookerVerifyVerified    = "cooker-verifyverified"
	MetricsCookerVerifyMissed      = "cooker-verifymissed"
	MetricsCookerVerifyDifferOnTTL = "cooker-differonttl"
	MetricsCookerVerifyDifferOnIP  = "cooker-differonip"
	MetricsCookerVerifyUnexpected  = "cooker-unexpected"

	MetricsVerifyTotal       = "verifier-verifytotal"
	MetricsVerifyVerified    = "verifier-verifyverified"
	MetricsVerifyMissed      = "verifier-verifymissed"
	MetricsVerifyDifferOnTTL = "verifier-differonttl"
	MetricsVerifyDifferOnIP  = "verifier-differonip"
	MetricsVerifyUnexpected  = "verifier-unexpected"

	// sync map on cook stage
	MetricsCookerSyncCreated = "cooker-synccreated"
	MetricsCookerSyncRemoved = "cooker-syncremoved"

	// age for snapshots blobs files zones (configured)
	MetricsCookerSnapshotsAgeMin = "cooker-snapshotsage-min"
	MetricsCookerSnapshotsAgeMax = "cooker-snapshotsage-max"
	MetricsCookerSnapshotsAgeAvg = "cooker-snapshotsage-avg"
	MetricsCookerSnapshotsCount  = "cooker-snapshots-count"

	// time zone to be received
	MetricsReceiverZoneTime = "receiver-zonetime"

	// bpf metrics
	MetricsBpfPacketsRX    = "bpf-packetsrx"
	MetricsBpfPacketsTX    = "bpf-packetstx"
	MetricsBpfPacketsPass  = "bpf-packetspass"
	MetricsBpfPacketsError = "bpf-packetserror"

	MetricsBpfTimeMin = "bpf-timemin"
	MetricsBpfTimeMax = "bpf-timemax"
	MetricsBpfTimeAvg = "bpf-timeavg"
	MetricsBpfTimeCnt = "bpf-timecnt"

	BpfPacketsRX    = 0
	BpfPacketsTX    = 1
	BpfPacketsPass  = 2
	BpfPacketsError = 3

	BpfTimeMin = 4
	BpfTimeMax = 5
	BpfTimeSum = 6
	BpfTimeCnt = 7

	MetricsBpfTimeHistogram = "bpf-timehistogram"
)

// monitor is responsible for collecting metrics,
// calculatings some monitored properties of application
// and processing, exporing metrics
// to api worker
type WatcherWorker struct {
	p *TReceiverPlugin

	metrics map[string]map[int64][]int64

	lock sync.Mutex
}

func NewWatcherWorker(p *TReceiverPlugin) *WatcherWorker {
	var m WatcherWorker
	m.p = p
	m.metrics = make(map[string]map[int64][]int64)
	return &m
}

func (m *WatcherWorker) GetLastMetrics() map[string][]int64 {
	m.lock.Lock()
	defer m.lock.Unlock()

	out := make(map[string][]int64)
	for mid, times := range m.metrics {
		var t []int64
		for k := range times {
			t = append(t, k)
		}
		sort.Slice(t, func(i, j int) bool { return t[i] > t[j] })

		if len(t) > 0 {
			out[mid] = times[t[0]]
		}
	}

	return out
}

func (m *WatcherWorker) GetLastMetric(id string) []int64 {
	m.lock.Lock()
	defer m.lock.Unlock()

	var out []int64
	if _, ok := m.metrics[id]; !ok {
		return out
	}

	times := m.metrics[id]

	var t []int64
	for k := range times {
		t = append(t, k)
	}
	sort.Slice(t, func(i, j int) bool { return t[i] > t[j] })

	for _, q := range t {
		v := times[q]
		out = append(out, v[0])
	}

	return out
}

func (m *WatcherWorker) AsJSON() ([]byte, error) {
	return json.MarshalIndent(m.GetLastMetrics(), "", "  ")
}

func (m *WatcherWorker) PushMetric(id string, values []int64) {

	m.lock.Lock()
	defer m.lock.Unlock()

	if _, ok := m.metrics[id]; !ok {
		m.metrics[id] = make(map[int64][]int64)
	}
	now := time.Now().UnixNano()
	m.metrics[id][now] = values
}

func (m *WatcherWorker) PushMetrics(metrics map[string]int64) {
	for metrics, v := range metrics {
		m.PushMetric(metrics, []int64{v})
	}
}

func (m *WatcherWorker) PushHistograms(metrics map[string][]int64) {
	for metrics, v := range metrics {
		m.PushMetric(metrics, v)
	}
}

func (m *WatcherWorker) PushIntMetric(id string, metric int64) {
	m.PushMetric(id, []int64{metric})
}

func (m *WatcherWorker) PushFloatMetric(id string, metric float64) {
	m.PushMetric(id, []int64{int64(metric)})
}

func (m *WatcherWorker) DumpMetrics(n int) {
	id := "(monitor) (metrics) (dump)"

	m.lock.Lock()
	defer m.lock.Unlock()

	now := time.Now().UnixNano()
	for mid, times := range m.metrics {
		var t []int64
		for k := range times {
			t = append(t, k)
		}
		sort.Slice(t, func(i, j int) bool { return t[i] > t[j] })
		l := n
		if len(t) < l {
			l = len(t)
		}
		for i := 0; i < l; i++ {
			values := times[t[i]]
			m.p.G().L.Debugf("%s [%d]/[%d] '%d' t:'%d' age:'%d' %d %s values:'%+v'",
				id, i, l, len(t), t[i], now-t[i],
				len(values), mid, values)
		}
	}
}

func (m *WatcherWorker) GarbageMetrics(n int) {
	id := "(monitor) (metrics) (garbage)"
	now := time.Now().UnixNano()

	m.lock.Lock()
	defer m.lock.Unlock()

	removed := make(map[string][]int64)

	for mid, times := range m.metrics {
		var t []int64
		for k := range times {
			t = append(t, k)
		}
		sort.Slice(t, func(i, j int) bool { return t[i] > t[j] })
		for i := n; i < len(t); i++ {
			removed[mid] = append(removed[mid], t[i])
		}
	}

	for mid, tid := range removed {

		data := m.metrics[mid]
		for _, t := range tid {
			delete(data, t)

			m.p.G().L.Debugf("%s REMOVE '%d' '%d' t:'%d' age:'%d' '%s'",
				id, len(tid), len(data), t, now-t, mid)
		}

		m.metrics[mid] = data
	}

}

const (
	CollectorBpfMetrics     = 1001
	CollectorBpfHistograms  = 1002
	CollectorRuntimeMetrics = 1003
	CollectorGarbage        = 1004
	CollectorDumper         = 1005
	CollectorUnknown        = 0
)

func CollectorTypeToString(mode int) string {
	names := map[int]string{
		CollectorBpfMetrics:     "bpf+metrics",
		CollectorRuntimeMetrics: "runtime+metrics",
		CollectorBpfHistograms:  "bpf+histograms",
		CollectorGarbage:        "garbage-collector",
		CollectorDumper:         "dumper",
		CollectorUnknown:        "unknown",
	}
	if _, ok := names[mode]; !ok {
		return names[CollectorUnknown]
	}
	return names[mode]
}

func (m *WatcherWorker) Run(ctx context.Context) error {
	id := "(monitor) (worker)"
	var wg sync.WaitGroup

	collector := m.p.L().Monitor.Collector
	if collector.Enabled {

		types := []int{
			CollectorRuntimeMetrics,
			CollectorGarbage,
			CollectorDumper,
			CollectorBpfMetrics,
			CollectorBpfHistograms,
		}

		m.p.G().L.Debugf("%s running %d monitor workers", id, len(types))

		for _, t := range types {
			wg.Add(1)
			// we have to periodically collect metrics
			// from different sources and push them into
			// metrics map of slices
			go func(t int) {
				err := m.TickCollector(ctx, t, &wg)
				if err != nil {
					m.p.G().L.Errorf("%s error on collector tick, err:'%s'", id, err)
				}
			}(t)
		}
	}

	watcher := m.p.L().Monitor.Watcher
	if watcher.Enabled {
		wg.Add(1)

		go func() {
			m.p.G().L.Debugf("%s starting watcher", id)
			defer m.p.G().L.Debugf("%s watcher is stopped", id)

			err := m.TickWatcher(ctx, &wg)
			if err != nil {
				m.p.G().L.Errorf("%s error on watcher tick, err:'%s'", id, err)
			}
		}()
	}

	wg.Wait()
	return nil
}

const (
	ActionON  = "on"
	ActionOFF = "off"
)

type TAction struct {
	stage   string
	rule    TRule
	level   string
	w       int64
	counter int
}

func (m *WatcherWorker) GetXdpService() *offloader.TXdpService {
	plugin := m.p.P().GetPlugin(offloader.NamePlugin)
	offloader := plugin.(*offloader.TOffloaderPlugin)
	return offloader.GetXdpService()
}

func (m *WatcherWorker) CheckRules() error {
	id := "(watcher)"

	actions := make(map[string]TAction)

	watcher := m.p.L().Monitor.Watcher

	// getting current values
	runtime, err := m.GetXdpService().GetRuntimeConfigMap()
	if err != nil {
		m.p.G().L.Errorf("%s error getting runtime configuration map, err:'%s'", id, err)
		return err
	}

	dryrun := runtime[offloader.JericoRuntimeConfigDryrun]

	for rid, rule := range watcher.Rules {

		// getting current value of id and compare with
		// higher and lower ranges, also we need receive
		// current state of each action we should apply
		values := m.GetLastMetric(rid)
		if len(values) == 0 {
			// no any value of rule to check
			continue
		}

		w := values[0]
		stage := ""
		level := ""
		if w > int64(rule.Higher) {
			stage = ActionON
			level = "HIGH"
		}

		if w < int64(rule.Lower) {
			stage = ActionOFF
			level = "LOW"
		}

		if stage == ActionON || stage == ActionOFF {

			m.p.G().L.Debugf("%s (CHECK) id:'%s' higher:'%d' lower:'%d' vs '%d' (last of '%d') '%s' as '['%s'] to '%s' dryrun:'%d'",
				id, rid, rule.Higher, rule.Lower, w, len(values),
				level, strings.Join(rule.Actions, ","),
				strings.ToUpper(stage), dryrun)

			switch rid {
			case MetricsCookerSnapshotsAgeMax:
				if ((stage == ActionON) && (dryrun == 1)) ||
					((stage == ActionOFF) && (dryrun == 0)) {
					// no changes at all
					continue
				}
			}

			action := TAction{stage: stage, rule: rule, w: w, level: level, counter: len(values)}
			actions[rid] = action
			continue
		}

		// waiting for thresholds
	}

	// applying actions
	for rid, action := range actions {
		switch rid {
		case MetricsCookerSnapshotsAgeMax:
			dryrun := false
			if action.stage == ActionON {
				dryrun = true
			}

			err := m.GetXdpService().SetDryrun(dryrun)
			if err != nil {
				m.p.G().L.Errorf("%s error setting dryrun as value:'%t'", id, dryrun)
				continue
			}

			rule := action.rule
			m.p.G().L.Debugf("%s (APPLY) id:'%s' higher:'%d' lower:'%d' vs '%d' (last of '%d') '%s' as '['%s'] to '%s' dryrun:'%t'",
				id, rid, rule.Higher, rule.Lower, action.w, action.counter,
				action.level, strings.Join(rule.Actions, ","),
				strings.ToUpper(action.stage), dryrun)

		}
	}

	return nil
}

func (m *WatcherWorker) TickWatcher(ctx context.Context,
	wg *sync.WaitGroup) error {
	id := "(watcher)"

	defer wg.Done()

	interval := DefaultWatcherInterval
	watcher := m.p.L().Monitor.Watcher

	if watcher.Interval > 0 {
		interval = watcher.Interval
	}

	counter := 0
	timer := time.NewTicker(time.Duration(interval) * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			counter++

			err := m.CheckRules()
			if err != nil {
				m.p.G().L.Errorf("%s error checking rules", id)
				continue
			}

			// T.B.D.

		case <-ctx.Done():
			m.p.G().L.Debugf("%s context stop on watcher", id)
			return ctx.Err()
		}
	}
}

func (m *WatcherWorker) TickCollector(ctx context.Context,
	t int, wg *sync.WaitGroup) error {

	defer wg.Done()

	id := fmt.Sprintf("(monitor) (collector) (%s)",
		CollectorTypeToString(t))

	interval := DefaultMonitorMetricsInterval
	zero := DefaultMonitorZero

	collector := m.p.L().Monitor.Collector

	switch t {
	case CollectorBpfMetrics:
		interval = collector.Bpf.Intervals.Metrics
		zero = collector.Bpf.Intervals.Zero
	case CollectorBpfHistograms:
		interval = collector.Bpf.Intervals.Histograms
		zero = collector.Bpf.Intervals.Zero
	case CollectorRuntimeMetrics:
		interval = collector.Runtime.Intervals.Metrics
	case CollectorGarbage:
		interval = collector.GarbageCollector.Interval
	case CollectorDumper:
		interval = collector.DumpInterval
	}

	counter := 0
	timer := time.NewTicker(time.Duration(interval) * time.Second)
	defer timer.Stop()

	m.p.G().L.Debugf("%s started monitor worker", id)

	for {
		select {
		case <-timer.C:
			counter++

			if collector.Verbose {
				m.p.G().L.Debugf("%s [%d] time to collect metrics", id, counter)
			}

			var metrics map[string]int64
			var err error

			switch t {
			case CollectorBpfMetrics, CollectorBpfHistograms:
				var histograms map[string][]int64
				metrics, histograms, err = m.CollectBpfMetrics(t, zero)
				if err != nil {
					m.p.G().L.Errorf("%s error collecting bpf metrics, err:'%s'", id, err)
					continue
				}

				if t == CollectorBpfHistograms {
					m.PushHistograms(histograms)
					continue
				}

			case CollectorRuntimeMetrics:
				metrics, err = m.CollectRuntimeMetrics()
				if err != nil {
					m.p.G().L.Errorf("%s error collecting runtime metrics, err:'%s'", id, err)
					continue
				}

			case CollectorGarbage:
				// garabge collecting metrics in map, please note
				// that we need mutex lock in the end
				keep := collector.GarbageCollector.Keep
				m.GarbageMetrics(keep)

			case CollectorDumper:
				// dump metrics every defined interval of seconds
				m.DumpMetrics(1)

			default:
				continue
			}

			if collector.Verbose {
				m.p.G().L.Debugf("%s [%d] recevied %d metrics", id, counter, len(metrics))
				for mid, v := range metrics {
					m.p.G().L.Debugf("%s [%d] m:'%s' '%d'", id, counter, mid, v)
				}
			}

			// push metrics in the map
			m.PushMetrics(metrics)

		case <-ctx.Done():
			m.p.G().L.Debugf("%s context stop on worker", id)
			return ctx.Err()
		}
	}
}

func (m *WatcherWorker) CollectRuntimeMetrics() (map[string]int64, error) {
	metrics := make(map[string]int64)

	// getting number of goroutines run
	name := MetricsRuntimeNumGoroutine
	metrics[name] = int64(runtime.NumGoroutine())

	// reading memory statistics
	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	metrics[MeticsRuntimeMemHeapAlloc] = int64(mem.HeapAlloc)
	metrics[MeticsRuntimeMemTotalAlloc] = int64(mem.TotalAlloc)
	metrics[MeticsRuntimeMemSys] = int64(mem.Sys)
	metrics[MeticsRuntimeMemLookups] = int64(mem.Lookups)
	metrics[MeticsRuntimeMemMallocs] = int64(mem.Mallocs)
	metrics[MeticsRuntimeMemFrees] = int64(mem.Frees)
	metrics[MeticsRuntimeMemHeapSys] = int64(mem.HeapSys)
	metrics[MeticsRuntimeMemHeapIdle] = int64(mem.HeapIdle)
	metrics[MeticsRuntimeMemHeapInuse] = int64(mem.HeapInuse)
	metrics[MeticsRuntimeMemHeapReleased] = int64(mem.HeapReleased)
	metrics[MeticsRuntimeMemHeapObjects] = int64(mem.HeapObjects)
	metrics[MeticsRuntimeMemStackInuse] = int64(mem.StackInuse)
	metrics[MeticsRuntimeMemStackSys] = int64(mem.StackSys)
	metrics[MeticsRuntimeMemMSpanInuse] = int64(mem.MSpanInuse)
	metrics[MeticsRuntimeMemMSpanSys] = int64(mem.MSpanSys)
	metrics[MeticsRuntimeMemMCacheInuse] = int64(mem.MCacheInuse)
	metrics[MeticsRuntimeMemMCacheSys] = int64(mem.MCacheSys)
	metrics[MeticsRuntimeMemBuckHashSys] = int64(mem.BuckHashSys)
	metrics[MeticsRuntimeMemPauseTotalNs] = int64(mem.PauseTotalNs)
	metrics[MeticsRuntimeMemNumGC] = int64(mem.NumGC)
	metrics[MeticsRuntimeMemNumForcedGC] = int64(mem.NumForcedGC)

	// need calculate some other metrics (age of filers w.r.t
	// configuration)
	zones := &ZonesState{p: m.p}

	ages, err := zones.GetSnapshotsFilesState()
	if err == nil {
		metrics[MetricsCookerSnapshotsAgeMin] = ages.Min
		metrics[MetricsCookerSnapshotsAgeMax] = ages.Max
		metrics[MetricsCookerSnapshotsAgeAvg] = ages.Avg
		metrics[MetricsCookerSnapshotsCount] = ages.Count
	}

	return metrics, err
}

func (m *WatcherWorker) CollectBpfMetrics(t int, zero bool) (map[string]int64, map[string][]int64, error) {
	id := "(monitor) (bpf) (metrics)"

	metrics := make(map[string]int64)

	var bpfmetrics offloader.BpfMetrics

	switch t {
	case CollectorBpfMetrics:
		bpfmetrics = &offloader.PerfMetrics{PinPath: m.p.L().PinPath}
	case CollectorBpfHistograms:
		bpfmetrics = &offloader.PerfHistorgram{PinPath: m.p.L().PinPath}
	}

	err := bpfmetrics.LoadPinnedMap()
	if err != nil {
		m.p.G().L.Errorf("%s error loading pinned map:'%s', err:'%s'",
			id, bpfmetrics.MapName(), err)
		return metrics, nil, err
	}
	defer bpfmetrics.Close()

	values, err := bpfmetrics.Entries()
	if err != nil {
		m.p.G().L.Errorf("%s error getting bpf values from map:'%s', err:'%s'",
			id, bpfmetrics.MapName(), err)
		return metrics, nil, err
	}

	histograms := make(map[string][]int64)

	switch t {
	case CollectorBpfMetrics:

		// as we have interval metrics we need norm them w.r.t
		// metics interval (in seconds)

		collector := m.p.L().Monitor.Collector
		interval := uint64(DefaultMonitorMetricsInterval)
		if collector.Bpf.Intervals.Metrics > 0 {
			interval = uint64(collector.Bpf.Intervals.Metrics)
		}

		metrics[MetricsBpfPacketsRX] = int64(values[BpfPacketsRX] / interval)
		metrics[MetricsBpfPacketsTX] = int64(values[BpfPacketsTX] / interval)
		metrics[MetricsBpfPacketsPass] = int64(values[BpfPacketsPass] / interval)
		metrics[MetricsBpfPacketsError] = int64(values[BpfPacketsError] / interval)

		metrics[MetricsBpfTimeMin] = int64(values[BpfTimeMin])
		metrics[MetricsBpfTimeMax] = int64(values[BpfTimeMax])
		metrics[MetricsBpfTimeCnt] = int64(values[BpfTimeCnt])

		if values[BpfTimeCnt] > 0 {
			metrics[MetricsBpfTimeAvg] = int64(values[BpfTimeSum] / values[BpfTimeCnt])
		}

	case CollectorBpfHistograms:
		name := MetricsBpfTimeHistogram
		for _, v := range values {
			histograms[name] = append(histograms[name], int64(v))
		}
	}

	if zero {
		// clearing all counters as configured
		err := bpfmetrics.ZeroAll()
		if err != nil {
			m.p.G().L.Errorf("%s error zeroing values in pinned map:'%s', err:'%s'",
				id, bpfmetrics.MapName(), err)
			return metrics, nil, err
		}
	}

	return metrics, histograms, nil
}
