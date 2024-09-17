package metrics

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/slayer1366/yadns-controller/pkg/internal/api"
	"github.com/slayer1366/yadns-controller/pkg/internal/config"
	"github.com/slayer1366/yadns-controller/pkg/plugins"
)

const (
	// classes of metrics: rps and times: min/avg/max
	MetricsRPS      = 1
	MetricsRPSPrefx = "rps"

	// times in ms per intervals, percentiles?
	MetricsTimes       = 2
	MetricsTimesPrefix = "times"

	// absolute values stored as counter
	MetricsCounter       = 3
	MetricsCounterPrefix = "counter"

	// delimiter for key
	MetricsDel = "|"

	// default length of vector values
	// in seconds
	DefaultVectorLength = 60

	// default vector show in log
	DefaultVectorLogShow = 10
)

// vector to store last length values of
// some values
type MetricsVector struct {
	values map[string][]float64

	// defined length of array
	length int

	// ref and count pointers in values
	// slice to indicate all pushed values
	// and current ref
	ref   int
	count int
}

func NewMetricsVector(length int) *MetricsVector {
	var v MetricsVector
	v.length = length
	v.values = make(map[string][]float64)
	v.ref = 0
	v.count = 0
	return &v
}

func (v *MetricsVector) PushValue(key string, value float64) {

	if _, ok := v.values[key]; !ok {
		v.values[key] = make([]float64, v.length)
	}

	v.values[key][v.ref] = value
	v.count++
	v.ref++

	if v.ref >= v.length {
		v.ref = 0
	}

	if v.count > v.length {
		v.count = v.length
	}
}

func (v *MetricsVector) AsString(key string, max int) string {
	var out []string

	values := v.GetLastValues(key)
	for i, w := range values {
		if i > max {
			break
		}
		out = append(out, fmt.Sprintf("%2.2f", w))
	}

	return fmt.Sprintf("key:'%s' ['%s'], ref:'%d'", key,
		strings.Join(out, " "), v.ref)
}

func (v *MetricsVector) GetLastValues(key string) []float64 {
	var values []float64
	for j := v.ref - 1; j >= 0; j-- {
		if j < len(v.values[key]) {
			values = append(values, v.values[key][j])
		}
	}

	for j := len(v.values) - 1; j > v.ref; j-- {
		if j < len(v.values[key]) {
			values = append(values, v.values[key][j])
		}
	}

	return values
}

func (v *MetricsVector) GetAvgValue(max int, key string) float64 {

	values := v.GetLastValues(key)

	w := float64(0)
	count := 0
	for j := 0; j < len(values); j++ {
		if j > max {
			break
		}
		count++
		w += values[j]
	}
	if count > 0 {
		return w / float64(count)
	}
	return w
}

type MetricsWorker struct {
	g *config.TGlobal

	// map of raw values to store
	values map[string]map[int64][]float64

	// calculated values and some values around
	prev map[string]float64

	// vector of last values
	vectors map[string]*MetricsVector

	mutex sync.Mutex
}

func NewMetricsWorker(g *config.TGlobal) (*MetricsWorker, error) {

	var j MetricsWorker
	j.g = g

	j.values = make(map[string]map[int64][]float64)
	j.prev = make(map[string]float64)
	j.vectors = make(map[string]*MetricsVector)

	return &j, nil
}

const (
	// default service to use in metrics solomon
	DefaultSolomonService = "dhcp4"

	// default node solmon role
	DefaultSolomonRole = "node"

	// some null strings data to configure monitor
	DefaultNull = ""
)

func MetricToString(metricID int) string {
	values := map[int]string{
		MetricsRPS:     MetricsRPSPrefx,
		MetricsTimes:   MetricsTimesPrefix,
		MetricsCounter: MetricsCounterPrefix,
	}
	if _, ok := values[metricID]; ok {
		return values[metricID]
	}
	return ""
}

func TagsToKey(metricID int, tags []string) string {
	return fmt.Sprintf("%s%s%s", MetricToString(metricID), MetricsDel,
		strings.Join(tags, MetricsDel))
}

func KeyToTags(key string) (int, []string, string, error) {

	name := ""
	tags := strings.Split(key, MetricsDel)

	ids := map[string]int{
		MetricsRPSPrefx:      MetricsRPS,
		MetricsTimesPrefix:   MetricsTimes,
		MetricsCounterPrefix: MetricsCounter,
	}

	if len(tags) == 0 {
		err := fmt.Errorf("incorrect key supplied")
		return 0, tags, name, err
	}

	t := tags[0]
	if _, ok := ids[t]; !ok {
		err := fmt.Errorf("no type metric:'%s' supported", t)
		return 0, tags, name, err
	}

	id := ids[t]
	for _, t := range tags[1:] {
		p := strings.Split(t, "=")
		if len(p) == 2 {
			if p[0] == "name" {
				name = p[1]
			}
		}
	}

	return id, tags[1:], name, nil
}

const (
	// default values for times aggregates
	DefaultTimesAggregate = 10

	// default values to return as last values
	DefaultMonitorLength = 5
)

func (j *MetricsWorker) Push(metricID int,
	tags []string, value float64) {

	j.mutex.Lock()
	defer j.mutex.Unlock()

	key := TagsToKey(metricID, tags)

	interval := float64(DefaultTimesAggregate)

	if _, ok := j.values[key]; !ok {
		j.values[key] = make(map[int64][]float64)
		j.values[key][0] = append(j.values[key][0],
			float64(0))
		interval = 0
	}

	switch metricID {
	case MetricsRPS:
		// just incrementing first element in time and
		// in current vector of time values
		j.values[key][0][0]++

	case MetricsTimes:

		now := float64(time.Now().Unix())
		prev := j.values[key][0][0]

		// times should have some interval to aggregate
		// e.g. minute
		if interval == 0 {
			j.values[key][0][0] = now
			// sum, max and min, and counter index 1, 2, 3
			j.values[key][0] = append(j.values[key][0], value)
			j.values[key][0] = append(j.values[key][0], value)
			j.values[key][0] = append(j.values[key][0], value)
			j.values[key][0] = append(j.values[key][0], float64(1))
			return
		}

		if prev+interval >= now {
			// processing aggregation
			j.values[key][0][1] += value

			if j.values[key][0][2] < value {
				j.values[key][0][2] = value
			}

			if j.values[key][0][3] > value {
				j.values[key][0][3] = value
			}

			j.values[key][0][4]++

			return
		}

		j.values[key][0][0] = now
		j.values[key][0][1] = value
		j.values[key][0][2] = value
		j.values[key][0][3] = value
		j.values[key][0][4] = float64(1)

	case MetricsCounter:
		j.values[key][0][0] = value
	}

}

func (j *MetricsWorker) ProcessingMetrics(ctx context.Context) error {
	id := "(metrics) (worker)"

	// each second should be calculated metrics
	// and store the last N seconds of values vector
	// for each ID
	timer := time.NewTicker(1 * time.Second)
	defer timer.Stop()

	interval := float64(DefaultTimesAggregate)
	for {
		select {
		case <-timer.C:
			// each 1 second got current values and form
			// vectors of values
			count := 0
			for k, v := range j.values {

				class, tags, metric, err := KeyToTags(k)
				if err != nil {
					j.g.L.Errorf("%s error on processing k:'%s', err:'%s'", id, k, err)
					continue
				}

				value := v[0][0]

				// checking if we have previous value, if not setting
				// and we do not have any task to do
				if _, ok := j.prev[k]; !ok {
					j.prev[k] = value
					continue
				}

				delta := float64(0)
				name := "value"

				switch class {
				case MetricsRPS:
					prev := j.prev[k]
					j.prev[k] = value
					delta = value - prev
				case MetricsCounter:
					delta = value
				case MetricsTimes:
					now := float64(time.Now().Unix())
					ts := value
					sum := v[0][1]
					max := v[0][2]
					min := v[0][3]
					counter := v[0][4]

					j.g.L.Debugf("%s [%d]/[%d] k:'%s' ts:'%2.0f' sum:'%2.2f' count:'%2.2f' max:'%2.2f' min:'%2.2f'",
						id, count, len(j.values), k, ts, sum, counter, max, min)

					if ts+interval > now {
						if counter > 0 {
							delta = sum / counter
						}
					}

					name = "avg"
				}

				// pushing data into vector
				if _, ok := j.vectors[k]; !ok {
					length := DefaultVectorLength
					j.vectors[k] = NewMetricsVector(length)
				}

				j.vectors[k].PushValue(name, delta)

				j.g.L.Debugf("%s [%d]/[%d] name:'%s' k:'%s' -> class:'%s' tags:['%s'] value:'%2.2f' delta:'%2.2f' vector: %s", id,
					count, len(j.values), metric, k, MetricToString(class),
					strings.Join(tags, ","), value, delta,
					j.vectors[k].AsString(name, DefaultVectorLogShow))

				count++
			}

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (j *MetricsWorker) GetMetric(name string) (float64, error) {
	id := "(metric)"
	for k, v := range j.values {
		class, _, metric, err := KeyToTags(k)
		if err != nil {
			j.g.L.Errorf("%s error on processing k:'%s', err:'%s'", id, k, err)
			continue
		}
		if metric != name {
			continue
		}

		value := v[0][0]
		switch class {
		case MetricsCounter:
			return value, nil
		}
	}
	return float64(0), fmt.Errorf("not found metric:'%s'", name)
}

func (j *MetricsWorker) GetMetrics(name string) []Value {
	id := "(metrics) (dump) (convert)"

	var out []Value
	count := 0
	for k, v := range j.vectors {

		class, tags, metric, err := KeyToTags(k)
		if err != nil {
			j.g.L.Errorf("%s error on processing k:'%s', err:'%s'", id, k, err)
			continue
		}

		if len(name) > 0 && name != metric {
			// we need specific metric
			continue
		}

		tag := "value"
		switch class {
		case MetricsTimes:
			tag = "avg"
		}

		value := NewValue()
		for j := 0; j < len(tags); j++ {
			w := strings.Split(tags[j], "=")
			if len(w) > 0 {
				if w[0] == "name" {
					value.ID = w[1]
					continue
				}
				value.Tags[w[0]] = w[1]
			}
		}

		if len(v.values) > 0 {
			max := DefaultMonitorLength
			value.Value = v.GetAvgValue(max, tag)
		}

		out = append(out, value)

		j.g.L.Debugf("%s [%d]/[%d] name:'%s'k:'%s' -> class:'%s' tags:['%s'] name:'%s' vector:'%s'",
			id, count, len(j.vectors), metric, k, MetricToString(class), strings.Join(tags, ","),
			tag, v.AsString(name, DefaultVectorLogShow))

		count++
	}

	return out
}

// getting client check via api call
func (t *TMetricsPlugin) GetClientMetrics(metric string) ([]Value, error) {
	id := "(metrics) (client)"

	t.G().L.Debugf("%s request to get metric:'%s'", id, metric)

	client := api.NewClient(t.G())

	url := NamePlugin
	if len(metric) > 0 {
		url = fmt.Sprintf("%s/%s", NamePlugin, metric)
	}
	content, code, err := client.Request(http.MethodGet, url, nil)
	if err != nil {
		t.G().L.Errorf("%s error request url:'%s', err:'%s'", id, url, err)
		return nil, err
	}

	t.G().L.Debugf("%s recevied response content:'%d' code:'%d'", id, len(content), code)
	t.G().L.DumpBytes(id, content, 0)

	if code == http.StatusOK {
		var out []Value
		err = json.Unmarshal(content, &out)
		if err != nil {
			t.G().L.Errorf("%s error unmarshal data, err:'%s'", id, err)
			return nil, err
		}
		return out, err
	}
	return nil, fmt.Errorf("not found")
}

func (t *TMetricsPlugin) Push(metricID int, tags []string, value float64) {
	if t.worker != nil {
		t.worker.Push(metricID, tags, value)
	}
}

func (t *TMetricsPlugin) GetMetric(name string) (float64, error) {
	if t.worker != nil {
		return t.worker.GetMetric(name)
	}
	return float64(0), fmt.Errorf("metric not found")
}

func (t *TMetricsPlugin) Run(ctx context.Context, overrides *plugins.OverrideOptions) error {
	id := "(metrics) (worker)"

	w, ctx := errgroup.WithContext(ctx)

	t.G().L.Debugf("%s starting worker", id)

	// metrics should done metrics push and metrics
	// garbage collecting
	var err error
	if t.worker, err = NewMetricsWorker(t.G()); err != nil {
		t.G().L.Errorf("%s error on creating metrics worker, err:'%s'", id, err)
		return err
	}

	w.Go(func() error {
		// some type of metrics should be calculated each
		// second, e.g. calculating rps
		return t.worker.ProcessingMetrics(ctx)
	})

	return w.Wait()
}
