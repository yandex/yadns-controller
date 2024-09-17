package example

import (
	"context"
	"fmt"

	"github.com/slayer1366/yadns-controller/pkg/plugins/metrics"
	"github.com/slayer1366/yadns-controller/pkg/plugins/monitor"
)

const (
	// metric counter for example plugin
	MetricNameCounter = "counter"

	// monitor class for check
	MonitorClass = "example"
)

func (t *TExamplePlugin) Monitor(m *monitor.TMonitorPlugin) {

	// generic example monitoring check, please choose ID
	// monitoring checks carefully
	m.AddConfig(monitor.CheckConfig{ID: "yadns-example-generic",
		F: t.ExampleGenericMonitor})
}

// example check to demonstate its run and pushing
// results into monitor controller
func (t *TExamplePlugin) ExampleGenericMonitor(ctx context.Context,
	m *monitor.TMonitorPlugin) (*monitor.Check, error) {

	tid := "yadns-example-generic"
	id := fmt.Sprintf("(monitor) (%s)", tid)

	// getting our counter from metrics
	value, err := t.P().M().(*metrics.TMetricsPlugin).GetMetric(MetricNameCounter)
	if err != nil {
		// something wrong with metric value
		// not ready yet
		check := &monitor.Check{
			ID: tid, Class: MonitorClass,
			Message: fmt.Sprintf("value metric:'%s' not found, err:'%s'",
				MetricNameCounter, err),
			Code: monitor.Crit,
		}
		return check, err
	}

	// our check is checkinf for counter from metrics
	// data and if divided by 100 count with module
	// 3 (0, 1, 2) is mapped to OK, WARN and CRIT
	t.G().L.Debugf("%s check started metric:'%s' value:'%2.2f",
		id, MetricNameCounter, value)

	// some example logics to have OK, WARN and CRIT codes
	modulo := int(int64(value) / 10 % 3)

	check := &monitor.Check{
		ID: tid, Class: MonitorClass,
		Message: fmt.Sprintf("value:'%2.2f' modulo:'%d'", value, modulo),

		// differnet OK, WARN, CRIT values w.r.t modulo
		Code: modulo,
	}

	return check, err
}
