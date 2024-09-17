package offloader

import (
	"github.com/yandex/yadns-controller/pkg/plugins/monitor"
)

const (
	// metric counter for example plugin
	MetricNameCounter = "counter"

	// monitor class for check
	MonitorClass = "offloader"
)

func (t *TOffloaderPlugin) Monitor(m *monitor.TMonitorPlugin) {

	// all active and passive monitoring checks should be
	// set here: controlling some timers
}
