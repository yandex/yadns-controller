package receiver

import (
	"github.com/slayer1366/yadns-controller/pkg/plugins/monitor"
)

const (
	// metric counter for example plugin
	MetricNameCounter = "counter"

	// monitor class for check
	MonitorClass = "receiver"
)

func (t *TReceiverPlugin) Monitor(m *monitor.TMonitorPlugin) {

	// all active and passive monitoring checks should be
	// set here: controlling some timers
}
