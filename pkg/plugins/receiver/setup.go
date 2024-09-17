package receiver

// receiver implements all data DNS zones logics: receive
// data, sync data, verify and cook snapshots for XDP maps

import (
	"fmt"
	"strings"
	"time"

	yaml "gopkg.in/yaml.v3"

	"github.com/yandex/yadns-controller/pkg/plugins"
	"github.com/yandex/yadns-controller/pkg/plugins/monitor"
)

const (
	// plugin name is used by controller to link
	// code and configuration
	NamePlugin = "receiver"

	// default workers count for transfer pool
	DefaultTransferPoolWorkers = 5

	// in many places we dump lists of rrsets
	// settings below defines a maximum number of rrsets
	// to dump
	DefaultDumpMaxRRsets = 10

	// snapshot default max counts, should be at least 2?
	DefaultSnapshotCount = 4

	// default time interval state update in
	// seconds to update zone data
	DefaultTransfersInterval = 10 * time.Second

	// default suffix for snapshot files
	DefaultSnapshotSuffix = "yadns-xdp.blob"
)

type TReceiverPluginConfig struct {
	// could be disabled
	Enabled bool `json:"enabled" yaml:"enabled"`

	// pinpath to import/sync recevied data
	PinPath string `json:"pinpath" yaml:"pinpath"`

	// global recevier options
	Options TDataReceiverOptions `json:"options" yaml:"options"`

	// http and file transfer adapter
	HTTPTransfer TConfigHTTPTransfer `json:"http-transfer" yaml:"http-transfer"`

	// axfr transfer adapter
	AxfrTransfer TConfigAxfrTransfer `json:"axfr-transfer" yaml:"axfr-transfer"`

	// verifier configuration
	Verifier TConfigDataVerifier `json:"verifier" yaml:"verifier"`

	// cooker configuration
	Cooker TConfigDataCooker `json:"cooker" yaml:"cooker"`

	// monitor collector and its options
	Monitor TConfigMonitor `json:"monitor" yaml:"monitor"`
}

type TConfigMonitor struct {
	Collector TConfigMonitorCollector `json:"collector" yaml:"collector"`

	Watcher TConfigMonitorWatcher `json:"watcher" yaml:"watcher"`
}

type TConfigMonitorWatcher struct {
	// watcher checks some conditions and thresholds
	// for rules and make some actions (also exported
	// monitoring events via API)
	Enabled bool `json:"enabled" yaml:"enabled"`

	// check interval
	Interval int `json:"interval" yaml:"interval"`

	// a list of rules to check
	Rules map[string]TRule `json:"rules" yaml:"rules"`
}

type TRule struct {
	Higher  int      `json:"higher" yaml:"higher"`
	Lower   int      `json:"lower" yaml:"lower"`
	Actions []string `json:"actions" yaml:"actions"`
}

type TConfigMonitorCollector struct {
	Enabled bool                  `json:"enabled" yaml:"enabled"`
	Bpf     TConfigMonitorBpf     `json:"bpf" yaml:"bpf"`
	Runtime TConfigMonitorRuntime `json:"runtime" yaml:"runtime"`

	DumpInterval int `json:"dump-interval" yaml:"dump-interval"`

	Verbose bool `json:"verbose" yaml:"verbose"`

	GarbageCollector TGarbageCollector `json:"garbage-collector" yaml:"garbage-collector"`
}

type TGarbageCollector struct {
	Interval int `json:"interval" yaml:"interval"`

	Keep int `json:"keep" yaml:"keep"`
}

type TConfigMonitorBpf struct {
	Intervals TConfigMonitorIntervals `json:"intervals" yaml:"intervals"`
}

type TConfigMonitorRuntime struct {
	Intervals TConfigMonitorIntervals `json:"intervals" yaml:"intervals"`
}

type TConfigMonitorIntervals struct {
	Metrics int `json:"metrics" yaml:"metrics"`

	Histograms int `json:"histograms" yaml:"histograms"`

	Zero bool `json:"zero" yaml:"zero"`
}

type TConfigDataCooker struct {
	Enabled bool `json:"enabled" yaml:"enabled"`

	Dryrun bool `json:"dryrun" yaml:"dryrun"`

	// cooking interval in seconds
	Interval int `json:"interval" yaml:"interval"`

	// snapshot per bpf map
	Snapshots TSnapshotsDataCooker `json:"snapshots" yaml:"snapshots"`
}

type TSnapshotsDataCooker struct {
	// if snapshots is not enabled, controller
	// should receive zones states as it starts
	// if enabled it read the last snapshot (if
	// configured below)
	Enabled bool `json:"enabled" yaml:"enabled"`

	// reading on startup
	ReadOnStartup bool `json:"read-onstartup" yaml:"read-onstartup"`

	// reading snapshots with specified age
	ReadValidInterval int `json:"read-validinterval" yaml:"read-validinterval"`

	// snapshots directory
	Directory string `json:"directory" yaml:"directory"`

	// number snapshots to keep
	Keep int `json:"keep" yaml:"keep"`
}

type TConfigDataVerifier struct {
	Enabled bool `json:"enabled" yaml:"enabled"`

	Interval int `json:"interval" yaml:"interval"`

	VerifyOnCook bool `json:"verify-oncook" yaml:"verify-oncook"`
}

type TConfigVerifier struct {
	// server to transfer data
	Server string `json:"server" yaml:"server"`

	// a list of zones to transfer
	Zone []string `json:"zone" yaml:"zone"`

	// an optional TSIG key for transfer
	Key string `json:"key" yaml:"key"`

	Dryrun bool `json:"dryrun" yaml:"dryrun"`
	Force  bool `json:"force" yaml:"force"`
}

func (t *TConfigVerifier) AsString() string {
	var b strings.Builder

	if len(t.Server) > 0 {
		fmt.Fprintf(&b, "server:'%s',", t.Server)
	}
	if len(t.Zone) > 0 {
		fmt.Fprintf(&b, "zone:['%s']", strings.Join(t.Zone, ","))
	}

	fmt.Fprintf(&b, "dryrun:'%t',", t.Dryrun)
	fmt.Fprintf(&b, "force:'%t',", t.Force)

	return b.String()
}

type TDataReceiverOptions struct {
	Incremental bool `json:"incremental" yaml:"incremental"`

	// snapshot per zone
	Snapshots TSnapshotsDataReceiver `json:"snapshots" yaml:"snapshots"`
}

type TSnapshotsDataReceiver struct {
	Enabled bool `json:"enabled" yaml:"enabled"`

	// reading on startup
	ReadOnStartup bool `json:"read-onstartup" yaml:"read-onstartup"`

	// reading snapshots with specified age
	ReadValidInterval int `json:"read-validinterval" yaml:"read-validinterval"`

	// syncing blob to bpf.Map age on startup
	StartupValidInterval int `json:"startup-validinterval" yaml:"startup-validinterval"`

	// snapshots directory
	Directory string `json:"directory" yaml:"directory"`
}

type TConfigHTTPTransfer struct {
	// enabling axfr transfer
	Enabled bool `json:"enabled" yaml:"enabled"`

	// zones configuration
	Zones TZones `json:"zones" yaml:"zones"`
}

type TConfigAxfrTransfer struct {
	// enabling axfr transfer
	Enabled bool `json:"enabled" yaml:"enabled"`

	// transfering zone method
	TransferVia string `json:"transfer-via" yaml:"transfer-via"`

	// detecting if zone changes
	DirtyVia string `json:"dirty-via" yaml:"dirty-via"`

	// transfer configuration
	Transfer TTransfer `json:"transfer" yaml:"transfer"`

	// zones configuration
	Zones TZones `json:"zones" yaml:"zones"`

	// notify configuration
	Notify TNotify `json:"notify" yaml:"notify"`
}

type TNotify struct {
	// enabling or disabling notify processing
	Enabled bool `json:"enabled" yaml:"enabled"`

	// a list of addresses to bind for notify listeners
	Listen []string `json:"listen" yaml:"listen"`

	// udp buffer size
	UDPBufferSize int `json:"udp-buffer-size" yaml:"udp-buffer-size"`

	// workers number for dns server server instance
	Workers int `json:"workers" yaml:"workers"`

	// global options to override allow notify
	AllowNotify []string `json:"allow-notify" yaml:"allow-notify"`

	// T.B.D some bind options for notify rate
	NotifyRate int `json:"notify-rate" yaml:"notify-rate"`

	// T.B.D. startup rate
	StartupNotifyRate int `json:"startup-notify-rate" yaml:"startup-notify-rate"`

	Cookers TNotifyCooker `json:"cookers" yaml:"cookers"`
}

type TNotifyCooker struct {
	Workers int `json:"workers" yaml:"workers"`
}

type TZones struct {
	// optional configuration directory
	ZonesDirectory string `json:"zones-directory" yaml:"zones-directory"`

	// secondary zones configurations
	Secondary map[string]TConfigZone `json:"secondary" yaml:"secondary"`

	// if transfer should be incremental
	Incremental bool `json:"incremental" yaml:"incremental"`

	// Aliases primary map configuration (used in
	// zones configuration)
	Primary map[string]string `json:"primary" yaml:"primary"`
}

type TConfigZone struct {
	// zone could be disabled
	Enabled bool `json:"enabled" yaml:"enabled"`

	// primary master servers
	Primary []string `json:"primary" yaml:"primary"`

	// allowing notification from sources
	AllowNotify []string `json:"allow-notify" yaml:"allow-notify"`

	// override refresh counter
	Refresh int `json:"refresh" yaml:"refresh"`

	// a type of zone: could be axfr, http (of file)
	Type string `json:"type" yaml:"type"`
}

func (t *TConfigZone) String() string {
	var out []string

	out = append(out, fmt.Sprintf("enabled:'%t'", t.Enabled))
	out = append(out, fmt.Sprintf("primary:['%s']", strings.Join(t.Primary, ",")))
	out = append(out, fmt.Sprintf("allow-notify:['%s']", strings.Join(t.AllowNotify, ",")))

	if t.Refresh > 0 {
		out = append(out, fmt.Sprintf("refresh:'%d'", t.Refresh))
	}

	return strings.Join(out, ",")
}

func CreateDefaultConfigZone(primary []string) TConfigZone {
	var c TConfigZone
	c.Enabled = true
	c.Primary = append(c.Primary, primary...)
	return c
}

type TTransfer struct {
	// number of max transfer
	TransfersIn int `json:"transfers-in" yaml:"transfers-in"`

	// method to receive job to make transfer
	TransfersVia []string `json:"transfers-via" yaml:"transfers-via"`

	// transfer interval
	TransfersInterval int `json:"transfers-interval" yaml:"transfers-interval"`
}

type TConfigCooker struct {
	Dryrun bool `json:"dryrun" yaml:"dryrun"`
}

type TConfigNotifier struct {
	Dryrun bool `json:"dryrun" yaml:"dryrun"`
}

// ConfigImporter includes two types of import via
// file (if file defines) or via dns axfr (if zone
// define and file is not)
type TConfigImporter struct {
	// a list of files to import, assuming axfr
	File []string `json:"file" yaml:"file"`

	// server to transfer data
	Server string `json:"server" yaml:"server"`

	// a list of zones to transfer
	Zone []string `json:"zone" yaml:"zone"`

	// a list of (http) endpoints
	Endpoint []string `json:"endpoint" yaml:"endpoint"`

	// an optional TSIG key for transfer
	Key string `json:"key" yaml:"key"`

	// an optional fqdn suffix to append in import
	Suffix string `json:"suffix" yaml:"suffix"`

	// serial number if set try to use IXFR
	Incremental bool `json:"incremental" yaml:"incremental"`

	Dryrun bool `json:"dryrun" yaml:"dryrun"`
}

func (t *TConfigImporter) AsString() string {
	var b strings.Builder

	if len(t.File) > 0 {
		fmt.Fprintf(&b, "file:['%s'],", strings.Join(t.File, ","))
	}
	if len(t.Server) > 0 {
		fmt.Fprintf(&b, "server:'%s',", t.Server)
	}
	if len(t.Zone) > 0 {
		fmt.Fprintf(&b, "zone:['%s']", strings.Join(t.Zone, ","))
	}

	return b.String()
}

type TReceiverPlugin struct {

	// some common attributes for all plugins, global
	// configuration ref, name and type
	plugins.Plugin

	// pluging configuration
	c *TReceiverPluginConfig

	// pool of transfer workers
	pool *CollectorTransferPool

	// current state of zones fetched
	zones *ZonesState

	// verifier and cooker
	verifier *VerifierWorker
	cooker   *CookerWorker

	// watching for some properties
	watcher *WatcherWorker

	// a process to listen notifies
	notifier *NotifierWorker
}

func (t *TReceiverPlugin) L() *TReceiverPluginConfig {
	return t.c
}

func NewPlugin(options *plugins.PluginOptions) (*TReceiverPlugin, error) {

	id := "example"

	var a TReceiverPlugin

	a.SetName(options.Name)
	a.SetType(options.Type)
	a.SetGlobal(options.Global)
	a.SetPlugins(options.Plugins)

	var c TReceiverPluginConfig
	err := yaml.Unmarshal(options.Content, &c)
	if err != nil {
		a.G().L.Errorf("%s error configuring plugin, err:'%s'", id, err)
		return nil, err
	}

	// plugin could be disabled
	if !c.Enabled {
		err = fmt.Errorf("plugin:'%s' disabled", options.Name)
		a.G().L.Errorf("%s plugin is disabled, err:'%s'", id, err)
		return nil, err
	}
	a.c = &c

	// adding command line processing (if any)
	if options.Root != nil {
		cmd := cmdReceiver{p: &a}
		options.Root.AddCommand(cmd.Command())
	}

	// setting up monitoring checks
	if a.P().Monitor() != nil {
		a.Monitor(a.P().Monitor().(*monitor.TMonitorPlugin))
	}

	return &a, nil
}
