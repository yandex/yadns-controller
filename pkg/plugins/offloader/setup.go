package offloader

// offloader plugin implements bpf/xdp program handler:
// load, unload bpf map interface, configuration

import (
	"fmt"
	"strings"

	yaml "gopkg.in/yaml.v3"

	"github.com/yandex/yadns-controller/pkg/plugins"
	"github.com/yandex/yadns-controller/pkg/plugins/monitor"
)

const (
	// plugin name is used by controller to link
	// code and configuration
	NamePlugin = "offloader"

	// some predefined values, in seconds
	DefaultWatcherInterval = 20
)

type TOffloaderPluginConfig struct {
	// could be disabled
	Enabled bool `json:"enabled" yaml:"enabled"`

	// bpf controls for some cases
	Controls TConfigControls `json:"controls" yaml:"controls"`

	// bpf xdp options
	Options TConfigOptions `json:"options" yaml:"options"`

	// XDP loader options, by default we have primary mode
	Loader TConfigLoader `json:"loader" yaml:"loader"`
}

type TConfigControls struct {
	// if controller should check and mount bppfs
	Bpffs bool `json:"bpffs" yaml:"bpffs"`

	// if we should set memlock to unlimit
	UnlimitMemlock bool `json:"unlimit-memlock" yaml:"unlimit-memlock"`
}

type TConfigOptions struct {
	// interface
	Interface string `json:"interface" yaml:"interface"`

	// requests DSTS for IP6 and IP4 dst addresses
	// to match VS processing
	Addrs []string `json:"addrs" yaml:"addrs"`

	// I hope that we will need only one bpf program
	// to handle traffic
	Path string `json:"path" yaml:"path"`

	// pinpath
	PinPath string `json:"pinpath" yaml:"pinpath"`

	// bpf option dryrun
	BpfDryrun bool `json:"bpf-dryrun" yaml:"bpf-dryrun"`

	// bpf option to enable xdpcap hook call
	BpfXdpcap bool `json:"bpf-xdpcap" yaml:"bpf-xdpcap"`

	// enable of disable bpf perf
	BpfMetrics bool `json:"bpf-metrics" yaml:"bpf-metrics"`

	// if xdp should generate random TTL (it could be
	// used in ns-cache responses)
	ResponseRandomTTL bool `json:"response-random-ttl" yaml:"response-random-ttl"`

	// response flags, AA, RD, RA, MBZ
	ResponseFlags []string `json:"response-flags" yaml:"response-flags"`
}

func (t *TConfigOptions) String() string {
	var b strings.Builder

	fmt.Fprintf(&b, "response-random-ttl:'%t',", t.ResponseRandomTTL)
	fmt.Fprintf(&b, "response-flags:['%s'],", strings.Join(t.ResponseFlags, ","))
	fmt.Fprintf(&b, "addrs:['%s'],", strings.Join(t.Addrs, ","))

	return b.String()
}

type TConfigLoader struct {

	// mode could be "primary" "secondary", auto"
	Mode string `json:"mode" yaml:"mode"`

	// hook options for "secondary" mode
	Hook THookLoader `json:"hook" yaml:"hook"`
}

type THookLoader struct {

	// hook pinpath
	PinPath string `json:"pinpath" yaml:"pinpath"`

	// index pinpath
	Index []int `json:"index" yaml:"index"`
}

type TOffloaderPlugin struct {

	// some common attributes for all plugins, global
	// configuration ref, name and type
	plugins.Plugin

	// pluging configuration
	c *TOffloaderPluginConfig

	// xdp server
	xdp *TXdpService
}

func (t *TOffloaderPlugin) L() *TOffloaderPluginConfig {
	return t.c
}

func (t *TOffloaderPlugin) GetXdpService() *TXdpService {
	return t.xdp
}

func NewPlugin(options *plugins.PluginOptions) (*TOffloaderPlugin, error) {

	id := "offloader"

	var a TOffloaderPlugin

	a.SetName(options.Name)
	a.SetType(options.Type)
	a.SetGlobal(options.Global)
	a.SetPlugins(options.Plugins)

	var c TOffloaderPluginConfig
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
		cmd := cmdOffloader{p: &a}
		options.Root.AddCommand(cmd.Command())
	}

	// setting up monitoring checks
	a.Monitor(a.P().Monitor().(*monitor.TMonitorPlugin))

	return &a, nil
}
