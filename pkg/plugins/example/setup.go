package example

// example plugin to introduce features and integration
// with controller: configuration, API methods, cmd commands,
// metrics, interaction with other plugins

import (
	"fmt"

	yaml "gopkg.in/yaml.v3"

	"github.com/slayer1366/yadns-controller/pkg/plugins"
	"github.com/slayer1366/yadns-controller/pkg/plugins/monitor"
)

const (
	// plugin name is used by controller to link
	// code and configuration
	NamePlugin = "example"

	// some predefined values, in seconds
	DefaultWatcherInterval = 20
)

type TExamplePluginConfig struct {
	// could be disabled
	Enabled bool `json:"enabled" yaml:"enabled"`

	// example watcher
	Watcher TExampleWatcher `json:"watcher" yaml:"watcher"`
}

type TExampleWatcher struct {
	// interval to make some actions
	Interval int `json:"interval" yaml:"interval"`
}

func (t *TExampleWatcher) String() string {
	return fmt.Sprintf("example watcher interval:'%d'", t.Interval)
}

type TExamplePlugin struct {

	// some common attributes for all plugins, global
	// configuration ref, name and type
	plugins.Plugin

	// pluging configuration
	c *TExamplePluginConfig
}

func (t *TExamplePlugin) L() *TExamplePluginConfig {
	return t.c
}

func NewPlugin(options *plugins.PluginOptions) (*TExamplePlugin, error) {

	id := "example"

	var a TExamplePlugin

	a.SetName(options.Name)
	a.SetType(options.Type)
	a.SetGlobal(options.Global)
	a.SetPlugins(options.Plugins)

	var c TExamplePluginConfig
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
		cmd := cmdExample{p: &a}
		options.Root.AddCommand(cmd.Command())
	}

	// setting up monitoring checks
	a.Monitor(a.P().Monitor().(*monitor.TMonitorPlugin))

	return &a, nil
}
