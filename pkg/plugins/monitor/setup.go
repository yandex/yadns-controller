package monitor

// we need some worker to calculate state and monitoring signals
// and making some actions

import (
	"fmt"

	yaml "gopkg.in/yaml.v3"

	"github.com/slayer1366/yadns-controller/pkg/plugins"
)

const (
	// plugin name is used by controller to link
	// code and configuration
	NamePlugin = "monitor"
)

type TMonitorPluginConfig struct {
	// could be disabled
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type TMonitorPlugin struct {

	// some common attributes for all plugins, global
	// configuration ref, name and type
	plugins.Plugin

	// pluging configuration
	c *TMonitorPluginConfig

	worker *MonitorWorker
}

func (t *TMonitorPlugin) L() *TMonitorPluginConfig {
	return t.c
}

func NewPlugin(options *plugins.PluginOptions) (*TMonitorPlugin, error) {

	id := NamePlugin

	var a TMonitorPlugin

	a.SetName(options.Name)
	a.SetType(options.Type)
	a.SetGlobal(options.Global)
	a.SetPlugins(options.Plugins)

	var c TMonitorPluginConfig
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

	// metrics should done metrics push and metrics
	// garbage collecting
	if a.worker, err = NewMonitorWorker(a.G(), &a); err != nil {
		a.G().L.Errorf("%s error on creating metrics worker, err:'%s'", id, err)
		return nil, err
	}

	// adding command line processing (if any)
	if options.Root != nil {
		cmd := cmdMonitor{p: &a}
		options.Root.AddCommand(cmd.Command())
	}

	return &a, nil
}
