package metrics

// common metrics plugin to store and export metrics

import (
	"fmt"

	yaml "gopkg.in/yaml.v3"

	"github.com/slayer1366/yadns-controller/pkg/plugins"
)

const (
	// plugin name is used by controller to link
	// code and configuration
	NamePlugin = "metrics"
)

type TMetricsPluginConfig struct {
	// could be disabled
	Enabled bool `json:"enabled" yaml:"enabled"`
}

type TMetricsPlugin struct {

	// some common attributes for all plugins, global
	// configuration ref, name and type
	plugins.Plugin

	// pluging configuration
	c *TMetricsPluginConfig

	// interval worker
	worker *MetricsWorker
}

func (t *TMetricsPlugin) L() *TMetricsPluginConfig {
	return t.c
}

func NewPlugin(options *plugins.PluginOptions) (*TMetricsPlugin, error) {

	id := NamePlugin

	var a TMetricsPlugin

	a.SetName(options.Name)
	a.SetType(options.Type)
	a.SetGlobal(options.Global)
	a.SetPlugins(options.Plugins)

	var c TMetricsPluginConfig
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
		cmd := cmdMetrics{p: &a}
		options.Root.AddCommand(cmd.Command())
	}

	return &a, nil
}
