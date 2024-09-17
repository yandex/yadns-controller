package plugins

import (
	"context"

	"github.com/labstack/echo/v4"
	"github.com/spf13/cobra"

	"github.com/slayer1366/yadns-controller/pkg/internal/config"
)

// possible options override configuration
type OverrideOptions struct {

	// bpf program from command line
	Bpf string
}

type PluginOptions struct {
	// name nad type of plugin
	Name string
	Type string

	// a part of configuration for plugin
	Content []byte

	// a root cmd object
	Root *cobra.Command

	// global reference to configuration
	Global *config.TGlobal

	// a plugins object
	Plugins *Plugins
}

// plugin implements all actions with plugins
type Plugin struct {

	// general configuration
	g *config.TGlobal

	// a reference to plugins
	plugins *Plugins

	// type and name of plugin, see possible
	// types and names above
	t string

	// name should be one of
	name string
}

func (p *Plugin) Name() string {
	return p.name
}

func (p *Plugin) Type() string {
	return p.t
}

func (p *Plugin) G() *config.TGlobal {
	return p.g
}

func (p *Plugin) P() *Plugins {
	return p.plugins
}

func (p *Plugin) SetName(name string) {
	p.name = name
}

func (p *Plugin) SetType(t string) {
	p.t = t
}

func (p *Plugin) SetGlobal(g *config.TGlobal) {
	p.g = g
}

func (p *Plugin) SetPlugins(plugins *Plugins) {
	p.plugins = plugins
}

type IPlugin interface {
	// returning a name
	Name() string

	// run method for plugin
	Run(ctx context.Context, overrides *OverrideOptions) error

	// setting up api methods
	SetupMethods(group *echo.Group)
}

type Plugins struct {
	g *config.TGlobal

	// map of plagins grouping with names
	plugins map[string][]IPlugin
}

func NewPlugins(g *config.TGlobal) *Plugins {
	var p Plugins
	p.g = g
	p.plugins = make(map[string][]IPlugin)
	return &p
}

func (p *Plugins) AddPlugin(k string, plugin IPlugin) {
	p.plugins[k] = append(p.plugins[k], plugin)
}

func (p *Plugins) GetPlugins() []IPlugin {
	var out []IPlugin
	for _, plugin := range p.plugins {
		out = append(out, plugin...)
	}
	return out
}

func (p *Plugins) GetPlugin(name string) IPlugin {
	for _, plugin := range p.plugins {
		for _, p := range plugin {
			if p.Name() == name {
				return p
			}
		}
	}
	return nil
}

// some useful shortcuts: for metrics plugin
// could be used to access its method from other
// plugins
func (p *Plugins) M() IPlugin {
	return p.GetPlugin("metrics")
}

// monior plugin to interact with monitoring checks
func (p *Plugins) Monitor() IPlugin {
	return p.GetPlugin("monitor")
}
