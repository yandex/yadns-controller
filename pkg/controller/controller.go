package controller

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"
	yaml "gopkg.in/yaml.v3"

	"github.com/slayer1366/yadns-controller/pkg/internal/api"
	"github.com/slayer1366/yadns-controller/pkg/internal/config"
	"github.com/slayer1366/yadns-controller/pkg/internal/log"
	"github.com/slayer1366/yadns-controller/pkg/plugins"
	"github.com/slayer1366/yadns-controller/pkg/plugins/example"
	"github.com/slayer1366/yadns-controller/pkg/plugins/metrics"
	"github.com/slayer1366/yadns-controller/pkg/plugins/monitor"
	"github.com/slayer1366/yadns-controller/pkg/plugins/offloader"
	"github.com/slayer1366/yadns-controller/pkg/plugins/receiver"
)

type ControllerOptions struct {
	// possible variables to override
	// configuration
	Bpf string
}

// controller is an instance to control a list
// of servers, caches, some internal logics. We would
// like to have many servers - each for interface with
// its own configuration. Base usage: eth0 for external
// lo for internal
type Controller struct {
	g *config.TGlobal

	// api contoller worker
	api *api.Server

	// map of plagins grouping with names
	plugins *plugins.Plugins

	mutex sync.Mutex

	// options from server command line
	options *ControllerOptions
}

func (c *Controller) Runtime() *config.TRuntime {
	return c.g.Runtime
}

func (c *Controller) L() *log.Logger {
	return c.g.L
}

func (c *Controller) O() *config.TConfig {
	return c.g.Opts
}

// some more options to override config could be
// presented here
type ConfigOptions struct {
	LogFile    string
	Debug      bool
	ConfigFile string

	Dryrun bool
}

func NewController() *Controller {
	var c Controller
	var g config.TGlobal
	var r config.TRuntime

	// runtime configuration
	r.ProgramName = config.ProgramName
	r.Hostname, _ = os.Hostname()

	g.Runtime = &r
	c.g = &g

	c.plugins = plugins.NewPlugins(c.g)

	// also we need options from configuration
	// and logger initialization
	return &c
}

func (c *Controller) LoadConfig(options *ConfigOptions) error {
	var err error

	id := "(contoller) (config)"

	ConfigFile := ""
	if options != nil {
		if len(options.ConfigFile) > 0 {
			ConfigFile = options.ConfigFile
		}
	}

	if c.g.Opts, err = config.NewConfig(ConfigFile, c.g.L); err != nil {
		if c.L() != nil {
			c.L().Errorf("%s error loading config:'%s', err:'%s'", id, ConfigFile, err)
		}
		return err
	}

	return err
}

func (c *Controller) CreateLogger(filename string, debug bool) error {

	var err error

	var opts log.LoggerOptions
	opts.Debug = debug
	opts.Path = filename

	opts.Stdout = false
	if len(opts.Path) == 0 {
		opts.Stdout = true
	}

	opts.MaxAge = c.O().Log.MaxAge
	opts.MaxSize = c.O().Log.MaxSize
	opts.MaxBackups = c.O().Log.MaxBackups
	opts.Compression = c.O().Log.Compression

	if c.g.L, err = c.g.CreateLogger(&opts); err != nil {
		return err
	}

	return err
}

type PluginsOptions struct {

	// root cmd to export some commands
	// to cobra configuration
	Root *cobra.Command
}

func (c *Controller) CreatePlugins(opts *PluginsOptions) error {
	id := "(controller) (plugins)"
	var err error

	// possible plugin types
	types := []string{"monitoring", "misc", "bpf", "data"}

	for _, k := range types {
		if _, ok := c.g.Opts.Plugins[k]; !ok {
			continue
		}
		for n, p := range c.g.Opts.Plugins[k] {

			// checking possible types
			if !config.StringInSlice(k, types) {
				err := fmt.Errorf("incorrect type:'%s', expecting one of ['%s']",
					k, strings.Join(types, ","))
				c.L().Errorf("%s error init plugin name:'%s', err:'%s'", id, k, err)
				return err
			}

			// marshal back configuation for plugin
			content, err := yaml.Marshal(p)
			if err != nil {
				c.L().Errorf("%s error marshalling plugin configuration, err:'%s'", id, err)
				return err
			}
			c.L().DumpBytes(id, content, 0)

			var plugin plugins.IPlugin

			var options plugins.PluginOptions
			options.Root = opts.Root
			options.Type = k
			options.Name = n
			options.Content = content
			options.Global = c.g
			options.Plugins = c.plugins

			switch n {
			case example.NamePlugin:
				// example (and others) plugin is created in setup
				// function returing interface to plugin and
				// parsed configuration in
				if plugin, err = example.NewPlugin(&options); err != nil {
					c.L().Errorf("%s error configuring plugin name:'%s', err:'%s'", id, n, err)
					continue
				}
			case metrics.NamePlugin:
				if plugin, err = metrics.NewPlugin(&options); err != nil {
					c.L().Errorf("%s error configuring plugin name:'%s', err:'%s'", id, n, err)
					continue
				}
			case monitor.NamePlugin:
				// monitor module plugins implements worker to check
				// monitoring methods for plugins, exporting
				// checks results (for active juggler cycle)
				if plugin, err = monitor.NewPlugin(&options); err != nil {
					c.L().Errorf("%s error configuring plugin name:'%s', err:'%s'", id, n, err)
					continue
				}
			case offloader.NamePlugin:
				// offloader implements xdp dns worker, loading and unloading
				// bpf program, configuration and map management
				if plugin, err = offloader.NewPlugin(&options); err != nil {
					c.L().Errorf("%s error configuring plugin name:'%s', err:'%s'", id, n, err)
					continue
				}

			case receiver.NamePlugin:
				// receiver worker fethces all data for DNS zones
				// from external sources and generates snapshots to
				// import later via importer or cooker
				if plugin, err = receiver.NewPlugin(&options); err != nil {
					c.L().Errorf("%s error configuring plugin name:'%s', err:'%s'", id, n, err)
					continue
				}

			default:
				err = fmt.Errorf("pluging type:'%s' name:'%s' is not implemented", k, n)
				c.L().Errorf("%s error configuring plugin name:'%s', err:'%s'", id, n, err)
				continue
			}

			c.L().Debugf("%s config plugin k:'%s' name:'%s' plugin:'%s'",
				id, k, n, plugin.Name())

			c.plugins.AddPlugin(k, plugin)
		}
	}

	return err
}

func (c *Controller) Run(ctx context.Context, options *ControllerOptions) error {
	id := "(controller) (run)"

	w, ctx := errgroup.WithContext(ctx)

	if c.g.Opts != nil {
		c.L().Debugf("%s load as '%+v'", id, c.g.Opts)
	}
	c.L().Debugf("%s running controller worker", id)

	var overrides plugins.OverrideOptions
	overrides.Bpf = options.Bpf

	// creating api web server and push it to all
	// workers connected with api: receiver (for
	// zones snapshot state)
	c.api = api.NewServer(c.g)

	// getting echo http group and set api
	group := c.api.GetGroup()

	// for all plugins making some initialization
	plugins := c.plugins.GetPlugins()
	for _, p := range plugins {
		p.SetupMethods(group)
	}

	// starting api web server
	w.Go(func() error {

		// as workers started also they responsible
		// to register all object pointers we need
		return c.api.Run(ctx)
	})

	// running all plugins Run methods
	for i := range plugins {
		p := plugins[i]
		c.L().Debugf("%s run plugin:'%s'", id, p.Name())

		w.Go(func() error {
			return p.Run(ctx, &overrides)
		})
	}

	return w.Wait()
}
