package example

import (
	"strings"

	"github.com/spf13/cobra"
)

// command line switches
type Switches struct {
	// should it be global switch or local
	Dryrun bool

	// watcher interval to override
	// configuration values
	Interval int
}

// cmd cobra struct
type cmdExample struct {

	// a reference to plugin
	p *TExamplePlugin

	// command line switches
	switches Switches
}

func (c *cmdExample) Command() *cobra.Command {

	cmd := &cobra.Command{}
	cmd.Use = NamePlugin

	cmd.Short = "Example plugin to demostrate all features"
	cmd.Long = `
Example plugin has its own command switches, logics, configuration
processing, metrics and monitoring, API methods
`

	var examples = []string{
		`  run one example step
      $program monitor list d2-dns-soa --juggler-config`,
	}

	cmd.Example = strings.Join(examples, "\n\n")

	cmd.PersistentFlags().IntVarP(&c.switches.Interval, "interval", "I",
		DefaultWatcherInterval, "interval in seconds")

	exampleRunCmd := cmdExampleRun{}
	exampleRunCmd.s = c
	cmd.AddCommand(exampleRunCmd.Command())

	return cmd
}

type cmdExampleRun struct {
	s *cmdExample
}

func (c *cmdExampleRun) Command() *cobra.Command {
	cmd := &cobra.Command{}

	cmd.Use = "run"
	cmd.Short = "Running example code"
	cmd.Long = "Running example code"

	cmd.RunE = c.Run
	return cmd
}

func (c *cmdExampleRun) Run(cmd *cobra.Command, args []string) error {
	id := "(example) (run)"
	var err error

	c.s.p.G().L.Debugf("%s request command", id)

	if err = c.s.p.RunCommand(); err != nil {
		c.s.p.G().L.Errorf("%s error on running command, err:'%s'", id, err)
		return err
	}

	return err
}
