package metrics

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
)

// command line switches
type Switches struct {
	// should it be global switch or local
	Dryrun bool

	// metric id
	ID string
}

// cmd cobra struct
type cmdMetrics struct {

	// a reference to plugin
	p *TMetricsPlugin

	// command line switches
	switches Switches
}

func (c *cmdMetrics) Command() *cobra.Command {

	cmd := &cobra.Command{}
	cmd.Use = NamePlugin

	cmd.Short = "Metrics managment via api client calls"
	cmd.Long = `
Metrics could be exported from API or requested to send
via default or specified method
`

	cmd.PersistentFlags().StringVarP(&c.switches.ID, "id", "I", "", "metric id")

	var examples = []string{
		`  exporting current metrics
      $program metrics export --debug`,
	}

	cmd.Example = strings.Join(examples, "\n\n")

	metricsExportCmd := cmdMetricsExport{}
	metricsExportCmd.s = c
	cmd.AddCommand(metricsExportCmd.Command())

	return cmd
}

type cmdMetricsExport struct {
	s *cmdMetrics
}

func (c *cmdMetricsExport) Command() *cobra.Command {
	cmd := &cobra.Command{}

	cmd.Use = "export"
	cmd.Short = "Exporing metrics"
	cmd.Long = "Exporing current values of metrics via api call"

	cmd.RunE = c.Run
	return cmd
}

func (c *cmdMetricsExport) Run(cmd *cobra.Command, args []string) error {
	id := "(metrics) (export)"
	var err error

	c.s.p.G().L.Debugf("%s request command", id)

	metrics, err := c.s.p.GetClientMetrics(c.s.switches.ID)
	if err != nil {
		c.s.p.G().L.Errorf("%s error getting check:'%s', err:'%s'", id,
			c.s.switches.ID, err)
		return err
	}
	c.s.p.G().L.Debugf("%s metric:'%s' received metrics:'%d'", id,
		c.s.switches.ID, len(metrics))

	for i, metric := range metrics {
		c.s.p.G().L.Debugf("%s [%d]/[%d] %s", id, i,
			len(metrics), metric.String())
		fmt.Printf("[%d]/[%d] %s", i, len(metrics),
			metric.String())
	}
	return err
}
