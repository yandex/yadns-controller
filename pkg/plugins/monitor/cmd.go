package monitor

import (
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/yandex/yadns-controller/pkg/internal/config"
)

// command line switches
type Switches struct {
	// should it be global switch or local
	Dryrun bool

	// check id
	ID string
}

// cmd cobra struct
type cmdMonitor struct {

	// a reference to plugin
	p *TMonitorPlugin

	// command line switches
	switches Switches
}

func (c *cmdMonitor) Command() *cobra.Command {

	cmd := &cobra.Command{}
	cmd.Use = NamePlugin

	cmd.Short = "Monitor managment via api client calls"
	cmd.Long = `
Monitor could be exported from API or requested to send
via default or specified method
`

	cmd.PersistentFlags().StringVarP(&c.switches.ID, "id", "I", "", "check id")

	var examples = []string{
		`  lising current monitoring checks values
      $program monitor list --debug --id yadns-example-generic`,
	}

	cmd.Example = strings.Join(examples, "\n\n")

	monitorListCmd := cmdMonitorList{}
	monitorListCmd.s = c
	cmd.AddCommand(monitorListCmd.Command())

	monitorMonrunCmd := cmdMonitorMonrun{}
	monitorMonrunCmd.s = c
	cmd.AddCommand(monitorMonrunCmd.Command())

	return cmd
}

type cmdMonitorList struct {
	s *cmdMonitor
}

func (c *cmdMonitorList) Command() *cobra.Command {
	cmd := &cobra.Command{}

	cmd.Use = "list"
	cmd.Short = "Listing monitoring checks"
	cmd.Long = "List monitor checks"

	cmd.RunE = c.Run
	return cmd
}

func (c *cmdMonitorList) Run(cmd *cobra.Command, args []string) error {
	id := "(monitor) (list)"
	var err error

	c.s.p.G().L.Debugf("%s requesting monitoring check:'%s' state",
		id, c.s.switches.ID)

	checks, err := c.s.p.GetClientChecks(c.s.switches.ID)
	if err != nil {
		c.s.p.G().L.Errorf("%s error getting check:'%s', err:'%s'", id,
			c.s.switches.ID, err)
		return err
	}
	c.s.p.G().L.Debugf("%s check:'%s' received checks:'%d'", id,
		c.s.switches.ID, len(checks))

	count := 0
	for cid, check := range checks {
		c.s.p.G().L.Debugf("%s [%d]/[%d] %s %s", id, count,
			len(checks), cid, check)

		fmt.Printf("%d;%s: %s\n", check.Code, check.ID, check.Message)
		count++
	}
	return err
}

type cmdMonitorMonrun struct {
	s *cmdMonitor
}

func (c *cmdMonitorMonrun) Command() *cobra.Command {
	cmd := &cobra.Command{}

	cmd.Use = "monrun"
	cmd.Short = "Monrun juggler-like checks show"
	cmd.Long = "Listing all current states for check in monrun view"

	cmd.RunE = c.Run
	return cmd
}

func (c *cmdMonitorMonrun) Run(cmd *cobra.Command, args []string) error {
	id := "(monitor) (monrun)"

	var err error
	c.s.p.G().L.Debugf("%s requesting monitoring monrun", id)

	checks, err := c.s.p.GetClientChecks(c.s.switches.ID)
	if err != nil {
		c.s.p.G().L.Errorf("%s error getting check:'%s', err:'%s'", id,
			c.s.switches.ID, err)
		return err
	}
	c.s.p.G().L.Debugf("%s check:'%s' received checks:'%d'", id,
		c.s.switches.ID, len(checks))

	// grouping checks w.r.t class and sorting within class in alphabet
	monrun := make(map[string][]*Check)
	for _, check := range checks {
		monrun[check.Class] =
			append(monrun[check.Class], check)
	}

	for class, checks := range monrun {
		fmt.Printf("Type: %s\n", class)
		sort.Slice(checks, func(i, j int) bool { return checks[i].ID > checks[j].ID })
		for i, check := range checks {
			c.s.p.G().L.Debugf("%s [%d]/[%d] class:'%s' '%s' %s", id, i,
				len(checks), class, check.ID, check.Message)

			colored := config.ColorString(check.Message, check.Color())
			fmt.Printf("\t%s = %s\n", check.ID, colored)
		}
	}

	return err
}
