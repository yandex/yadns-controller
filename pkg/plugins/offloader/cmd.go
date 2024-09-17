package offloader

import (
	"strings"

	"github.com/spf13/cobra"
)

// # все делается всё считается но в итоге XDP_PASS - параметр в конфиг
// offloader control bpf dryrun --on --debug
// offloader control bpf dryrun --off --debug

// command line switches
type Switches struct {
	// should it be global switch or local
	Dryrun bool
}

// cmd cobra struct
type cmdOffloader struct {

	// a reference to plugin
	p *TOffloaderPlugin

	// command line switches
	switches Switches
}

func (c *cmdOffloader) Command() *cobra.Command {

	cmd := &cobra.Command{}
	cmd.Use = NamePlugin

	cmd.PersistentFlags().BoolVarP(&c.switches.Dryrun, "dry-run", "",
		false, "dry-run: no any actual actions are done")

	cmd.Short = "Managment via api client calls"
	cmd.Long = `
Controller could be managed via corresponding api calls, e.g.
set or unset dryrun mode or other control options
`
	offloaderControlCmd := cmdOffloaderControl{p: c.p}
	offloaderControlCmd.s = c
	cmd.AddCommand(offloaderControlCmd.Command())

	return cmd
}

type cmdOffloaderControl struct {
	p *TOffloaderPlugin
	s *cmdOffloader
}

func (c *cmdOffloaderControl) Command() *cobra.Command {
	cmd := &cobra.Command{}

	cmd.Use = "control"
	cmd.Short = "Controlling xdp program"
	cmd.Long = "Controlling xdp program"

	controlBpfCmd := cmdControlBpf{p: c.p}
	controlBpfCmd.s = c.s
	cmd.AddCommand(controlBpfCmd.Command())

	return cmd
}

type cmdControlBpf struct {
	p *TOffloaderPlugin
	s *cmdOffloader
}

func (c *cmdControlBpf) Command() *cobra.Command {
	cmd := &cobra.Command{}

	cmd.Use = "bpf"
	cmd.Short = "Controlling bpf xdp program"
	cmd.Long = "Controlling bpf xdp program"

	controlBpfDryrunCmd := cmdControlBpfDryrun{p: c.p}
	controlBpfDryrunCmd.s = c.s
	cmd.AddCommand(controlBpfDryrunCmd.Command())

	return cmd
}

type cmdControlBpfDryrun struct {
	p *TOffloaderPlugin
	s *cmdOffloader

	swOn  bool
	swOff bool
}

func (c *cmdControlBpfDryrun) Command() *cobra.Command {
	cmd := &cobra.Command{}

	cmd.Use = "dryrun"
	cmd.Short = "Setting or unsetting bpf dryrun mode"
	cmd.Long = "Setting or unsetting bpf dryrun mode"

	cmd.PersistentFlags().BoolVarP(&c.swOn, "on", "",
		false, "setting bpf dryrun in ON")

	cmd.PersistentFlags().BoolVarP(&c.swOff, "off", "",
		false, "setting bpf dryrun in OFF")

	var examples = []string{
		`  a) setting dryrun mode of bpf program to "yes"
     mode with dry-run flag set (no any actual changes)

     offloader api control bpf dryrun --on --debug --dry-run`,

		`  b) setting dryrun mode of bpf program to "no"
     production traffic will be responsed

     offloader api control bpf dryrun --off --debug`,
	}

	cmd.Example = strings.Join(examples, "\n\n")

	cmd.RunE = c.Run

	return cmd
}

func (c *cmdControlBpfDryrun) Run(cmd *cobra.Command, args []string) error {
	id := "(offloader) (control)"

	c.s.p.G().L.Debugf("%s requesting set api control bpf dryrun on:'%t' off:'%t' dryrun:'%t'",
		id, c.swOn, c.swOff, c.s.switches.Dryrun)

	var options ControlBpfReq
	options.Dryrun = c.s.switches.Dryrun
	options.Option = "dryrun"
	options.Value = false
	if c.swOn {
		options.Value = true
	}

	return c.p.SetClientBpfOptions(&options)
}
