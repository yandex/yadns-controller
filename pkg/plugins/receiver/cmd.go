package receiver

import (
	"github.com/spf13/cobra"
)

// receiving data for zone "example.net" as its configured
// in corresponding section in configuration
// receiver fetch --zone="example.net" --debug

// command line switches
type Switches struct {
	// should it be global switch or local
	Dryrun bool
}

type cmdReceiver struct {

	// a reference to plugin
	p *TReceiverPlugin

	// command line switches
	switches Switches
}

func (c *cmdReceiver) Command() *cobra.Command {

	cmd := &cobra.Command{}
	cmd.Use = NamePlugin

	cmd.PersistentFlags().BoolVarP(&c.switches.Dryrun, "dry-run", "",
		false, "dry-run: no any actual actions are done")

	cmd.Short = "Receive dns zones data"
	cmd.Long = `
Fetches data from external sources and push them as
snaphots to validate, import or cook later
`
	// T.B.D.

	return cmd
}
