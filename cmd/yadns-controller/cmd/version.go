package cmd

import (
	"fmt"
	"runtime"

	"github.com/spf13/cobra"

	"github.com/yandex/yadns-controller/pkg/controller"
)

type cmdVersion struct {
	g *controller.Controller
}

func (c *cmdVersion) Command() *cobra.Command {

	cmd := &cobra.Command{}
	cmd.Use = "version"
	cmd.Short = "Showing version and some possible useful information"
	cmd.Long = "Description: showing application version and runtime options"
	cmd.RunE = c.Run

	return cmd
}

func (c *cmdVersion) Run(cmd *cobra.Command, args []string) error {

	fmt.Printf("%s: '%s', build date:'%s', compiler:'%s' '%s', running at host:'%s'\n",
		c.g.Runtime().ProgramName, c.g.Runtime().Version, c.g.Runtime().Date,
		runtime.Compiler, runtime.Version(),
		c.g.Runtime().Hostname)

	return nil
}
