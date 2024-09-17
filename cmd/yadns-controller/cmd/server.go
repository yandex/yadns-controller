package cmd

import (
	"context"
	"errors"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"
	"golang.org/x/sync/errgroup"

	"github.com/slayer1366/yadns-controller/pkg/controller"
)

type Switches struct {
	// alternative bpf to overrride ones
	// from plugin
	Bpf string
}

type cmdServer struct {
	g *controller.Controller

	switches Switches
}

func (c *cmdServer) Command() *cobra.Command {

	cmd := &cobra.Command{}
	cmd.Use = "server"
	cmd.Short = "Controlling server process"
	cmd.Long = "Starting and stopping server process"

	cmd.PersistentFlags().StringVarP(&c.switches.Bpf, "bpf", "B",
		"", "bpf: path to alternative bpf binary to load")

	serverStartCmd := cmdServerStart{g: c.g}
	serverStartCmd.s = c
	cmd.AddCommand(serverStartCmd.Command())

	return cmd
}

type cmdServerStart struct {
	g *controller.Controller

	s *cmdServer
}

func (c *cmdServerStart) Command() *cobra.Command {
	cmd := &cobra.Command{}

	cmd.Use = "start"
	cmd.Short = "Starting server"
	cmd.Long = "Starting server"

	cmd.RunE = c.Run
	return cmd
}

func (c *cmdServerStart) Run(cmd *cobra.Command, args []string) error {
	id := "(server) (start)"
	c.g.L().Debugf("%s starting server compiled as version:'%s' at date:'%s'", id,
		c.g.Runtime().Version, c.g.Runtime().Date)

	ctx := context.Background()
	w, ctx := errgroup.WithContext(ctx)

	w.Go(func() error {
		err := WaitInterrupted(ctx)
		c.g.L().Errorf("%s caught some interruption, err:'%s'", id, err)
		return err
	})

	w.Go(func() error {
		var options controller.ControllerOptions
		options.Bpf = c.s.switches.Bpf
		return c.g.Run(ctx, &options)
	})

	return w.Wait()
}

// Borrowed from dnsguard server code
func WaitInterrupted(ctx context.Context) error {
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	select {
	case v := <-sigChan:
		return errors.New(v.String())
	case <-ctx.Done():
		return ctx.Err()
	}
}
