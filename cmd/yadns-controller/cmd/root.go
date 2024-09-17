package cmd

import (
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/spf13/cobra"

	"github.com/slayer1366/yadns-controller/pkg/controller"
)

var (
	// an instance of controller to configure, to run
	c *controller.Controller

	// possible error on start
	status error

	// alternative configuration file could be
	// set in command line
	configFile string

	// debug option is set in command line and
	// configuration, should be processed together
	debug bool

	// log option is set in command line overrides
	// log options from configuration
	logFile string

	// root cmd command, all other commands have root
	// cmd as a parent and initialized in init section below
	rootCmd = &cobra.Command{
		SilenceUsage: true,
		Use:          "yadns-controller",
		Short:        "yadns controller dns controller",
		Long: `yadns-controller is a controller for dns optimizations:
bpf dns requests classification and xdp offload. It uses plugin-like
process managment for receiver, cooker, processing and monitoring
tasks`,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {

			err := c.CreateLogger(logFile, debug)
			if err != nil {
				fmt.Printf("error creating log, err:'%s'\n", err)
				os.Exit(1)

			}
		},
	}
)

func Execute() error {
	return rootCmd.Execute()
}

func SetVersion(version string, revision string) {
	c.Runtime().Version = fmt.Sprintf("%s-r%s", strings.TrimRight(version, "\r\n"),
		strings.TrimRight(revision, "\r\n"))
}

func SetDate(date string) {
	c.Runtime().Date = strings.TrimRight(date, "\r\n")
}

func init() {

	// as cobra variables not yet initialized we use flag
	config := flag.String("C", "", "configuration file")
	log := flag.String("L", "", "log file")

	flag.Parse()

	// global cmd variables
	rootCmd.PersistentFlags().StringVarP(&configFile, "config", "C", "", "configuration file")
	rootCmd.PersistentFlags().BoolVarP(&debug, "debug", "d",
		false, "debug output, default: 'false'")
	rootCmd.PersistentFlags().StringVarP(&logFile, "log", "L", "",
		"log file, default: 'stdout'")

	// please note that configuration should be load later
	// as we have log, config and debug flags override
	// cases
	c = controller.NewController()

	var options controller.ConfigOptions
	options.ConfigFile = *config

	// loading configuration (got name from config variable)
	err := c.LoadConfig(&options)
	if err != nil {
		c.L().Errorf("error loading configuration from:'%s', err:'%s'",
			options.ConfigFile, err)
		os.Exit(1)
	}

	// setting logfile
	logFile = *log
	err = c.CreateLogger(logFile, debug)
	if err != nil {
		fmt.Printf("error creating log, err:'%s'\n", err)
		os.Exit(1)
	}

	// creating plugins here as we need cobra initialization
	// entry point to each plugin for command line switches

	err = c.CreatePlugins(&controller.PluginsOptions{Root: rootCmd})
	if err != nil {
		c.L().Errorf("error creating plugins configuration from:'%s', err:'%s'",
			options.ConfigFile, err)
		os.Exit(1)
	}

	versionCmd := cmdVersion{g: c}
	rootCmd.AddCommand(versionCmd.Command())

	serverCmd := cmdServer{g: c}
	rootCmd.AddCommand(serverCmd.Command())

	// completionCmd represents the completion command
	var completionCmd = &cobra.Command{
		Use:    "completion",
		Hidden: true,
		Short:  "Generates bash completion scripts",
		Long: `To load completion run

. <(bitbucket completion)

To configure your bash shell to load completions for each session add to your bashrc

# ~/.bashrc or ~/.profile
. <(bitbucket completion)
`,
		Run: func(cmd *cobra.Command, args []string) {
			if err := rootCmd.GenBashCompletion(os.Stdout); err != nil {
				fmt.Printf("error generating bash completion, err:'%s'", err)
				return
			}
		},
	}

	rootCmd.AddCommand(completionCmd)
}
