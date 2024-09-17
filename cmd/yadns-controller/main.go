// ypdns-controller manages a list of plugins for dns
// processing: xdp, bpf programs managment, data control
// metrics and monitoring

package main

import (
	"os"

	"github.com/yandex/yadns-controller/cmd/yadns-controller/cmd"
)

const (
	// error on running command
	ExitCodeUnspecified = 1
)

var (
	Version  = "dev"
	Revision = "none"
	Date     = "unknown"
)

func main() {

	cmd.SetVersion(Version, Revision)
	cmd.SetDate(Date)

	err := cmd.Execute()
	if err != nil {
		os.Exit(ExitCodeUnspecified)
	}
}
