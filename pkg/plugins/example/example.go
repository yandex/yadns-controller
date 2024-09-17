package example

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/slayer1366/yadns-controller/pkg/plugins"
	"github.com/slayer1366/yadns-controller/pkg/plugins/metrics"
)

func (t *TExamplePlugin) Run(ctx context.Context, overrides *plugins.OverrideOptions) error {
	id := "(example) (run)"

	t.G().L.Debugf("%s starting", id)

	w, ctx := errgroup.WithContext(ctx)

	// placeholder to periodic tasks within server context
	// also some actions could be done in worker context
	w.Go(func() error {
		return t.TickServer(ctx)
	})

	// in example we have only one periodic task
	return w.Wait()
}

func (t *TExamplePlugin) TickServer(ctx context.Context) error {
	id := "(example) (tick)"

	interval := DefaultWatcherInterval
	watcher := t.L().Watcher
	if watcher.Interval > 0 {
		interval = watcher.Interval
	}

	counter := 0
	timer := time.NewTicker(time.Duration(interval) * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			t.G().L.Debugf("%s tick counter:'%d' update server", id, counter)

			err := t.RunCommand()
			if err != nil {
				t.G().L.Errorf("%s error on running command, err:'%s'", id, err)
				continue
			}

			t.P().M().(*metrics.TMetricsPlugin).Push(metrics.MetricsCounter,
				[]string{fmt.Sprintf("name=%s", MetricNameCounter), "type=example"},
				float64(counter))

			counter++

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t *TExamplePlugin) RunCommand() error {

	id := "(example) (run) (command)"
	var err error

	// example command: getting pluging configuration
	// option (enable/disable), getting global
	// configuration opions and print them
	runtime := t.G().Runtime
	t.G().L.Debugf("%s global runtime hostname:'%s' useragent:'%s'", id,
		runtime.Hostname, runtime.GetUseragent())

	local := t.L()
	t.G().L.Debugf("%s local plugin config:'%s'", id, local.Watcher.String())

	return err
}
