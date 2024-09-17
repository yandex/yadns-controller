package offloader

import (
	"context"
	"fmt"
	"time"

	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"

	"github.com/yandex/yadns-controller/pkg/plugins"
	"github.com/yandex/yadns-controller/pkg/plugins/metrics"
)

func (t *TOffloaderPlugin) Run(ctx context.Context, overrides *plugins.OverrideOptions) error {
	id := "(offloader) (run)"

	if overrides != nil {
		if len(overrides.Bpf) > 0 {
			t.c.Options.Path = overrides.Bpf
		}
	}

	t.G().L.Debugf("%s starting", id)

	// we have some prerequisite options for different
	// environment, e.g. creating bpffs or set unlimit
	// memlock
	controls := t.L().Controls

	if controls.Bpffs {
		// bpffs mount requested (in some cases we
		// need mount it as operation system in
		// container/docker did not do such things)
		t.G().L.Debugf("%s requesting bpf fs mount", id)

		err := t.MountBpffs()
		if err != nil {
			t.G().L.Errorf("%s error mounting bpffs, err:'%s'", id, err)
			return err
		}
	}

	if controls.UnlimitMemlock {
		// setting unlimitted lock for 5.4 kernel and map TRIE
		// something strange is going on without
		// memlock infinity
		t.G().L.Debugf("%s requesting unlimiting mem lock", id)

		err := unix.Setrlimit(unix.RLIMIT_MEMLOCK, &unix.Rlimit{
			Cur: unix.RLIM_INFINITY,
			Max: unix.RLIM_INFINITY,
		})
		if err != nil {
			t.G().L.Errorf("%s failed to set rlimit mem lock, err:'%s'", id, err)
			return err
		}
	}

	var err error
	if t.xdp, err = NewXdpService(t); err != nil {
		t.G().L.Errorf("%s error creating xdp service, err:'%s'", id, err)
		return err
	}

	w, ctx := errgroup.WithContext(ctx)

	// starting main XDP thread
	w.Go(func() error {
		t.G().L.Debugf("%s starting worker", id)
		defer t.G().L.Debugf("%s worker stopped", id)
		defer func() {
			if err := t.Stop(); err != nil {
				t.G().L.Debugf("%s error closing worker program, err:'%s'", id, err)
			}
		}()
		return t.xdp.Run(ctx)
	})

	// placeholder to periodic tasks within server context
	// also some actions could be done in worker context
	w.Go(func() error {
		return t.TickServer(ctx)
	})

	// in offloader we have only one periodic task
	return w.Wait()
}

func (t *TOffloaderPlugin) TickServer(ctx context.Context) error {
	id := "(offloader) (tick)"

	interval := DefaultWatcherInterval

	counter := 0
	timer := time.NewTicker(time.Duration(interval) * time.Second)
	defer timer.Stop()

	for {
		select {
		case <-timer.C:
			t.G().L.Debugf("%s tick counter:'%d' update server", id, counter)

			t.P().M().(*metrics.TMetricsPlugin).Push(metrics.MetricsCounter,
				[]string{fmt.Sprintf("name=%s", MetricNameCounter), "type=offloader"},
				float64(counter))

			counter++

		case <-ctx.Done():
			return ctx.Err()
		}
	}
}

func (t *TOffloaderPlugin) Stop() error {
	return t.xdp.Stop()
}
