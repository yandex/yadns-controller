package receiver

import (
	"context"
	"time"

	"golang.org/x/sync/errgroup"

	"github.com/slayer1366/yadns-controller/pkg/plugins"
)

func (t *TReceiverPlugin) TickStateStep(mode string) {
	id := "(receiver) (state) (server)"
	t.G().L.Debugf("%s tick update server %s", id, mode)

	if t.pool != nil {
		// need ref for job executed for zones state
		// and for possible sync mutex object
		t.pool.zones = t.zones
	}
	err := t.zones.Update(t.pool)
	if err != nil {
		t.G().L.Errorf("%s error on state zones update, err:'%s'", id, err)
	}
}

const (
	TickStepOnce = "once"
	TickStepNext = "next"
)

func (t *TReceiverPlugin) TickStateServer(ctx context.Context) error {
	id := "(receiver) (state) (server)"

	interval := DefaultTransfersInterval
	transfer := t.L().AxfrTransfer.Transfer
	if transfer.TransfersInterval > 0 {
		interval = time.Duration(transfer.TransfersInterval) * time.Second
	}

	timer := time.NewTicker(interval)
	defer timer.Stop()

	// first time also we need start the check
	first := make(chan bool, 1)
	first <- true

	for {
		select {
		case <-first:
			// as program started wait for some time
			time.Sleep(5 * time.Second)
			t.TickStateStep(TickStepOnce)

		case <-timer.C:
			t.TickStateStep(TickStepNext)

		case <-ctx.Done():
			t.G().L.Debugf("%s context stop on state update", id)
			return ctx.Err()
		}
	}
}

func (t *TReceiverPlugin) Run(ctx context.Context, overrides *plugins.OverrideOptions) error {
	id := "(receiver) (worker)"

	t.G().L.Debugf("%s starting", id)

	w, ctx := errgroup.WithContext(ctx)

	// starting monitoring workers: they periodically
	// checks some metrics and controller state, makes
	// some actions: (e.g. setting bpf to dryrun)
	t.watcher = NewWatcherWorker(t)
	w.Go(func() error {
		return t.watcher.Run(ctx)
	})

	t.zones = NewZonesState(t)

	transfer := t.L().AxfrTransfer
	if transfer.Enabled {
		context, cancel := context.WithCancel(ctx)
		w.Go(func() error {
			t.G().L.Debugf("%s starting transfer pool", id)

			// canceling cooker ?
			defer cancel()

			// stating axfr transfer pool
			return t.TransferPoolRun(context)
		})

		// periodic state update state for
		// transfer zones
		w.Go(func() error {
			defer t.G().L.Debugf("%s state update server stopped", id)

			// starting update zones cycle
			return t.TickStateServer(ctx)
		})

		// if we have enabled cooker we need start and
		// push to cooker zones ref
		var options TConfigCooker
		options.Dryrun = false

		t.cooker, _ = NewCookerWorker(t, &options, t.zones)

		cooker := t.L().Cooker
		if cooker.Enabled {

			// trying to explicitly call cancel
			// context for cooker (as it could last
			// very long)
			w.Go(func() error {
				defer t.cooker.Stop()

				// cooker starts on different content with
				// cancel defer function
				return t.cooker.Run(context)
			})
		}
	}

	verifier := t.L().Verifier
	if verifier.Enabled {
		w.Go(func() error {

			verifier, err := NewVerifierWorker(t, t.zones)
			if err != nil {
				t.G().L.Errorf("%s error on creating verifier worker, err:'%s'", id, err)
				return err
			}
			defer verifier.Stop()

			t.verifier = verifier
			t.cooker.verifier = verifier

			return verifier.Run(ctx)
		})
	}

	notifier := t.L().AxfrTransfer.Notify
	if len(notifier.Listen) > 0 && notifier.Enabled {
		w.Go(func() error {
			var options TConfigNotifier
			options.Dryrun = false
			notifier, err := NewNotifierWorker(t, &options, t.zones)

			if err != nil {
				t.G().L.Errorf("%s error on creating notifier worker, err:'%s'", id, err)
				return err
			}
			defer notifier.Stop()

			t.notifier = notifier
			return notifier.Run(ctx)
		})
	}

	return w.Wait()
}

func (t *TReceiverPlugin) Stop() {
	id := "(receiver) (stop)"
	t.G().L.Debugf("%s request to stop some workers", id)

	if t.notifier != nil {
		// sending request to stop all dns notifer
		// listeners servers
		t.notifier.Stop()
	}
}
