package timed

import (
	"sync"
	"time"

	"goPSLoginServer/utils"
	"goPSLoginServer/utils/logging"
)

type Timed struct {
	running         bool
	ticker          *time.Ticker
	terminationChan chan bool
	tickerDuration  time.Duration
	f               func()
	loop            func()
	ttl             int64
	startTTL        int64
	wg              sync.WaitGroup
}

// Once
//
// Calling a callback once
func Once(duration time.Duration, f func()) (timer *time.Timer) {

	return time.AfterFunc(duration, f)
}

// New
//
// Creates and returns a Timed instance running until manually stopped.
func New(duration time.Duration, f func()) (timed *Timed) {

	timed = &Timed{
		running:         false,
		ticker:          &time.Ticker{},
		terminationChan: make(chan bool),
		tickerDuration:  duration,
		f:               f,
		ttl:             -1,
		startTTL:        -1,
		wg:              sync.WaitGroup{},
	}

	timed.loop = func() {

		timed.wg.Done()

		for {
			select {
			case <-timed.terminationChan:
				return
			case <-timed.ticker.C:
				logging.Verbosef("TICKED %s", utils.GetFunctionName(f))
				f()
			}
		}
	}

	return
}

// NewTTL
//
// Creates and returns a Timed instance running until manually stopped or TTL reaching 0.
func NewTTL(duration time.Duration, f func(), ttl int64) (timed *Timed) {

	timed = &Timed{
		running:         false,
		ticker:          &time.Ticker{},
		terminationChan: make(chan bool),
		tickerDuration:  duration,
		f:               f,
		ttl:             ttl,
		startTTL:        ttl,
		wg:              sync.WaitGroup{},
	}

	timed.loop = func() {

		timed.wg.Done()

		for {
			select {
			case <-timed.terminationChan:
				// input from termination channel
				return

			case <-timed.ticker.C:
				// input from ticker

				logging.Verbosef("TICKED %s", utils.GetFunctionName(f))
				f()

				// handle TTL
				if timed.ttl > 0 {

					// TTL has not ended yet
					timed.ttl -= 1

					// stop Timed if TTL ended
					if timed.ttl == 0 {
						timed.Stop()
						return
					}
				}
			}
		}
	}

	return
}

// Start
//
// Starts the Timed instance.
// If running already it will be stopped first.
func (t *Timed) Start() {

	logging.Debugf("Starting Timed for function %s", utils.GetFunctionName(t.f))

	// stop previous ticker
	t.Stop()

	// prevent channel access before go routine is run
	t.wg.Add(1)

	// start new loop
	go t.loop()

	// wait for go routine
	t.wg.Wait()

	// start ticker
	t.ticker = time.NewTicker(t.tickerDuration)

	t.running = true
}

func (t *Timed) Stop() {

	if !t.running {
		return
	}

	logging.Debugf("Stopping Timed for function %s", utils.GetFunctionName(t.f))

	t.ticker.Stop()
	t.terminationChan <- true
}
