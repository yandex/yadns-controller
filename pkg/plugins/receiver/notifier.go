package receiver

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sys/unix"
)

const (
	// default number of cooker workers
	DefaultCookerWorkers = 2
)

// notifier listens for NOTIFY events from master server
// and makes SOA and or TRANSFER via AXFR or IXFR request
type NotifierWorker struct {
	p *TReceiverPlugin

	options *TConfigNotifier

	// pool of transfer workers
	pool *NotifierWorkerPool

	// ref to zones state gathered by recevier
	zones *ZonesState

	// servers to hold for shutdown in stop function
	servers []*dns.Server
}

func NewNotifierWorker(p *TReceiverPlugin, options *TConfigNotifier,
	zones *ZonesState) (*NotifierWorker, error) {

	var j NotifierWorker
	j.p = p
	j.options = options
	j.zones = zones

	return &j, nil
}

func (j *NotifierWorker) Run(ctx context.Context) error {
	id := "(notifier) (worker)"
	w, ctx := errgroup.WithContext(ctx)

	notifier := j.p.L().AxfrTransfer.Notify
	if len(notifier.Listen) > 0 {
		// dnsserver started as dns instance
		w.Go(func() error {
			defer j.p.G().L.Debugf("%s server stopped", id)

			// dns server listens for some events
			return j.NotifierServer(ctx)
		})
	}

	// also we need NotifierPool to process light
	// simple IXFR requests (need some filtering here)
	// please beware that these updates are applied
	// also later (as SOA timer expires)
	workers := notifier.Cookers.Workers
	if workers == 0 {
		workers = DefaultCookerWorkers
	}

	if workers > 0 {
		j.p.G().L.Debugf("%s request to start notify cooker workers:'%d'", id, workers)

		w.Go(func() error {
			j.p.G().L.Debugf("%s starting notifier cookers pool", id)
			defer j.p.G().L.Debugf("%s notifier cookers pool stopped", id)

			// stating axfr transfer pool
			return j.CookerPoolRun(ctx)
		})
	}
	return w.Wait()
}

func (j *NotifierWorker) CookerPoolRun(ctx context.Context) error {
	var err error
	id := "(notifier) (cooker workers)"

	notifier := j.p.L().AxfrTransfer.Notify
	workers := notifier.Cookers.Workers
	if workers == 0 {
		workers = DefaultCookerWorkers
	}
	j.p.G().L.Debugf("%s starting, workers count:'%d'", id, workers)

	j.pool = NewNotifierWorkerPool(j.p, workers, j.zones)
	go j.pool.Run(ctx)

	for {
		select {
		case r, ok := <-j.pool.Results():
			if !ok {
				j.p.G().L.Debugf("%s error on worker results", id)
				continue
			}
			if r.Error != nil {
				j.p.G().L.Errorf("%s job id:'%d' failed, err:'%s'",
					id, r.Job.ID, r.Error)
				continue
			}

			j.p.G().L.Debugf("%s result on worker:'%d' job id:'%d' processed OK, time:'%d'",
				id, r.ID, r.Job.ID, r.Processed)

		case <-ctx.Done():
			j.p.G().L.Debugf("%s context stop on thread pool", id)
			return ctx.Err()

		case <-j.pool.done:
			return err
		}
	}
}

// notifier cooker workers pool
type NotifierWorkerPool struct {
	p *TReceiverPlugin

	// job channels in both directions
	jobs    chan NotifierJob
	results chan NotifierResult

	count int

	states *ZonesState

	// channel to send done request in
	// event waiting cycle
	done chan struct{}
}

type NotifierJob struct {
	ID int64 `json:"ID"`

	ClassJob int `json:"class-job"`

	// zone to operate (transfer, dump)
	Zone string `json:"zone"`

	// serial number to make a IXFR transfer
	Serial uint32 `json:"serial"`

	// states of zones
	States *ZonesState
}

func (j *NotifierJob) String() string {
	return fmt.Sprintf("id:'%d' ixfr zone:'%s' serial:'%d'",
		j.ID, j.Zone, j.Serial)
}

type NotifierResult struct {
	Job *NotifierJob `json:"job"`

	ID int64 `json:"id"`

	// error for collector result or nil
	// if all is okey
	Error error `json:"error"`

	// processed time
	Processed int64 `json:"processed"`
}

func NewNotifierWorkerPool(p *TReceiverPlugin, count int, states *ZonesState) *NotifierWorkerPool {
	return &NotifierWorkerPool{
		p:       p,
		count:   count,
		states:  states,
		jobs:    make(chan NotifierJob, count),
		results: make(chan NotifierResult, count),
		done:    make(chan struct{}),
	}
}

func (j *NotifierJob) execute(p *TReceiverPlugin, ctx context.Context,
	index int, job NotifierJob) NotifierResult {

	id := "(notifier) (cooker) (job)"
	t0 := time.Now()

	var result NotifierResult
	result.ID = time.Now().UnixNano()
	result.Job = j

	switch job.ClassJob {
	case ClassJobNotifier:

		zone := j.Zone

		if _, ok := j.States.locks[zone]; !ok {
			var lock sync.Mutex
			j.States.locks[zone] = &lock
		}

		j.States.locks[zone].Lock()
		defer j.States.locks[zone].Unlock()

		// checking if some snapshot exists in memory
		snapshot := j.States.GetLastZoneSnapshot(zone)
		if snapshot == nil {
			err := fmt.Errorf("zone:'%s' memory snapshot missed", zone)
			p.G().L.Errorf("%s worker:'%d' zone:'%s' memory snapshot not found, err:'%s'",
				id, index, zone, err)
			result.Error = err
			return result
		}

		serial, err := snapshot.Serial()
		if err != nil {
			err := fmt.Errorf("zone:'%s' snapshot serial missed", zone)
			p.G().L.Errorf("%s worker:'%d' zone:'%s' serial failed, err:'%s'",
				id, index, zone, err)
			result.Error = err
			return result
		}

		p.G().L.Debugf("%s worker:'%d' zone:'%s' memory soa:'%d' recevied notify soa:'%d'",
			id, index, zone, serial, j.Serial)

		if j.Serial <= serial && j.Serial != 0 {
			err := fmt.Errorf("zone:'%s' notify aborted as notify serial:'%d' less or equal snapshot memory:'%d'",
				zone, j.Serial, serial)
			p.G().L.Errorf("%s worker:'%d' zone:'%s' serial not changed or incorrect, err:'%s'",
				id, index, zone, err)
			result.Error = err
			return result
		}

		// getting configuration of zone
		conf, err := j.States.GetConfig(zone)
		if err != nil {
			result.Error = fmt.Errorf("error found configuratuion for zone:'%s', err:'%s'", zone, err)
			p.G().L.Errorf("%s worker:'%d' error detecting config zone:'%s', err:'%s'",
				id, index, zone, err)
			return result
		}

		if len(conf.Primary) == 0 {
			err := fmt.Errorf("zone:'%s' does not have primary defined", zone)
			p.G().L.Errorf("%s worker:'%d' zone:'%s' could not be processed, err:'%s'",
				id, index, zone, err)
			result.Error = err
			return result
		}

		// T.B.D. we use first primary server at least now
		primary := conf.Primary[0]

		opts := new(TransferOptions)
		if j.Serial > 0 {
			opts.Mode = TransferModeIXFR
			opts.Serial = serial
		}
		if j.Serial == 0 {
			opts.Mode = TransferModeAXFR
		}

		opts.Ns = snapshot.soa.(*dns.SOA).Ns

		// OMG, mailbox, :)
		opts.Mbox = snapshot.soa.(*dns.SOA).Mbox

		p.G().L.Debugf("%s worker:'%d' requesting ixfr zone:'%s' serial:'%d' ns:'%s' mbox:'%s' via primary:'%s'",
			id, index, zone, opts.Serial, opts.Ns, opts.Mbox, primary)

		// do we need request SOA to ensure serial from notify?
		// now we skip this step
		rr, err := TransferZone(primary, zone, opts)
		if err != nil {
			result.Error = fmt.Errorf("error transferring zone:'%s', err:'%s'", zone, err)
			p.G().L.Errorf("%s worker:'%d' error on notify processing zone:'%s', err:'%s'",
				id, index, zone, err)
			return result
		}
		p.G().L.Debugf("%s worker:'%d' transferred zone:'%s' as rrsets:'%d'", id, index, zone, len(rr))

		mode := TransferModeUnknown

		var soa dns.RR
		var actions *TSnapshotActions
		if soa, mode, actions, err = snapshot.ApplyIXFR(rr); err != nil {
			p.G().L.Errorf("%s error applying IXFR to AXFR for zone:'%s', err:'%s'", id, zone, err)
			result.Error = err
			return result
		}

		p.G().L.Debugf("%s worker:'%d' approved zone:'%s' '%s' received soa '%s'",
			id, index, zone, TransferModeAsString(mode),
			soa.String())

		if actions == nil {
			err := fmt.Errorf("zone:'%s' actions could not be defined", zone)
			p.G().L.Errorf("%s worker:'%d' zone:'%s' actions could not be applied, err:'%s'",
				id, index, zone, err)
			result.Error = err
			return result
		}
		actions.Dump(p)

		// we have to create new zone state and replace by
		// (taken from UpdateZoneState)
		var state TZoneState
		state.Config = conf
		state.SnapshotID = -1
		state.State = ZoneStateDirty
		state.SnapshotCount = DefaultSnapshotCount
		state.Snapshots = make(map[int]TSnapshotZone)

		snapshot.soa = soa
		snapshot.timestamp = time.Now()

		// setting imports for cooker
		imports := &TImportActions{
			mode:    TransferModeIXFR,
			zone:    zone,
			actions: actions,
		}
		snapshot.imports = imports

		snapshot.Dump(p, "(notifier) (ixfr)", DefaultDumpMaxRRsets)

		state.SnapshotID = (state.SnapshotID + 1) % state.SnapshotCount
		state.Snapshots[state.SnapshotID] = *snapshot

		state.Zone = zone
		state.State = state.DetectState(p, snapshot)

		j.States.zones[zone] = state

		p.G().L.Debugf("%s ixfr snapshot zone:'%s' updated rrsets:'%d'",
			id, zone, len(snapshot.rrsets))

		// T.B.D. cooker: applying actions right now to bpf.Map with locking per zone?
		var options TConfigCooker
		options.Dryrun = false
		cooker, _ := NewCookerWorker(p, &options, j.States)

		var r *TSyncMapResult
		if r, err = cooker.CookIncrementZone(ctx, zone, CookerNoLock); err != nil {
			p.G().L.Errorf("%s error cooking zone:'%s', err:'%s'", id, zone, err)
			result.Error = err
			return result
		}

		p.G().L.Debugf("%s ixfr applied update zone:'%s' created:'%d' removed:'%d'",
			id, zone, r.Created, r.Removed)

		if err = snapshot.WriteSnapshotZone(options.Dryrun); err != nil {
			p.G().L.Errorf("%s error writing blob for zone:'%s', err:'%s'",
				id, zone, err)
			result.Error = err
			return result
		}
	}

	result.Processed = time.Since(t0).Milliseconds()

	p.G().L.Debugf("%s worker:'%d' executed job %s in '%d' ms",
		id, index, j.String(), result.Processed)

	return result

}

func (p *NotifierWorkerPool) Run(ctx context.Context) {
	var wg sync.WaitGroup

	for i := 0; i < p.count; i++ {
		wg.Add(1)
		go p.Worker(ctx, i, &wg, p.jobs, p.results)
	}

	wg.Wait()
	close(p.done)
	close(p.results)
}

func (p *NotifierWorkerPool) Worker(ctx context.Context, index int, wg *sync.WaitGroup,
	jobs <-chan NotifierJob, results chan<- NotifierResult) {

	id := "(notifier) (cooker) (worker)"

	defer wg.Done()
	for {
		select {
		case job, ok := <-jobs:
			if !ok {
				p.p.G().L.Debugf("%s error on worker channel index '%d'", id, index)
				results <- NotifierResult{Error: ctx.Err()}
				return
			}

			// run job and receive a result from execution
			// context as collector job result
			results <- job.execute(p.p, ctx, index, job)

		case <-ctx.Done():
			p.p.G().L.Debugf("%s stopped worker on index '%d'", id, index)
			results <- NotifierResult{Error: ctx.Err()}
			return
		}
	}
}

func (p *NotifierWorkerPool) Results() <-chan NotifierResult {
	return p.results
}

func (p *NotifierWorkerPool) Job(zone string, serial uint32) {
	id := "(notifier) (job)"

	var job NotifierJob
	job.ClassJob = ClassJobNotifier

	job.Zone = zone
	job.Serial = serial
	job.ID = time.Now().UnixNano()
	job.States = p.states

	p.p.G().L.Debugf("%s push job zone:'%s' serial:'%d'", id, zone, serial)

	p.jobs <- job
}

const (
	NetUDP = "udp"
	NetTCP = "tcp"
)

type TWorkerOptions struct {
	net         string
	addr        string
	soreuseport bool
	tcpsize     int
	udpbuffer   int
}

// taken from miekg dns
func reuseportControl(network, address string, c syscall.RawConn) error {
	var opErr error
	err := c.Control(func(fd uintptr) {
		opErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
	})
	if err != nil {
		return err
	}

	return opErr
}

func (j *NotifierWorker) Worker(ctx context.Context, wg *sync.WaitGroup,
	options *TWorkerOptions) {

	id := "(notifier) (worker)"
	defer wg.Done()

	lc := &net.ListenConfig{}
	lc.Control = reuseportControl

	p, err := lc.ListenPacket(ctx, options.net, options.addr)
	if err != nil {
		j.p.G().L.Errorf("%s error creating listen on net:'%s' addr:'%s', err:'%s'",
			id, options.net, options.addr, err)
		return
	}

	server := &dns.Server{
		PacketConn: p,
		Net:        "udp",
		TsigSecret: nil,
		ReusePort:  options.soreuseport,
		UDPSize:    options.udpbuffer,
	}

	j.servers = append(j.servers, server)

	err = server.ActivateAndServe()
	if err != nil {
		j.p.G().L.Errorf("%s error starting server, err:'%s'", id, err)
		return
	}

	j.p.G().L.Debugf("%s notify worker stopped", id)
}

func (j *NotifierWorker) ReqString(w dns.ResponseWriter, r *dns.Msg, q *dns.Msg) string {

	var out []string

	// local server address to server a request
	out = append(out, fmt.Sprintf("(request) serve:'%s'",
		w.LocalAddr().String()))

	// request, cookie?
	qtype := r.Question[0].Qtype
	out = append(out, fmt.Sprintf("req: name:'%s' type:'%s'",
		r.Question[0].Name, dns.TypeToString[qtype]))

	// opcode
	out = append(out, fmt.Sprintf("opcode: '%d' '%s'", r.Opcode,
		dns.OpcodeToString[r.Opcode]))

	// request
	countr := len(r.Answer)
	var datar []string
	for _, r := range r.Answer {
		datar = append(datar, fmt.Sprintf("'%s'", strings.ReplaceAll(r.String(), "\t", " ")))
	}
	out = append(out, fmt.Sprintf("request: [%d] ['%s']", countr,
		strings.Join(datar, ",")))

	// response answer
	count := len(q.Answer)
	var data []string
	for _, r := range q.Answer {
		data = append(data, fmt.Sprintf("'%s'", strings.ReplaceAll(r.String(), "\t", " ")))
	}
	out = append(out, fmt.Sprintf("response: [%d] ['%s']", count,
		strings.Join(data, ",")))

	// response status
	out = append(out, fmt.Sprintf("status: %d %s", q.Rcode,
		dns.RcodeToString[q.Rcode]))

	// response flags
	var flags []string
	if q.Response {
		flags = append(flags, "qr")
	}
	if q.Authoritative {
		flags = append(flags, "aa")
	}
	if q.Truncated {
		flags = append(flags, "tc")
	}
	if q.RecursionDesired {
		flags = append(flags, "rd")
	}
	if q.RecursionAvailable {
		flags = append(flags, "ra")
	}
	if q.Zero { // Hmm
		flags = append(flags, "z")
	}
	if q.AuthenticatedData {
		flags = append(flags, "ad")
	}
	if q.CheckingDisabled {
		flags = append(flags, "cd")
	}

	out = append(out, fmt.Sprintf("flags: [%s]",
		strings.Join(flags, " ")))

	return strings.Join(out, ",")
}

type TMatchedRequest struct {
	zone   string
	serial uint32
}

func (j *NotifierWorker) MatchRequest(r *dns.Msg) (*TMatchedRequest, error) {
	if r == nil {
		return nil, fmt.Errorf("not request")
	}

	if r.Opcode != dns.OpcodeNotify || len(r.Question) == 0 {
		return nil, fmt.Errorf("not notify")
	}

	if len(r.Answer) > 0 {
		rr := r.Answer[0]
		if rr.Header().Rrtype == dns.TypeSOA {
			soa := rr.(*dns.SOA)
			name := RemoveDot(rr.Header().Name)

			if _, ok := j.zones.zones[name]; !ok {
				return nil, fmt.Errorf("not corrent notify")
			}

			var matched TMatchedRequest
			matched.zone = name
			matched.serial = soa.Serial

			return &matched, nil
		}
	}

	if len(r.Question) > 0 {
		rr := r.Question[0]
		if rr.Qtype != dns.TypeSOA {
			return nil, fmt.Errorf("not SOA request")
		}
		name := RemoveDot(rr.Name)
		if _, ok := j.zones.zones[name]; !ok {
			return nil, fmt.Errorf("not corrent notify")
		}

		var matched TMatchedRequest
		matched.zone = name
		matched.serial = 0

		return &matched, nil
	}

	return nil, fmt.Errorf("notify ignored")
}

func (j *NotifierWorker) Handle(w dns.ResponseWriter, r *dns.Msg) {
	id := "(notifier) (handler)"

	// need something to answer
	m := new(dns.Msg)
	m.SetReply(r)

	m.Authoritative = true
	m.RecursionAvailable = true

	// Checking for SOA record and match fqdn zone name
	// to a list of supported. All other requests and SOA
	// request should be answere as REFUSED
	matched, err := j.MatchRequest(r)
	if err != nil {
		// not matching any request sent REFUSED
		m.SetRcode(r, dns.RcodeRefused)
	}

	if matched != nil {
		// checking if notify is supported, here
		// we have new serial as matched.serial
		// and also we have blob with serial.
		// comparing it will give us difference and
		// AXFR or IXFR request
		j.p.G().L.Debugf("%s request %s matched as soa zone:'%s' serial:'%d': OK", id,
			j.ReqString(w, r, m), matched.zone, matched.serial)

		m.SetRcode(r, dns.RcodeSuccess)
	}

	buf, _ := m.Pack()
	if _, err := w.Write(buf); err != nil {
		j.p.G().L.Debugf("%s error writing buffer, err:'%s'", id, err)
	}

	if matched != nil {
		if j.pool != nil {
			// adding job to handle IXFR
			j.pool.Job(matched.zone, matched.serial)
		}
	}
}

func (j *NotifierWorker) NotifierServer(ctx context.Context) error {
	id := "(notifier) (dns)"
	var err error

	notifier := j.p.L().AxfrTransfer.Notify
	j.p.G().L.Debugf("%s listen on: ['%s']", id, strings.Join(notifier.Listen, ","))

	dns.HandleFunc(".", j.Handle)

	reuseport := notifier.Workers > 1

	protos := []string{"udp://"}
	udpbuffer := notifier.UDPBufferSize

	var wg sync.WaitGroup

	for i := 0; i < notifier.Workers; i++ {
		for _, l := range notifier.Listen {

			// checking listen address
			valid := false
			for _, proto := range protos {
				if strings.HasPrefix(l, proto) {
					valid = true
				}
			}

			if !valid {
				err = fmt.Errorf("listen definition:'%s' is not correct", l)
				j.p.G().L.Errorf("%s error starting notifier worker, err:'%s'", id, err)
				return err
			}

			tags := strings.Split(l, "://")
			if len(tags) != 2 {
				err = fmt.Errorf("listen:'%s' is not correct", l)
				j.p.G().L.Errorf("%s incorrect listen proto, expecting one of ['%s'], err:'%s'",
					id, strings.Join(protos, ","), err)
				return err
			}

			addr := tags[1]

			// T.B.D. if addr AUTOIP6 or AUTOIP4

			j.p.G().L.Debugf("%s l:'%s' addr:'%s' udpbuffer:'%d' reuseport:'%t'", id,
				l, addr, udpbuffer, reuseport)

			var options TWorkerOptions
			options.net = tags[0]
			options.addr = addr
			options.soreuseport = reuseport
			options.udpbuffer = udpbuffer

			wg.Add(1)
			go j.Worker(ctx, &wg, &options)
		}
	}

	wg.Wait()

	j.p.G().L.Debugf("%s notifier stopped", id)

	return err
}

func (j *NotifierWorker) Stop() {
	id := "(notifier) (stop)"
	j.p.G().L.Debugf("%s request to stop all dns servers notifier listeners", id)
	for _, server := range j.servers {
		if server != nil {
			err := server.Shutdown()
			if err != nil {
				j.p.G().L.Errorf("%s error shutdown dns server listener, err:'%s'", id, err)
			}
		}
	}
}
