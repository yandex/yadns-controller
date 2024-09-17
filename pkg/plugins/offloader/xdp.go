package offloader

import (
	"context"
	"fmt"
	"net"
	"os"
	"strings"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"golang.org/x/sync/errgroup"

	"github.com/slayer1366/yadns-controller/pkg/internal/config"
)

const (
	// default interface to bind if no options
	// provided
	DefaultInterface = "lo"

	// default bpf object file
	DefaultPath = "/usr/lib/yadns-xdp.bpf.o"

	// default pin path, for now we have to check
	// if it exists - use it, if not, create a path
	DefaultOffloaderPinPath = "/sys/fs/bpf/xdp/globals"

	// Response case flags: AA, RD, MBZ
	FlagAA  = "AA"
	FlagRD  = "RD"
	FlagMBZ = "MBZ"

	// prefix used for bpf program flag name
	PrefixFlag = "yadns_xdp_resp_flag_"

	// a list of constants to set
	BpfConstantRespRandomTTL = "yadns_xdp_resp_random_ttl"

	BpfConstantMetricsEnabled = "yadns_xdp_bpf_metrics_enabled"
	BpfConstantXdpcapEnabled  = "yadns_xdp_bpf_xdpcap_enabled"
	BpfConstantBpfDyrun       = "yadns_xdp_bpf_dryrun"

	// a list of loader mode, could be
	// primary or secondary, via "auto"
	LoaderModePrimary = 100

	// secondary mode also could be set
	// via "auto"
	LoaderModeSecondary = 101

	// default pin path for exported hook
	// from primary
	DefaultHookPinPath = "/sys/fs/bpf/xdp/bpftail-call/xdpcap_hook"

	// default list of xdp actions to set
	DefaultAction = xdpPass

	// default binary IP
	DefaultIPBinary = "/usr/sbin/ip"

	// a list of mode loader
	LoaderConfigModePrimary = "primary"

	LoaderConfigModeSecondary = "secondary"

	LoaderConfigModeAuto = "auto"

	//default value for dst address as value
	DefaultDstValue = 0
)

type xdpAction int

const (
	xdpAborted xdpAction = iota
	xdpDrop
	xdpPass
	xdpTx
	xdpRedirect
	xdpUnknown
)

func XdpActionAsString(action xdpAction) string {
	names := map[xdpAction]string{
		xdpAborted:  "XDP_ABORTED",
		xdpDrop:     "XDP_DROP",
		xdpPass:     "XDP_PASS",
		xdpTx:       "XDP_TX",
		xdpRedirect: "XDP_REDIRECT",
	}

	if _, ok := names[action]; ok {
		return names[action]
	}
	return ""
}

func StringAsXdpAction(action string) xdpAction {
	actions := map[string]xdpAction{
		"XDP_ABORTED":  xdpAborted,
		"XDP_DROP":     xdpDrop,
		"XDP_PASS":     xdpPass,
		"XDP_TX":       xdpTx,
		"XDP_REDIRECT": xdpRedirect,
	}

	if _, ok := actions[action]; ok {
		return actions[action]
	}
	return xdpUnknown
}

func LoaderModeAsString(mode int) string {
	names := map[int]string{
		LoaderModePrimary:   "primary",
		LoaderModeSecondary: "secondary",
	}
	if _, ok := names[mode]; ok {
		return names[mode]
	}
	return ""
}

type TXdpServiceFlags struct {
	// some xdp attach flags
	Flags link.XDPAttachFlags
}

type TXdpCiliumBinary struct {

	// used in load and assign bpf call
	// also could be set with maps
	Program *ebpf.Program `ebpf:"xdp_dns"`

	// a list of ebpf maps for each type RR
	MapA RRMapA

	MapAAAA RRMapAAAA

	// a list of maps with dst addr
	MapPass4 PassMap4
	MapPass6 PassMap6
}

type TXdpService struct {
	// main binary xdp
	binary *TXdpCiliumBinary

	// some service flags
	flags TXdpServiceFlags

	// options from configuration
	options *TConfigOptions

	// possible xdp modes: primary and secondary
	// primary makes XDP program be attached to
	// interface and secondary waits for bpf program
	// to be attached to exported hook map
	mode int

	// ref to plugin
	p *TOffloaderPlugin
}

func NewXdpService(p *TOffloaderPlugin) (*TXdpService, error) {
	id := "(xdp) (service)"

	var err error
	var xdp TXdpService

	// using "generic" method to load xdp, see
	// "uapi/linux/if_link.h" for other options
	xdp.flags.Flags = 0x02

	options := p.L().Options
	xdp.options = &options

	// setting some default options
	if len(xdp.options.Interface) == 0 {
		xdp.options.Interface = DefaultInterface
	}
	if len(xdp.options.PinPath) == 0 {
		xdp.options.PinPath = DefaultOffloaderPinPath
	}
	if len(xdp.options.Path) == 0 {
		xdp.options.Path = DefaultPath
	}

	xdp.p = p

	mode := LoaderModePrimary
	if mode, err = xdp.DetectLoaderMode(xdp.options.Interface); err != nil {
		p.G().L.Errorf("%s error detecting loader mode, err:'%s'", id, err)
		return nil, err
	}

	// need resolve auto mode and check conditions
	// for mode requested in configuration
	loader := p.L().Loader

	switch loader.Mode {
	case LoaderConfigModePrimary:
		if mode != LoaderModePrimary {
			err = fmt.Errorf("loader config mode:'%s' failed", loader.Mode)
			return nil, err
		}
		mode = LoaderModePrimary
	case LoaderConfigModeSecondary:
		if mode != LoaderModeSecondary {
			err = fmt.Errorf("loader config mode:'%s' failed", loader.Mode)
			return nil, err
		}
	case LoaderConfigModeAuto:
		if mode != LoaderModeSecondary && mode != LoaderModePrimary {
			err = fmt.Errorf("loader config mode:'%s' failed", loader.Mode)
			return nil, err
		}
	default:
		err = fmt.Errorf("loader config mode:'%s' failed", loader.Mode)
		return nil, err
	}

	xdp.mode = mode

	p.G().L.Debugf("%s environment mode:'%s' effective requested mode:'%s'",
		id, LoaderModeAsString(xdp.mode), loader.Mode)

	p.G().L.Debugf("%s service request interface:'%s' via path:'%s' options %s", id,
		xdp.options.Interface, xdp.options.Path, options.String())

	p.G().L.Debugf("%s pinpath:'%s'", id, xdp.options.PinPath)

	// checking if pinpath exists, and create it
	pinpath := xdp.options.PinPath
	if err = os.MkdirAll(pinpath, os.ModePerm); err != nil {
		p.G().L.Errorf("%s error create pinpath:'%s', err:'%s'",
			id, pinpath, err)
		return nil, err
	}

	// should we check if file exists?
	spec, err := ebpf.LoadCollectionSpec(xdp.options.Path)
	if err != nil {
		p.G().L.Errorf("%s error loading spec bpf:'%s', err:'%s'", id, xdp.options.Path, err)
		return nil, err
	}

	consts := make(map[string]interface{})

	// setting configured response flags
	flags := []string{FlagAA, FlagRD, FlagMBZ}
	for _, flag := range flags {
		if config.StringInSlice(flag, options.ResponseFlags) {
			fid := fmt.Sprintf("%s%s", PrefixFlag, strings.ToLower(flag))
			consts[fid] = true
		}
	}

	// setting corrseponding constants to configuration values
	consts[BpfConstantRespRandomTTL] = false
	if options.ResponseRandomTTL {
		consts[BpfConstantRespRandomTTL] = true
	}

	consts[BpfConstantMetricsEnabled] = false
	if options.BpfMetrics {
		consts[BpfConstantMetricsEnabled] = true
	}

	consts[BpfConstantXdpcapEnabled] = false
	if options.BpfXdpcap {
		consts[BpfConstantXdpcapEnabled] = true
	}

	consts[BpfConstantBpfDyrun] = false
	if options.BpfDryrun {
		consts[BpfConstantBpfDyrun] = true
	}

	for k, v := range consts {
		p.G().L.Debugf("%s setting BPF constants '%s' -> '%t'", id, k, v)
	}

	err = spec.RewriteConstants(consts)
	if err != nil {
		p.G().L.Errorf("%s error rewriting constants, err:'%s'", id, err)
		return nil, err
	}

	// loading binary
	var binary TXdpCiliumBinary

	opts := ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: pinpath,
		},
	}

	if err = spec.LoadAndAssign(&binary, &opts); err != nil {
		p.G().L.Errorf("%s error loading and assigning bpf:'%s', err:'%s'",
			id, xdp.options.Path, err)
		return nil, err
	}

	// checking bpf maps
	bpfmaps := []string{"yadns_xdp_rr_a", "yadns_xdp_rr_aaaa", "daddr4_pass", "daddr6_pass"}
	for _, bpfmap := range bpfmaps {
		if _, ok := spec.Maps[bpfmap]; !ok {
			err = fmt.Errorf("no bpf map:'%s' detected", bpfmap)
			p.G().L.Errorf("%s error detecting ebpf map:'%s', err:'%s'", id, bpfmap, err)
			return nil, err
		}
	}

	// configuration map initialization
	names := []string{"daddr4_pass", "daddr6_pass"}

	srcs := make(map[string]map[string]TAddr)
	for _, name := range names {
		src, err := xdp.GetConfiguredIP(name)
		if err != nil {
			p.G().L.Errorf("%s error getting configured IP name:'%s', err:'%s'", id, name, err)
			return nil, err
		}
		srcs[name] = src
	}

	if err = xdp.SyncPassMap("", names, srcs); err != nil {
		p.G().L.Errorf("%s error syncing pass map, err:'%s'", id, err)
		return nil, err
	}

	values := RuntimeConfigOptions{
		BpfConstantBpfDyrun: options.BpfDryrun,
	}

	if err = xdp.SyncRuntimeConfigMap(&values); err != nil {
		p.G().L.Errorf("%s error syncing configuration map, err:'%s'", id, err)
		return nil, err
	}

	p.G().L.Debugf("%s bpf:'%s' loaded OK", id, xdp.options.Path)

	xdp.binary = &binary

	return &xdp, err
}

func (t *TXdpService) Stop() error {
	id := "(xdp) (service) (stop)"
	t.p.G().L.Debugf("%s request to stop service", id)
	return t.binary.Program.Close()
}

// taken for xdpcap
// no good way to check if a program is already attached, as Create() doesn't
// work on prog array maps We could check if values are present for keys, but
// that's not atomic with writing a value anyways
func (t *TXdpService) AttachHook(hookMap *ebpf.Map, fd int, index int) error {
	err := hookMap.Put(int32(index), int32(fd))
	if err != nil {
		return fmt.Errorf("attaching prog fd:'%d' to hook, err:'%s'", fd, err)
	}
	return nil
}

func (t *TXdpService) SecondaryAttachHook(fd int) error {
	var err error

	id := "(xdp) (hook) (attach)"

	// waiting for secondary mode hook detaching
	loader := t.p.L().Loader
	path := DefaultHookPinPath
	if len(loader.Hook.PinPath) > 0 {
		path = loader.Hook.PinPath
	}

	hook, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		t.p.G().L.Errorf("%s error loading hook map:'%s', err:'%s'", id, path, err)
		return err
	}

	for _, index := range loader.Hook.Index {
		err = t.AttachHook(hook, fd, index)

		t.p.G().L.Debugf("%s attach fd:'0x%0x' on index:'%d'",
			id, fd, index)

		if err != nil {
			t.p.G().L.Errorf("%s error attaching hook, err:'%s'", id, err)
			return err
		}
	}

	return err
}

// Here we use dnguard style to manage xdp load and unload, see [1]
// [1] https://a.yandex-team.ru/arcadia/noc/dnsguard/pkg/internal/dnsguard/dgxdp/xdp.go#L157

func (t *TXdpService) Run(ctx context.Context) error {
	id := "(xdp) (run)"
	dev, err := net.InterfaceByName(t.options.Interface)
	if err != nil {
		t.p.G().L.Errorf("%s error detected dev by interface name:'%s', err:'%s'",
			id, t.options.Interface, err)
		return err
	}

	w, ctx := errgroup.WithContext(ctx)
	w.Go(func() error {

		switch t.mode {
		case LoaderModePrimary:
			l, err := link.AttachXDP(link.XDPOptions{
				Program:   t.binary.Program,
				Interface: dev.Index,
				Flags:     t.flags.Flags,
			})
			if err != nil {
				t.p.G().L.Errorf("%s error attching xdp to interface name:'%s' index:'%d', err:'%s'",
					id, t.options.Interface, dev.Index, err)
				return err
			}

			t.p.G().L.Debugf("%s bpf:'%s' attached to interface:'%s' OK",
				id, t.options.Path, t.options.Interface)

			defer func() {
				if err := l.Close(); err != nil {
					t.p.G().L.Errorf("%s error on detaching xdp program, err:'%s'", id, err)
					return
				}

				t.p.G().L.Debugf("%s xdp program detached from interface:'%s' OK",
					id, t.options.Interface)
			}()

			t.p.G().L.Debugf("%s bpf:'%s' on:'%s' waiting...", id, t.options.Path, t.options.Interface)

		case LoaderModeSecondary:
			// waiting for secondary mode hook detaching
			loader := t.p.L().Loader

			hook := DefaultHookPinPath
			if len(loader.Hook.PinPath) > 0 {
				hook = loader.Hook.PinPath
			}

			if err = t.SecondaryAttachHook(t.binary.Program.FD()); err != nil {
				t.p.G().L.Errorf("%s error on attaching hooke, err:'%s'", id, err)
				return err
			}

			t.p.G().L.Debugf("%s bpf:'%s' on hook:'%s' waiting...", id,
				t.options.Path, hook)
		}

		<-ctx.Done()
		t.p.G().L.Debugf("%s waited", id)

		return nil
	})

	return w.Wait()
}
