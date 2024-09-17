package offloader

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/slayer1366/yadns-controller/pkg/internal/config"
)

type TConfigNetdevProg struct {
	ID    int    `json:"id"`
	Jited int    `json:"jited"`
	Tag   string `json:"tag"`
}

type TConfigNetdev struct {
	Address   string            `json:"address"`
	Broadcast string            `json:"broadcast"`
	Flags     []string          `json:"flags"`
	Group     string            `json:"group"`
	Ifindex   int               `json:"ifindex"`
	Ifname    string            `json:"ifname"`
	Mtu       int               `json:"mtu"`
	Operstate string            `json:"operstate"`
	Xdp       *TConfigNetdevXdp `json:"xdp"`
}

type TConfigNetdevXdp struct {
	Mode int               `json:"mode"`
	Prog TConfigNetdevProg `json:"prog"`

	Attached []TConfigNetdevXdp `json:"attached"`
}

func (t *TOffloaderPlugin) MountBpffs() error {
	id := "(offloader) (bpffs)"
	var err error

	// getting capabilities could be useful for some other
	// checks or prereqs, such as cap_sys_admin

	capsh := "/usr/sbin/capsh"
	command := []string{"--print"}

	t.G().L.Debugf("%s getting capabilities  via '%s' ['%s']", id,
		capsh, strings.Join(command, ","))

	var output []byte
	if output, err = exec.Command(capsh, command...).CombinedOutput(); err != nil {
		t.G().L.DumpBytes(id, output, 0)
		t.G().L.Errorf("%s error executing command, err:'%s'", id, err)
		return err
	}
	t.G().L.DumpBytes(id, output, 0)

	cat := "/usr/bin/cat"
	command = []string{"/proc/mounts"}

	t.G().L.Debugf("%s checking of bpf mounted via '%s' ['%s']", id,
		cat, strings.Join(command, ","))

	if output, err = exec.Command(cat, command...).CombinedOutput(); err != nil {
		t.G().L.DumpBytes(id, output, 0)
		t.G().L.Errorf("%s error executing command, err:'%s'", id, err)
		return err
	}
	t.G().L.DumpBytes(id, output, 0)

	rows := strings.Split(string(output), "\n")
	for _, row := range rows {
		if len(row) > 0 && strings.Contains(row, "bpf") {
			t.G().L.Debugf("%s bpffs detected as:'%s' mounted: OK", id, row)
			return nil
		}
	}

	// we should mount bppfs
	mount := "/usr/bin/mount"
	command = []string{"-t", "bpf", "sysfs", "/sys/fs/bpf", "-o",
		"rw,nosuid,nodev,noexec,relatime,mode=700"}

	t.G().L.Debugf("%s mounting bpf mounted via '%s' ['%s']", id,
		mount, strings.Join(command, ","))

	if output, err = exec.Command(mount, command...).CombinedOutput(); err != nil {
		t.G().L.DumpBytes(id, output, 0)
		t.G().L.Errorf("%s error executing command, err:'%s'", id, err)
		return err
	}
	t.G().L.DumpBytes(id, output, 0)

	return nil
}

func (t *TXdpService) DetectLoaderMode(netdev string) (int, error) {
	id := "(offloader) (loader)"
	var err error

	// detecting environment configuration, if we have
	// hook pin set and if we have xdp program loaded
	pinpath := t.p.L().Loader.Hook.PinPath

	mode := LoaderModePrimary
	if len(pinpath) == 0 {
		// fallback to default mode, we assume that
		// default it "primary"
		return mode, err
	}

	pinexists := config.Exists(pinpath)
	t.p.G().L.Debugf("%s hook pinpath:'%s' exists:'%t' ", id, pinpath, pinexists)

	// detecting if some xdp program already exists
	// /usr/sbin/ip -j link list  dev eth0

	// Untarring snapshot into temporary directory if
	// not supplied as snapshot remote recevied?
	binary := DefaultIPBinary
	var params []string
	params = append(params, "-j")
	params = append(params, "link")
	params = append(params, "list")
	params = append(params, "dev")
	params = append(params, netdev)
	t.p.G().L.Debugf("%s %s command ['%s']", id, binary, strings.Join(params, " "))

	var content []byte
	if content, err = exec.Command(binary, params...).CombinedOutput(); err != nil {
		t.p.G().L.Errorf("%s error running, err:'%s'", id, err)
		t.p.G().L.DumpBytes(id, content, 0)
		return mode, err
	}
	t.p.G().L.DumpBytes(id, content, 0)

	var configs []TConfigNetdev
	if err = json.Unmarshal(content, &configs); err != nil {
		t.p.G().L.Errorf("%s json error unmarshall, err:'%s'", id, err)
		return mode, err
	}
	t.p.G().L.Debugf("%s number configs:'%d'", id, len(configs))

	if len(configs) == 0 {
		err = fmt.Errorf("no configuration found dev:'%s'", netdev)
		t.p.G().L.Errorf("%s error netdev detection, err:'%s'", id, err)
		return mode, err
	}
	netconfig := configs[0]
	xdploaded := netconfig.Xdp != nil
	t.p.G().L.Debugf("%s xdploaded on dev:'%s' '%t'", id, netdev, xdploaded)

	if !pinexists && xdploaded {
		// It could be primary program loaded (assuming
		// that it's dnsguard
		assume := true
		if !assume {
			err = fmt.Errorf("error on configuration found dev:'%s' pin:'%t' xdp:'%t'",
				netdev, pinexists, xdploaded)
			t.p.G().L.Errorf("%s error netdev detection, err:'%s'", id, err)
			return mode, err
		}
		t.p.G().L.Debugf("%s hook pinpath:'%s' pinexists:'%t' xdploaded:'%t'",
			id, pinpath, pinexists, xdploaded)

	}

	if !pinexists && !xdploaded {
		// no pinning hook map and no loaded program,
		// it means that we primary
		return LoaderModePrimary, err
	}

	if pinexists && xdploaded {
		// secondary should expect that pin hook exists
		// and xdp program loaded (primary bpf)
		return LoaderModeSecondary, err
	}

	return mode, err
}

func (t *TXdpService) GetConfiguredIP(name string) (map[string]TAddr, error) {
	id := "(xdp) (config)"

	var err error
	nets := make(map[string]TAddr)
	for _, addr := range t.options.Addrs {
		var ip IPNet
		if err = ip.UnmarshalText([]byte(addr)); err != nil {
			t.p.G().L.Errorf("%s configuration error addr:'%s' could not be unmarshalled, err:'%s'",
				id, addr, err)
			return nets, err
		}

		switch ip.Bits {
		case 128:
			if name == "daddr6_pass" {
				nets[ip.IP.String()] = TAddr{network: ip, value: DefaultDstValue}
			}
		case 32:
			if name == "daddr4_pass" {
				nets[ip.IP.String()] = TAddr{network: ip, value: DefaultDstValue}
			}
		}
	}
	return nets, nil
}

const (
	ActionRemove = 0
	ActionCreate = 1
)

func ActionAsString(action int) string {
	names := map[int]string{
		ActionRemove: "REMOVE",
		ActionCreate: "CREATE",
	}
	return names[action]
}

// T.B.D. adding value compare
func (t *TXdpService) GetConfiguredActions(src map[string]TAddr,
	dst map[string]TAddr) map[int][]TAddr {

	actions := make(map[int][]TAddr)

	for k, v := range src {
		if _, ok := dst[k]; !ok {
			actions[ActionCreate] =
				append(actions[ActionCreate], v)
			continue
		}

		// checking if value is the same
		w := dst[k]
		if v.Value() != w.Value() {
			actions[ActionRemove] =
				append(actions[ActionRemove], w)
			actions[ActionCreate] =
				append(actions[ActionCreate], v)
		}
	}

	for k, v := range dst {
		if _, ok := src[k]; !ok {
			actions[ActionRemove] =
				append(actions[ActionRemove], v)
		}
	}

	return actions
}

func (t *TXdpService) ApplyActions(name string, passmap PassMap,
	actions map[int][]TAddr) error {

	id := "(xdp) (actions)"

	types := []int{ActionRemove, ActionCreate}
	for _, tt := range types {
		for i, action := range actions[tt] {
			var err error
			t.p.G().L.Debugf("%s %s '%s' [%d]/[%d] %s", id, name, ActionAsString(tt), i,
				len(actions[tt]), action.network.AsString())

			dir := ""
			switch tt {
			case ActionRemove:
				dir = "DOWN"
				err = passmap.Remove(action)
			case ActionCreate:
				dir = "UP"
				err = passmap.Update(action)
			}

			if err != nil {
				t.p.G().L.Errorf("%s error on action name:'%s' action:'%s v:'%d'', err:'%s'",
					id, name, action.network.AsString(),
					action.Value(), err)
				return err
			}

			t.p.G().L.Debugf("%s dst addr:'%s v:'%d'' set to %s", id,
				action.network.IP.String(), action.Value(), dir)
		}
	}
	return nil
}

func (t *TXdpService) SyncPassMap(tag string, names []string, srcs map[string]map[string]TAddr) error {
	id := "(xdp) (service) (pass) (map)"

	var err error

	// we need sync src and dst maps, reading first current
	// bpf pass map content and detecting the difference (as usual)

	var daddrmaps map[string]map[string]TAddr
	var daddrs map[string]PassMap
	if daddrmaps, daddrs, err = t.GetPassMaps(tag, names); err != nil {
		t.p.G().L.Errorf("%s error getting pass map names:['%s'], err:'%s'", id,
			strings.Join(names, ","), err)
		return err
	}

	for _, name := range names {

		if _, ok := daddrmaps[name]; !ok {
			err = fmt.Errorf("no map:'%s' found", name)
			t.p.G().L.Errorf("%s error getting entries from name:'%s', err:'%s'", id, name, err)
			return err
		}

		dst := daddrmaps[name]
		t.p.G().L.Debugf("%s tag:'%s' received entries:'%d' from map:'%s'",
			id, tag, len(dst), name)

		count := 0
		for _, net := range dst {
			t.p.G().L.Debugf("%s tag:'%s' map:'%s' (dump) [%d]/[%d] %s", id, tag, name,
				count, len(dst), net.network.AsString())
			count++
		}

		if _, ok := srcs[name]; !ok {
			// possible that only IPv6 map exists, so IPv4 is failed here
			t.p.G().L.Debugf("%s tag:'%s' getting configured IP name:'%s' family class not found",
				id, tag, name)

			if len(dst) > 0 {
				// it means that destination has some data but
				// source is not defined
				t.p.G().L.Errorf("%s configured name:'%s' dst:'%d' src not found",
					id, name, len(dst))
			}
			continue
		}
		src := srcs[name]

		t.p.G().L.Debugf("%s tag:'%s' received configured entries:'%d' from map:'%s'",
			id, tag, len(src), name)

		actions := t.GetConfiguredActions(src, dst)

		remove := len(actions[ActionRemove])
		create := len(actions[ActionCreate])

		t.p.G().L.Debugf("%s tag:'%s' '%s' actions detected create:'%d' remove:'%d'",
			id, tag, name, create, remove)

		if remove+create == 0 {
			t.p.G().L.Debugf("%s tag:'%s' '%s' dst IP configuration synced: OK", id, tag, name)
			continue
		}

		if err = t.ApplyActions(name, daddrs[name], actions); err != nil {
			t.p.G().L.Errorf("%s error applying action name:'%s', err:'%s'", id, name, err)
			return err
		}
	}
	if t.options != nil {
		// some strange code?
		for _, addr := range t.options.Addrs {

			var ip IPNet
			if err = ip.UnmarshalText([]byte(addr)); err != nil {
				t.p.G().L.Errorf("%s configuration error addr:'%s' could not be unmarshalled, err:'%s'",
					id, addr, err)
				return err
			}

			name := ""
			switch ip.Bits {
			case 128:
				name = "daddr6_pass"
			case 32:
				name = "daddr4_pass"
			}

			if len(name) == 0 {
				err = fmt.Errorf("no family found")
				t.p.G().L.Errorf("%s configuration error addr:'%s' could not be matched to ip familty, err:'%s'",
					id, addr, err)
				return err
			}

			if err = daddrs[name].Update(TAddr{network: ip, value: DefaultDstValue}); err != nil {
				t.p.G().L.Errorf("%s error on update dst addr:'%s' name:'%s', err:'%s'",
					id, addr, name, err)
				return err
			}

			t.p.G().L.Debugf("%s dst addr:'%s' set to UP", id, addr)
		}
	}
	// closing maps only in mapped case for ssel names in pinned mode
	for _, name := range names {
		if err = daddrs[name].Close(); err != nil {
			t.p.G().L.Errorf("%s error on close map name:'%s', err:'%s'",
				id, name, err)
			return err
		}
	}

	return err
}

type RuntimeConfigOptions struct {
	BpfConstantBpfDyrun bool
}

func (t *TXdpService) SetDryrun(dryrun bool) error {
	options := RuntimeConfigOptions{
		BpfConstantBpfDyrun: dryrun,
	}
	return t.SyncRuntimeConfigMap(&options)
}

func (t *TXdpService) GetRuntimeConfigMap() ([]uint32, error) {
	id := "(xdp) (get) (map)"

	var err error

	var configmap JericoRuntimeConfig
	configmap.PinPath = t.p.L().Options.PinPath
	if err = configmap.LoadPinnedMap(); err != nil {
		t.p.G().L.Errorf("%s error load pinned map by name:'%s', err:'%s'", id, configmap.MapName(), err)
		return []uint32{}, err
	}
	defer configmap.Close()

	return configmap.Entries()
}

func (t *TXdpService) SyncRuntimeConfigMap(options *RuntimeConfigOptions) error {
	id := "(xdp) (sync) (map)"

	var err error

	var configmap JericoRuntimeConfig
	configmap.PinPath = t.p.L().Options.PinPath
	if err = configmap.LoadPinnedMap(); err != nil {
		t.p.G().L.Errorf("%s error load pinned map by name:'%s', err:'%s'", id, configmap.MapName(), err)
		return err
	}
	defer configmap.Close()

	configs := []int{JericoRuntimeConfigDryrun}
	for _, c := range configs {
		switch c {
		case JericoRuntimeConfigDryrun:
			value := uint32(0)
			if options.BpfConstantBpfDyrun {
				value = 1
			}

			t.p.G().L.Debugf("%s setting id:'%d' to value:'%d'", id, c, value)
			if err = configmap.Update(uint32(JericoRuntimeConfigDryrun), value); err != nil {
				t.p.G().L.Errorf("%s error updating config:'%s', err:'%s'", id,
					configmap.MapName(), err)
				return err
			}
		}
	}

	return err
}
