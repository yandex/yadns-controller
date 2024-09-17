package receiver

import (
	"fmt"
	"os"
	"testing"

	"github.com/yandex/yadns-controller/pkg/internal/config"
	"github.com/yandex/yadns-controller/pkg/plugins"
)

func NewTestConfig(t *testing.T) (*config.TGlobal, error) {

	var g config.TGlobal
	var r config.TRuntime

	// runtime configuration
	r.ProgramName = config.ProgramName
	r.Hostname, _ = os.Hostname()
	g.Runtime = &r

	var err error
	if g.L, err = g.CreateLogger(nil); err != nil {
		return nil, err
	}

	return &g, err
}

var DefaultConfig = []byte(`
# global plugin enable confiugation
enabled: true
`)

func NewTestReceiverPlugin(t *testing.T) (*TReceiverPlugin, error) {
	var err error

	var options plugins.PluginOptions
	options.Name = "recevier"
	options.Type = "data"
	options.Content = DefaultConfig

	if options.Global, err = NewTestConfig(t); err != nil {
		return nil, err
	}
	options.Plugins = plugins.NewPlugins(options.Global)

	p, err := NewPlugin(&options)
	if err != nil {
		return nil, err
	}

	return p, nil
}

func TestApplyIXFR(t *testing.T) {

	p, err := NewTestReceiverPlugin(t)
	if err != nil {
		t.Error(fmt.Sprintf("Error making testing environment, err:'%s'", err))
		return
	}

	// Assuming that we have zone as text zone representation
	// in AXFR text file and
	type TTest struct {
		uuid    string
		enabled bool
		ixfr    string
		name    string
		zone    string
		err     bool
		result  string
	}

	// Below is the list of IXFR apply updates to AXFR content
	// without respect of SOA serial numbers, first we test
	// deletions, than addition and changes are the last, than
	// empty IXFR and AXFR (full, should be processed in another
	// way)
	var Tests = []TTest{
		{
			"1f6f2002-2fa9-457b-9bdc-b720fb184916",
			true,
			`tt.yandex.net.	600	IN	SOA	ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.	600	IN	SOA	ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
alpha-01v.lxd.tt.yandex.net.	617	IN	AAAA	2a02:6b8:c0e:125:0:433f:1:101
tt.yandex.net.	600	IN	SOA	ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			"tt.yandex.net",
			`tt.yandex.net.		600	IN	SOA	ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.		172801	IN	NS	ns3.yandex.ru.
tt.yandex.net.		172801	IN	NS	ns4.yandex.ru.
alpha.tt.yandex.net.	602	IN	AAAA	2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.	623	IN	CNAME	alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600	IN	AAAA	2a02:6b8:0:3400:0:45b:0:3
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:101
asrq-cache.tt.yandex.net. 600	IN	AAAA	2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.	1304	IN	AAAA	2a02:6b8:0:1a71::a652
tt.yandex.net.		600	IN	SOA	ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			false, `tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
		},
		{
			"8a598e2f-f7e2-4a88-8299-fd19b3a86595",
			true,
			`tt.yandex.net. 600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:101
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			"tt.yandex.net",
			`tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:101
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:102
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			false, `tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:102
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
		},
		{
			"4c567369-bc27-496a-96d6-a00a92a3c932",
			true,
			`tt.yandex.net. 600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			"tt.yandex.net",
			`tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:101
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			false, `tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:101
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
		},
		{
			"ad66490c-61b0-414f-bbcf-563dba3fe8a8",
			true,
			`tt.yandex.net. 600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			"tt.yandex.net",
			`tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			false, `tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
		},
		{
			"842ad0e5-8593-40c2-8f7e-a875872fbabf",
			true,
			`tt.yandex.net. 600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
alpha-01v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			"tt.yandex.net",
			`tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
alpha-01v.lxd.tt.yandex.net.    617     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			false, `tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
alpha-01v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
		},
		{
			"a2f89ef3-629c-4284-bbb2-cf1677ccebe4",
			true,
			`tt.yandex.net. 600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
alpha-01v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
alpha-02v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:104
alpha-03v.lxd.tt.yandex.net.    618     IN      A	5.255.255.70
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			"tt.yandex.net",
			`tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			false, `tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
alpha-01v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
alpha-02v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:104
alpha-03v.lxd.tt.yandex.net.    618     IN      A       5.255.255.70
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
		},
		{
			"3c9ab4b3-56f2-4ffa-bd3e-d0489d9b716c",
			true,
			`tt.yandex.net. 600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
alpha-01v.lxd.tt.yandex.net.    618     IN      CNAME	alpha-02v.lxd.tt.yandex.net.
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			"tt.yandex.net",
			`tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			false, `tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
		},
		{
			"cfb97c62-9cdf-484c-88c3-bf28bac9496b",
			true,
			`tt.yandex.net. 600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			"tt.yandex.net",
			`tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			false, `tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
		},
		{
			"72705e3d-5d94-4326-acde-1d70d81a29dc",
			true,
			`tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			"tt.yandex.net",
			`tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			false, `tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
		},
		{
			"c7afe74b-a408-43b6-a777-a879b3830749",
			true,
			`tt.yandex.net. 600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041752 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041752 900 600 3600000 300
alpha-01v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
alpha-02v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:104
alpha-03v.lxd.tt.yandex.net.    618     IN      A       5.255.255.70
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			"tt.yandex.net",
			`tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			false, `tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
alpha-01v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
alpha-02v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:104
alpha-03v.lxd.tt.yandex.net.    618     IN      A       5.255.255.70
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
		},
		{
			"54f29ed3-aace-44e8-81a5-d2fbe4cad81e",
			true,
			`tt.yandex.net. 600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041752 900 600 3600000 300
alpha-01v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041752 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
alpha-02v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:104
alpha-03v.lxd.tt.yandex.net.    618     IN      A       5.255.255.70
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041753 900 600 3600000 300
tt.yandex.net.  600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			"tt.yandex.net",
			`tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
alpha-01v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:103
alpha-02v.lxd.tt.yandex.net.    618     IN      AAAA    2a02:6b8:c0e:125:0:433f:1:104
alpha-03v.lxd.tt.yandex.net.    618     IN      A       5.255.255.70
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
			false, `tt.yandex.net.         600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300
tt.yandex.net.          172801  IN      NS      ns3.yandex.ru.
tt.yandex.net.          172801  IN      NS      ns4.yandex.ru.
alpha.tt.yandex.net.    602     IN      AAAA    2a02:6b8:b010:a4fc::a00a
*.alpha.tt.yandex.net.  623     IN      CNAME   alpha.tt.yandex.net.
rdr.alpha.tt.yandex.net. 600    IN      AAAA    2a02:6b8:0:3400:0:45b:0:3
asrq-cache.tt.yandex.net. 600   IN      AAAA    2a02:6b8:0:3400:0:45b:0:4
view.tt.yandex.net.     1304    IN      AAAA    2a02:6b8:0:1a71::a652
tt.yandex.net.          600     IN      SOA     ns3.yandex.ru. sysadmin.yandex.ru. 2017041755 900 600 3600000 300`,
		},
	}

	for _, Test := range Tests {
		if !Test.enabled {
			continue
		}

		// before test the real function we need convert a text IXFR
		// data into a list of dns.RR record sets
		ixfr, err := NewXFR(Test.ixfr)
		if err != nil {
			fmt.Printf("Test:'%s' ixfr parse FAILED (ERROR), err:'%s'\n", Test.uuid, err)
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nFOR TEST", fmt.Sprintf("\nixfr:'%s'", Test.ixfr),
				"\nEXPECTED", fmt.Sprintf("\nerr:'%t'", Test.err),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}
		fmt.Printf("Test:'%s' ixfr parsed OK, records:'%d'\n", Test.uuid, len(ixfr))

		snapshot, err := NewSnapshotZone(p, Test.zone, Test.name)
		if err != nil {
			fmt.Printf("Test:'%s' snapshot parse FAILED (ERROR), err:'%s'\n", Test.uuid, err)
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nFOR TEST", fmt.Sprintf("\nzone:'%s'", Test.zone),
				"\nEXPECTED", fmt.Sprintf("\nerr:'%t'", Test.err),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}
		fmt.Printf("Test:'%s' zone:'%s' snapshot parsed OK, records:'%d'\n", Test.uuid,
			Test.name, len(snapshot.rrsets))

		snapshot.Dump(p, "snapshot original", 20)

		soa, err := snapshot.SOA()
		if err != nil {
			fmt.Printf("Test:'%s' snapshot SOA FAILED (ERROR), err:'%s'\n", Test.uuid, err)
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nFOR TEST", fmt.Sprintf("\nzone:'%s'", Test.zone),
				"\nEXPECTED", fmt.Sprintf("\nerr:'%t'", Test.err),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}
		fmt.Printf("Test:'%s' zone:'%s' SOA:'%s'\n", Test.uuid, Test.name, soa)

		serial, err := snapshot.Serial()
		if err != nil {
			fmt.Printf("Test:'%s' snapshot serial FAILED (ERROR), err:'%s'\n", Test.uuid, err)
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nFOR TEST", fmt.Sprintf("\nzone:'%s'", Test.zone),
				"\nEXPECTED", fmt.Sprintf("\nerr:'%t'", Test.err),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}
		fmt.Printf("Test:'%s' zone:'%s' serial:'%d'\n", Test.uuid, Test.name, serial)

		refresh, err := snapshot.Refresh()
		if err != nil {
			fmt.Printf("Test:'%s' snapshot refresh FAILED (ERROR), err:'%s'\n", Test.uuid, err)
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nFOR TEST", fmt.Sprintf("\nzone:'%s'", Test.zone),
				"\nEXPECTED", fmt.Sprintf("\nerr:'%t'", Test.err),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}
		fmt.Printf("Test:'%s' zone:'%s' serial:'%d'\n", Test.uuid, Test.name, refresh)

		_, _, _, err = snapshot.ApplyIXFR(ixfr)
		if err != nil {
			fmt.Printf("Test:'%s' snapshot ixfr apply  FAILED (ERROR), err:'%s'\n", Test.uuid, err)
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nFOR TEST", fmt.Sprintf("\nixfr:'%s'", Test.ixfr),
				"\nFOR TEST", fmt.Sprintf("\nzone:'%s'", Test.zone),
				"\nEXPECTED", fmt.Sprintf("\nerr:'%t'", Test.err),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}
		snapshot.Dump(p, "snapshot modified", 20)

		snapshot2, err := NewSnapshotZone(p, Test.result, Test.name)
		if err != nil {
			fmt.Printf("Test:'%s' snapshot2 parse FAILED (ERROR), err:'%s'\n", Test.uuid, err)
			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nFOR TEST", fmt.Sprintf("\nresult:'%s'", Test.result),
				"\nEXPECTED", fmt.Sprintf("\nerr:'%t'", Test.err),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}

		if !snapshot.Equal(snapshot2) {
			fmt.Printf("Test:'%s' snapshot result equality FAILED (ERROR), err:'%s'\n", Test.uuid, err)
			snapshot2.Dump(p, "snapshot expected", 20)

			t.Error(
				"\nUUID", fmt.Sprintf("\nuuid:'%s'", Test.uuid),
				"\nFOR TEST", fmt.Sprintf("\nresult:'%s'", Test.result),
				"\nEXPECTED", fmt.Sprintf("\nerr:'%t'", Test.err),
				"\nGOT", fmt.Sprintf("\nerr:'%s'", err),
			)
			continue
		}

		fmt.Printf("Test:'%s' zone:'%s' ixfr apply OK\n", Test.uuid, Test.name)
	}
}
