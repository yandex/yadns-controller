package offloader

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/yandex/yadns-controller/pkg/internal/api"
)

func (t *TOffloaderPlugin) SetupMethods(group *echo.Group) {

	// bpf has some options could be configured in
	// runtime, e.g. dryrun mode run
	group.POST(fmt.Sprintf("/%s/control/bpf", NamePlugin), t.SetBpfOptions)
}

type ControlBpfReq struct {
	Dryrun    bool     `json:"dryrun"`
	Option    string   `json:"option"`
	Value     bool     `json:"value"`
	ValueList []string `json:"values,omitempty"`
}

func (c *ControlBpfReq) AsJSON() []byte {
	body, _ := json.MarshalIndent(c, "", "  ")
	return body
}

func (c *ControlBpfReq) AsString() string {
	var out []string

	out = append(out, fmt.Sprintf("dryrun:'%t'", c.Dryrun))
	out = append(out, fmt.Sprintf("option:'%s'", c.Option))
	out = append(out, fmt.Sprintf("value:'%t'", c.Value))
	out = append(out, fmt.Sprintf("values:['%s']",
		strings.Join(c.ValueList, ",")))

	return strings.Join(out, ",")
}

func (t *TOffloaderPlugin) SetBpfOptions(ctx echo.Context) error {
	id := "(offloader) (set) (bpf) (options)"
	request := ControlBpfReq{}
	if err := ctx.Bind(&request); err != nil {
		return err
	}
	t.G().L.Debugf("%s request recevied as '%s'", id, request.AsString())

	if request.Dryrun {
		err := fmt.Errorf("request to set:'%s' to value:'%t' is dryrun",
			request.Option, request.Value)
		return echo.NewHTTPError(http.StatusBadRequest, err.Error())
	}

	var options RuntimeConfigOptions
	switch request.Option {
	case "dryrun":
		// setting bpf to dryrun mode
		options.BpfConstantBpfDyrun = request.Value
		err := t.xdp.SyncRuntimeConfigMap(&options)
		if err != nil {
			err := fmt.Errorf("bpf map could not be updated, err:'%s'", err)
			return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
		}
	}

	return ctx.String(http.StatusOK, "OK")
}

func (t *TOffloaderPlugin) SetClientBpfOptions(options *ControlBpfReq) error {
	id := "(offloader) (client) (control) (bpf)"

	client := api.NewClient(t.G())

	resp, code, err := client.Request("POST", fmt.Sprintf("%s/control/bpf",
		NamePlugin), options.AsJSON())
	if err != nil {
		return err
	}
	t.G().L.DumpBytes(id, resp, 0)

	if code != http.StatusOK {
		err := fmt.Errorf("http error '%s'", http.StatusText(code))
		t.G().L.Errorf("%s request error, err:'%s'", id, err)
		return err
	}

	return nil
}
