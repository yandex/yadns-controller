package monitor

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"

	"github.com/yandex/yadns-controller/pkg/internal/api"
)

const (
	// default API empty idenficator
	DefaultEmpty = ""
)

func (t *TMonitorPlugin) SetupMethods(group *echo.Group) {
	// ping example method
	group.GET(fmt.Sprintf("/%s/ping", NamePlugin), t.Ping)

	// main monitoring methods getting current state
	// of registeted checks in controller for all
	// plugins
	group.GET(fmt.Sprintf("/%s/:id", NamePlugin), t.GetHTTPCheck)
	group.GET(fmt.Sprintf("/%s", NamePlugin), t.GetHTTPCheck)

}

func (t *TMonitorPlugin) Ping(ctx echo.Context) error {
	id := "(monitor) (api) (ping)"

	// requested ping method
	t.G().L.Debugf("%s requested ping", id)

	return ctx.String(http.StatusOK, "OK")
}

// monitoring check should be responded as a map
func (t *TMonitorPlugin) GetHTTPCheck(ctx echo.Context) error {
	id := "(monitor) (api) (check)"

	// names of checks
	var names []string

	// if no id requested we assume that we
	// need all checks
	name := ctx.Param("id")
	if len(name) > 0 {
		names = append(names, name)
	} else {
		// getting checks IDs
		names = append(names, t.GetCheckIDs()...)
		if len(names) == 0 {
			return ctx.String(http.StatusNotFound, "Not found")
		}
	}

	t.G().L.Debugf("%s requested check names:['%s']", id,
		strings.Join(names, ","))

	out := make(map[string]*Check)

	for _, name := range names {
		// getting check itself
		check, err := t.GetCheck(name)
		if err != nil {
			// specified check not found
			return ctx.String(http.StatusNotFound, "Not found")
		}

		// getting check history
		history, err := t.GetHistory(name)
		if err != nil {
			// history is not found
			return ctx.String(http.StatusNotFound, "Not found")
		}

		c := NewCheck(check)
		c.Message = fmt.Sprintf("%s '%s' as history %s age:'%2.2f' seconds", check.Message,
			check.CodeString(), history.String(), check.Age())

		out[check.ID] = c
	}

	return ctx.JSONPretty(http.StatusOK, out, "  ")
}

// getting client check via api call
func (t *TMonitorPlugin) GetClientChecks(tid string) (map[string]*Check, error) {
	id := "(monitor) (client)"

	t.G().L.Debugf("%s request to get check:'%s'", id, tid)

	client := api.NewClient(t.G())

	url := NamePlugin
	if len(tid) > 0 {
		url = fmt.Sprintf("%s/%s", NamePlugin, tid)
	}
	content, code, err := client.Request(http.MethodGet, url, nil)
	if err != nil {
		t.G().L.Errorf("%s error request url:'%s', err:'%s'", id, url, err)
		return nil, err
	}

	t.G().L.Debugf("%s recevied response content:'%d' code:'%d'", id, len(content), code)
	t.G().L.DumpBytes(id, content, 0)

	if code == http.StatusOK {
		var out map[string]*Check
		err = json.Unmarshal(content, &out)
		if err != nil {
			t.G().L.Errorf("%s error unmarshal data, err:'%s'", id, err)
			return nil, err
		}
		return out, err
	}

	return nil, fmt.Errorf("not found")
}
