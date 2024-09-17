package metrics

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (t *TMetricsPlugin) SetupMethods(group *echo.Group) {
	// ping example method
	group.GET(fmt.Sprintf("/%s/ping", NamePlugin), t.Ping)

	// exporting metrics as plain json
	group.GET(fmt.Sprintf("/%s", NamePlugin), t.GetHTTPMetrics)
	group.GET(fmt.Sprintf("/%s/:id", NamePlugin), t.GetHTTPMetrics)

}

func (t *TMetricsPlugin) Ping(ctx echo.Context) error {
	id := "(metrics) (api) (ping)"

	// requested ping method
	t.G().L.Debugf("%s requested ping", id)

	return ctx.String(http.StatusOK, "OK")
}

// exporting metrics as json
func (t *TMetricsPlugin) GetHTTPMetrics(ctx echo.Context) error {
	id := "(metrics) (api) (export)"

	name := ctx.Param("id")
	t.G().L.Debugf("%s requested metric:'%s'", id, name)

	metrics := t.worker.GetMetrics(name)
	if len(metrics) == 0 {
		// no metrics found
		return ctx.String(http.StatusNotFound, "Not found")
	}

	return ctx.JSONPretty(http.StatusOK, metrics, "  ")
}
