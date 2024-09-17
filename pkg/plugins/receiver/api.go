package receiver

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (t *TReceiverPlugin) SetupMethods(group *echo.Group) {
	// getting metrics from watcher worker
	group.GET(fmt.Sprintf("/%s/metrics", NamePlugin), t.Metrics)
}

func (t *TReceiverPlugin) Metrics(ctx echo.Context) error {
	id := "(receiver) (api) (metrics)"

	// requested metrics
	t.G().L.Debugf("%s requested metrics", id)

	content, err := t.watcher.AsJSON()
	if err != nil {
		return echo.NewHTTPError(http.StatusServiceUnavailable, err.Error())
	}

	return ctx.Blob(http.StatusOK, "application/json", content)
}
