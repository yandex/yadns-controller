package example

import (
	"fmt"
	"net/http"

	"github.com/labstack/echo/v4"
)

func (t *TExamplePlugin) SetupMethods(group *echo.Group) {
	// ping example method
	group.GET(fmt.Sprintf("/%s/ping", NamePlugin), t.Ping)
}

func (t *TExamplePlugin) Ping(ctx echo.Context) error {
	id := "(example) (api) (ping)"

	// requested ping method
	t.G().L.Debugf("%s requested ping", id)

	return ctx.String(http.StatusOK, "OK")
}
