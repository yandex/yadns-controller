package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strings"

	"github.com/labstack/echo/v4"
	"github.com/labstack/echo/v4/middleware"
	"golang.org/x/sync/errgroup"

	"github.com/slayer1366/yadns-controller/pkg/internal/config"
)

const (
	//default debug option
	DefaultDebug = false

	// current api version
	CurrentAPIVersion = "/api/v1.0"
)

type Server struct {
	g *config.TGlobal

	// T.B.D. some pointers to zone states snapshots
	// some pointers to map? or we could establish connection
	// every time?

	// ref to receiver to control and verify
	// receiver *worker.ReceiverWorker

	// ref to monitor worker to get
	// exported metrics
	//monitor *worker.MonitorWorker

	server *echo.Echo

	// group to attach plugin methods
	group *echo.Group
}

func NewServer(g *config.TGlobal) *Server {

	server := echo.New()
	server.HideBanner = true
	server.HidePort = true
	server.Use(middleware.RequestID())
	server.Use(middleware.Recover())
	server.Use(middleware.Gzip())
	server.Use(middleware.Logger())
	server.Debug = DefaultDebug

	options := g.Opts.Controller.API
	if options.Debug {
		server.Debug = options.Debug
	}

	m := &Server{g: g}
	m.server = server

	// creating echo group for methods
	m.group = m.CreateGroup()

	return m
}

func (m *Server) GetGroup() *echo.Group {
	return m.group
}

func (m *Server) CreateGroup() *echo.Group {
	v1 := m.server.Group(CurrentAPIVersion)

	v1.GET("/ping", func(ctx echo.Context) error {
		return ctx.String(http.StatusOK, "OK")
	})

	return v1
}

func (m *Server) Run(ctx context.Context) error {

	id := "(api) (run)"

	addr := m.g.Opts.GetListenAddr()

	wg, ctx := errgroup.WithContext(ctx)
	wg.Go(func() error {
		listener, err := net.Listen("tcp", addr)
		if err != nil {
			return err
		}

		m.g.L.Debugf("%s http server run on %s", id, listener.Addr())
		defer m.g.L.Debugf("%s stopped", id)

		m.server.Listener = listener
		return m.server.Start(addr)
	})
	wg.Go(func() error {
		<-ctx.Done()
		return m.server.Shutdown(context.Background())
	})

	return wg.Wait()
}

type ControlVerifyReq struct {
	Dryrun bool `json:"dryrun"`
}

func (c *ControlVerifyReq) AsJSON() []byte {
	body, _ := json.MarshalIndent(c, "", "  ")
	return body
}

func (c *ControlVerifyReq) AsString() string {
	var out []string

	out = append(out, fmt.Sprintf("dryrun:'%t'", c.Dryrun))

	return strings.Join(out, ",")
}

type MetricsReceiveReq struct {
	Dryrun bool `json:"dryrun"`
}

func (c *MetricsReceiveReq) AsJSON() []byte {
	body, _ := json.MarshalIndent(c, "", "  ")
	return body
}

func (c *MetricsReceiveReq) AsString() string {
	var out []string

	out = append(out, fmt.Sprintf("dryrun:'%t'", c.Dryrun))

	return strings.Join(out, ",")
}

type ControlBpfReq struct {
	Dryrun    bool     `json:"dryrun"`
	Option    string   `json:"option"`
	Value     bool     `json:"value"`
	ValueList []string `json:"values"`
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
