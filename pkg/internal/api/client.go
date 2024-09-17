package api

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/slayer1366/yadns-controller/pkg/internal/config"
)

type Client struct {
	g *config.TGlobal
}

type ClientOptions struct {
	Dryrun bool
}

func NewClient(g *config.TGlobal) *Client {
	m := &Client{g: g}
	return m
}

const (
	// number of milliseconds for timeout in
	// client http call
	DefaultHTTPTimeout = 2000
)

func (m *Client) Request(method string, uri string, content []byte) ([]byte, int, error) {
	id := "(client) (http)"

	t0 := time.Now()

	url := fmt.Sprintf("http://%s%s/%s", m.g.Opts.GetListenAddr(),
		CurrentAPIVersion, uri)

	m.g.L.Debugf("%s requesting '%s' data over endpoint:'%s'", id, uri, url)
	m.g.L.Debugf("%s version:'%s' date:'%s'", id, m.g.Runtime.Version,
		m.g.Runtime.Date)

	m.g.L.DumpBytes(id, content, 0)

	reader := bytes.NewReader(content)

	timeout := DefaultHTTPTimeout
	ctx, cancel := context.WithTimeout(context.Background(),
		time.Duration(timeout)*time.Millisecond)

	defer cancel()

	req, err := http.NewRequestWithContext(ctx, method, url, reader)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("User-Agent", m.g.Runtime.GetUseragent())
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, err
	}

	defer resp.Body.Close()

	var body []byte
	if body, err = io.ReadAll(resp.Body); err != nil {
		return nil, resp.StatusCode, err
	}
	m.g.L.Debugf("%s recevied size:'%d' finished in '%s'",
		id, len(body), time.Since(t0))

	m.g.L.Debugf("%s recevied code:'%d'", id, resp.StatusCode)

	counter := 0
	for k, v := range resp.Header {
		m.g.L.Debugf("%s recevied headers [%d]/[%d] '%s' '%s'", id, counter, len(resp.Header), k, v)
		counter++
	}

	return body, resp.StatusCode, nil
}

func (m *Client) ControlVerify(options *ClientOptions) error {
	id := "(client) (control) (verify)"

	req := ControlVerifyReq{}
	req.Dryrun = options.Dryrun

	resp, code, err := m.Request("POST", "control/verify", req.AsJSON())
	if err != nil {
		return err
	}
	m.g.L.DumpBytes(id, resp, 0)

	if code != http.StatusOK {
		err := fmt.Errorf("http error '%s'", http.StatusText(code))
		m.g.L.Errorf("%s request error, err:'%s'", id, err)
		return err
	}

	return nil
}

func (m *Client) MetricsReceive(options *ClientOptions) error {
	id := "(client) (metrics) (receive)"

	req := MetricsReceiveReq{}
	req.Dryrun = options.Dryrun

	resp, code, err := m.Request("POST", "metrics", req.AsJSON())
	if err != nil {
		return err
	}
	m.g.L.DumpBytes(id, resp, 0)

	if code != http.StatusOK {
		err := fmt.Errorf("http error '%s'", http.StatusText(code))
		m.g.L.Errorf("%s request error, err:'%s'", id, err)
		return err
	}

	return nil
}

func (m *Client) ConfigList(options *ClientOptions) error {
	id := "(client) (list)"

	req := MetricsReceiveReq{}
	req.Dryrun = options.Dryrun

	resp, code, err := m.Request("GET", "config", req.AsJSON())
	if err != nil {
		return err
	}
	m.g.L.DumpBytes(id, resp, 0)

	if code != http.StatusOK {
		err := fmt.Errorf("http error '%s'", http.StatusText(code))
		m.g.L.Errorf("%s request error, err:'%s'", id, err)
		return err
	}

	return nil
}

type ClientControlBpfOptions struct {
	Dryrun    bool
	Option    string
	Value     bool
	ValueList []string
}

func (m *Client) ControlBpf(options *ClientControlBpfOptions) error {
	id := "(client) (control) (bpf)"

	req := ControlBpfReq{}
	req.Dryrun = options.Dryrun
	req.Option = options.Option
	req.Value = options.Value
	req.ValueList = options.ValueList

	resp, code, err := m.Request("POST", "control/bpf", req.AsJSON())
	if err != nil {
		return err
	}
	m.g.L.DumpBytes(id, resp, 0)

	if code != http.StatusOK {
		err := fmt.Errorf("http error '%s'", http.StatusText(code))
		m.g.L.Errorf("%s request error, err:'%s'", id, err)
		return err
	}

	return nil
}
