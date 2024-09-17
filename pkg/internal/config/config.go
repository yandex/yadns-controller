package config

import (
	"fmt"
	"io/ioutil"
	"os"

	yaml "gopkg.in/yaml.v3"

	"github.com/slayer1366/yadns-controller/pkg/internal/log"
)

const (
	// a program name used in version and logging
	// strings, also used as UA identification plus
	// version (if any set)
	ProgramName = "yadns-controller"

	// default configuration file if no any
	// file specified, if default file does not exist
	// we use default configuration
	DefaultConfigFile string = "/etc/yadns-controller/yadns-controller.yaml"
)

type TGlobal struct {

	// options set by configuration (from file or default)
	Opts *TConfig

	// runtime settings set after configuration
	// is parsed
	Runtime *TRuntime

	L *log.Logger
}

func (c *TGlobal) O() *TConfig {
	return c.Opts
}

type TConfig struct {
	// logging config
	Log TLogConfig `json:"log" yaml:"log"`

	// controller configuration
	Controller TControllerConfig `json:"controller" yaml:"controller"`

	// plugins configuration
	Plugins map[string]map[string]TPluginConfig `json:"plugins" yaml:"plugins"`
}

type TLogConfig struct {
	Format  string `json:"format" yaml:"format"`
	Log     string `json:"log" yaml:"log"`
	Level   string `json:"level" yaml:"level"`
	Verbose bool   `json:"verbose" yaml:"verbose"`

	// max log size in MB
	MaxSize int `json:"max-size" yaml:"max-size"`
	// max log file count
	MaxBackups int `json:"max-backups" yaml:"max-backups"`
	// maximum number of days to retain old log files
	MaxAge int `json:"max-age" yaml:"max-age"`
	// if the rotated log files should be compressed using gzip
	Compression bool `json:"compression" yaml:"compression"`
}

type TRuntime struct {
	Version string `json:"version" yaml:"version"`
	Date    string `json:"date" yaml:"date"`

	ProgramName string `json:"program-name" yaml:"program-name"`
	Hostname    string `json:"hostname" yaml:"hostname"`
}

func (t *TRuntime) GetUseragent() string {
	return fmt.Sprintf("%s/%s", ProgramName, t.Version)
}

type TControllerConfig struct {
	// common API requests (all plugins should
	// register its methods?)
	API TAPIOptions `json:"api" yaml:"api"`
}

type TAPIOptions struct {
	// listen options in from "[::1]:5053"
	Listen string `json:"listen" yaml:"listen"`

	// debug for echo server
	Debug bool `json:"debug" yaml:"debug"`
}

type TPluginConfig interface{}

// a default fallback configuration if no config options
// set and no file provided or detected
var DefaultConfig = []byte(`
# default configuration

log:
  # logging format could be "string" or "json"
  format: "string"

  # "stdout" - output to console (actually to syslog)
  # or could be defined as log path like 
  # "/var/log/yadns-controller/yadns-controller.log"
  log: "stdout"

  # level of debugging could be "debug", "info", could be
  # overrided by command line switch
  level: "debug"

`)

func Exists(name string) bool {
	if _, err := os.Stat(name); err != nil {
		if os.IsNotExist(err) {
			return false
		}
	}
	return true
}

// loading a configuration from file or set by default
func NewConfig(filename string, Log *log.Logger) (*TConfig, error) {
	id := "(config) (yaml)"

	var err error
	var conf TConfig
	var content []byte

	// if we have configuration file specified, read
	// it and fail if we could not get content with error
	if len(filename) > 0 {
		if content, err = ioutil.ReadFile(filename); err != nil {
			if Log != nil {
				Log.Errorf("%s error reading config file:'%s', err:'%s'",
					id, filename, err)
			}
			return &conf, err
		}
	}

	if len(filename) == 0 {
		// checking if default configuration file exists
		// and we could read it
		config := DefaultConfigFile
		exists := Exists(config)

		if exists {
			// default config exists so it could be read
			if content, err = ioutil.ReadFile(config); err != nil {
				if Log != nil {
					Log.Errorf("%s error reading config file:'%s', err:'%s'",
						id, config, err)
				}
				return &conf, err
			}
		}

		if !exists {
			content = DefaultConfig
		}
	}
	if err = yaml.Unmarshal(content, &conf); err != nil {
		if Log != nil {
			Log.Errorf("%s error parsing config data err:'%s'", id, err)
		}
		return &conf, err
	}

	file := filename
	if len(file) == 0 {
		file = "default"
	}
	if Log != nil {
		Log.Debugf("%s successfully loaded configuration from:'%s'", id, file)
	}

	return &conf, err
}

func (c *TGlobal) CreateLogger(opts *log.LoggerOptions) (*log.Logger, error) {

	var err error

	var l *log.Logger

	options := log.LoggerOptions{
		Debug:  log.DefaultLoggingDebug,
		Stdout: log.DefaultLoggingStdout,
		Path:   log.DefaultLoggingPath,
	}

	if opts != nil {
		// overriding default proprties if supplied
		options.Debug = opts.Debug
		options.Stdout = opts.Stdout

		if opts.Path != "stdout" {
			options.Path = opts.Path
		}

		options.Verbose = opts.Verbose

		options.MaxAge = opts.MaxAge
		options.MaxSize = opts.MaxSize
		options.MaxBackups = opts.MaxBackups
		options.Compression = opts.Compression
	}

	if l, err = log.CreateLogger(options); err != nil {
		// No any logger created yet, but we need say
		// something about error ocurred
		fmt.Printf("error creating default logger, err:'%s'", err)
		return l, err
	}

	return l, err
}

const (
	// default addr for API
	DefaultListenAddr = "[::1]:5053"
)

func (t *TConfig) GetListenAddr() string {
	addr := DefaultListenAddr
	options := t.Controller.API
	if len(options.Listen) > 0 {
		addr = options.Listen
	}
	return addr
}

func StringInSlice(key string, list []string) bool {
	for _, entry := range list {
		if entry == key {
			return true
		}
	}
	return false
}

const (
	ColorWhite         = 0
	ColorRed           = 1
	ColorGreen         = 2
	ColorYellow        = 3
	ColorBlue          = 4
	ColorMagenta       = 5
	ColorCyan          = 6
	ColorBrightBlack   = 7
	ColorBrightRed     = 8
	ColorBrightGreen   = 9
	ColorBrightYellow  = 10
	ColorBrightBlue    = 11
	ColorBrightMagenta = 12
	ColorBrightCyan    = 13
	ColorBrightWhite   = 14
)

func ColorString(s string, color int) string {
	reset := "\033[0m"
	colors := map[int]string{
		ColorWhite:         "\033[37m",
		ColorRed:           "\033[31m",
		ColorGreen:         "\033[32m",
		ColorYellow:        "\033[33m",
		ColorBlue:          "\033[34m",
		ColorBrightBlack:   "\033[90m",
		ColorBrightRed:     "\033[91m",
		ColorBrightGreen:   "\033[92m",
		ColorBrightYellow:  "\033[93m",
		ColorBrightBlue:    "\033[94m",
		ColorBrightMagenta: "\033[95m",
		ColorBrightCyan:    "\033[96m",
		ColorBrightWhite:   "\033[97m",
	}

	command := ""
	if _, ok := colors[color]; ok {
		command = colors[color]
	}

	return fmt.Sprintf("%s%s%s", command, s, reset)
}
