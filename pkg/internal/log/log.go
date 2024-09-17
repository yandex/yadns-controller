package log

import (
	"bytes"
	"fmt"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	lumberjack "gopkg.in/natefinch/lumberjack.v2"
)

const (
	callerSkip = 1

	// we have our own predefined values
	// for rotation via lumberjack

	// max size in megabytes
	DefaultMaxSize int = 500

	// max backups
	DefaultMaxBackups int = 24

	// max age of file to keep im days
	DefaultMaxAge int = 1

	// default compression
	DefaultCompression bool = false
)

const (
	// default values for logging before
	// configuration is read, by default
	// we have stdout without debug
	DefaultLoggingDebug  bool = false
	DefaultLoggingStdout bool = true

	// no any log file is set
	DefaultLoggingPath string = ""
)

type Logger struct {
	zapper  *zap.Logger
	config  *zap.Config
	options *LoggerOptions

	lumberjack *lumberjack.Logger
}

var onlyOnce sync.Once

func (l *Logger) GetLoggerOptions() *LoggerOptions {
	return l.options
}

type lumberjackSink struct {
	*lumberjack.Logger
}

func (lumberjackSink) Sync() error {
	return nil
}

type LoggerOptions struct {
	Path   string `json:"path"`
	Debug  bool   `json:"debug"`
	Stdout bool   `json:"stdout"`

	// some methods (especially for debug level)
	// could also be verbose or not, used only
	// in vf methods
	Verbose bool `json:"verbose"`

	// options from lumberjack
	MaxSize     int  `json:"max-size"`
	MaxBackups  int  `json:"max-backups"`
	MaxAge      int  `json:"max-age"`
	Compression bool `json:"compression"`
}

func GetGID() uint64 {
	b := make([]byte, 64)
	b = b[:runtime.Stack(b, false)]
	b = bytes.TrimPrefix(b, []byte("goroutine "))
	b = b[:bytes.IndexByte(b, ' ')]
	n, _ := strconv.ParseUint(string(b), 10, 64)
	return n
}

func GetGPid() string {
	return fmt.Sprintf("[%d]:[%d]", os.Getpid(), GetGID())
}

// imported from internal/color/color zap to have
// colored custom level encoder

// Foreground colors.
const (
	Black Color = iota + 30
	Red
	Green
	Yellow
	Blue
	Magenta
	Cyan
	White
)

// Color represents a text color.
type Color uint8

// Add adds the coloring to the given string.
func (c Color) Add(s string) string {
	return fmt.Sprintf("\x1b[%dm%s\x1b[0m", uint8(c), s)
}

var (
	_levelToColor = map[zapcore.Level]Color{
		// by default zap has magenta as debug color
		// it seems to be tooo match
		// DebugLevel:  Magenta
		InfoLevel:  Blue,
		WarnLevel:  Yellow,
		ErrorLevel: Red,
		FatalLevel: Red,
	}
)

func (l *Logger) CustomLevelEncoder(level zapcore.Level, enc zapcore.PrimitiveArrayEncoder) {

	le := level.CapitalString()
	label := le[0:4]

	if l.options != nil {
		if l.options.Stdout {
			// logging to file should not be colored
			if _, ok := _levelToColor[level]; ok {
				color := _levelToColor[level]
				label = color.Add(label)
			}
		}
	}

	format := "2006-01-02 15:04:05.000000"
	date := time.Now().Format(format)
	enc.AppendString(fmt.Sprintf("%s[%s] %s", label, date, GetGPid()))
}

type Level = zapcore.Level

const (
	InfoLevel  Level = zap.InfoLevel
	WarnLevel  Level = zap.WarnLevel
	ErrorLevel Level = zap.ErrorLevel

	FatalLevel Level = zap.FatalLevel
	DebugLevel Level = zap.DebugLevel
)

type Field = zap.Field

func (l *Logger) Debug(msg string, fields ...Field) {
	l.zapper.Debug(msg, fields...)
}

func (l *Logger) Info(msg string, fields ...Field) {
	l.zapper.Info(msg, fields...)
}

func (l *Logger) Warn(msg string, fields ...Field) {
	l.zapper.Warn(msg, fields...)
}

func (l *Logger) Error(msg string, fields ...Field) {
	l.zapper.Error(msg, fields...)
}
func (l *Logger) Fatal(msg string, fields ...Field) {
	l.zapper.Fatal(msg, fields...)
}

func (l *Logger) GetZap() *zap.Logger {
	return l.zapper
}

func (l *Logger) GetConfigLevel() string {
	level := "info"
	if l.options != nil {
		if l.options.Debug {
			level = "debug"
		}
	}
	return level
}

func (l *Logger) GetConfig() *zap.Config {
	return l.config
}

func (l *Logger) Rotate() error {
	if l.lumberjack != nil {
		return l.lumberjack.Rotate()
	}
	return nil
}

func (l *Logger) Debugf(msg string, args ...interface{}) {
	if ce := l.zapper.Check(zap.DebugLevel, ""); ce != nil {
		ce.Message = fmt.Sprintf(msg, args...)
		ce.Write()
	}
}

func (l *Logger) Debugvf(msg string, args ...interface{}) {
	if l.options != nil {
		if l.options.Verbose {
			l.Debugf(msg, args...)
		}
	}
}

func (l *Logger) SetVerbose(verbose bool) {
	if l.options != nil {
		l.options.Verbose = verbose
	}
}

func (l *Logger) Warnf(msg string, args ...interface{}) {
	if ce := l.zapper.Check(zap.WarnLevel, ""); ce != nil {
		ce.Message = fmt.Sprintf(msg, args...)
		ce.Write()
	}
}

func (l *Logger) Infof(msg string, args ...interface{}) {
	if ce := l.zapper.Check(zap.InfoLevel, ""); ce != nil {
		ce.Message = fmt.Sprintf(msg, args...)
		ce.Write()
	}
}

func (l *Logger) Errorf(msg string, args ...interface{}) {
	if ce := l.zapper.Check(zap.ErrorLevel, ""); ce != nil {
		ce.Message = fmt.Sprintf(msg, args...)
		ce.Write()
	}
}

func (l *Logger) Fatalf(msg string, args ...interface{}) {
	if ce := l.zapper.Check(zap.FatalLevel, ""); ce != nil {
		ce.Message = fmt.Sprintf(msg, args...)
		ce.Write()
	}
}

func (l *Logger) SetLogLevel(level Level) {
	l.config.Level.SetLevel(level)
}

func (l *Logger) SetDebugLogLevel() {
	l.SetLogLevel(DebugLevel)
}

func (l *Logger) SetInfoLogLevel() {
	l.SetLogLevel(InfoLevel)
}

func (l *Logger) Dump(id string, content string, max int) {
	rows := strings.Split(content, "\n")
	for i, r := range rows {
		if (i < max && max > 0) || max == 0 {
			l.Debug(fmt.Sprintf("%s [%02d]/[%02d] %s",
				id, i+1, len(rows), r))
		}
	}
}

func (l *Logger) DumpBytes(id string, content []byte, max int) {
	rows := strings.Split(string(content), "\n")
	for i, r := range rows {
		if (i < max && max > 0) || max == 0 {
			l.Debug(fmt.Sprintf("%s [%02d]/[%02d] %s",
				id, i+1, len(rows), r))
		}
	}
}

func (l *Logger) DumpBytesv(id string, content []byte, max int) {
	if l.options != nil {
		if l.options.Verbose {
			l.DumpBytes(id, content, max)
		}
	}
}

// setupLogger should be called inside of rootCmd Execute function
// for variables to be set up properly
func CreateLogger(options LoggerOptions) (*Logger, error) {

	var logger Logger

	logLevel := InfoLevel
	if options.Debug {
		logLevel = DebugLevel
	}

	cfg := zap.NewProductionConfig()
	cfg.Encoding = "console"
	cfg.Sampling = nil

	if len(options.Path) > 0 && options.Path != "stdout" {
		maxsize := DefaultMaxSize
		maxbackups := DefaultMaxBackups
		maxage := DefaultMaxAge
		compression := DefaultCompression

		if options.MaxSize > 0 {
			maxsize = options.MaxSize
		}

		if options.MaxBackups > 0 {
			maxbackups = options.MaxBackups
		}

		if options.MaxAge > 0 {
			maxage = options.MaxAge
		}

		if options.Compression {
			compression = options.Compression
		}

		ll := lumberjack.Logger{
			Filename:   options.Path,
			MaxSize:    maxsize,
			MaxBackups: maxbackups,
			MaxAge:     maxage,
			Compress:   compression,
		}

		onlyOnce.Do(func() {
			err := zap.RegisterSink("lumberjack", func(*url.URL) (zap.Sink, error) {
				return lumberjackSink{
					Logger: &ll,
				}, nil
			})
			if err != nil {
				// New version of lumberjack checks number of register
				// sinks, we have to skip error handling, displaying
				// only error message. T.B.D. fixing such as RegisterSink
				// is called only once per program
				fmt.Printf("error register sink over logger, err:'%s'", err)
			}
		})

		path := fmt.Sprintf("lumberjack:%s", options.Path)

		cfg.OutputPaths = []string{path}
		cfg.ErrorOutputPaths = []string{path}

		logger.lumberjack = &ll
	}

	cfg.DisableStacktrace = true
	cfg.DisableCaller = true
	cfg.Level = zap.NewAtomicLevelAt(logLevel)

	cfg.EncoderConfig.ConsoleSeparator = " "
	cfg.EncoderConfig.EncodeLevel = logger.CustomLevelEncoder
	cfg.EncoderConfig.TimeKey = ""

	zapper, err := cfg.Build(zap.AddCallerSkip(callerSkip))
	if err != nil {
		return nil, err
	}

	logger.zapper = zapper
	logger.config = &cfg
	logger.options = &options

	return &logger, nil
}
