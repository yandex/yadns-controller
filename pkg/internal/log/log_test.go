package log

import (
	"errors"
	"fmt"
	"os"
	"testing"
	"time"
)

func TestCreateLogger(t *testing.T) {

	id := "(test) (logger)"

	var l *Logger
	var err error

	type TTest struct {
		uuid   string
		debug  bool
		stdout bool
		path   string
	}

	f, err := os.CreateTemp("/var/tmp/", "testcreatelogger-tmpfile-*.log")
	if err != nil {
		t.Error("error create tmpfile", fmt.Sprintf(", err:'%s'", err))
		return
	}

	defer f.Close()
	defer os.Remove(f.Name())

	var Tests = []TTest{
		// stdout logging with debug set to on
		{
			"45441580-f864-4a38-883f-057497dfc682",
			true,
			true,
			"",
		},
		// stdout logging with debug set to off
		{
			"aa928774-4f24-4ccc-8748-0017d1d9f97e",
			false,
			true,
			"",
		},
		// logging to file
		{
			"8304d099-2825-4b13-8f57-571f04eb5663",
			true,
			false,
			f.Name(),
		},
	}

	for _, Test := range Tests {

		var options LoggerOptions
		options.Debug = Test.debug
		options.Stdout = Test.stdout
		options.Path = Test.path

		if l, err = CreateLogger(options); err != nil {
			t.Error("error create logger", fmt.Sprintf(", err:'%s'", err))
			return
		}

		l.Debugf("%s uuid='%s' debug level logger created successfully", id, Test.uuid)
		l.Infof("%s uuid='%s' info level logger created successfully", id, Test.uuid)
		l.Warnf("%s uuid='%s' warn level logger created successfully", id, Test.uuid)

		err = errors.New("testing logger output")
		l.Errorf("%s uuid='%s' error creating logger, err:'%s'", id, err, Test.uuid)

		if len(Test.path) > 0 {

			var content []byte
			if content, err = os.ReadFile(Test.path); err != nil {
				t.Error("error reading logfile", fmt.Sprintf("error read file:'%s', err:'%s'",
					Test.path, err))
				return
			}

			l.DumpBytes("(dump)", content, 0)

			// trying to rotate a file N times
			N := 6
			for i := 1; i <= N; i++ {
				l.Debugf("%s uuid='%s' [%d]/[%d] rotation file:'%s'",
					id, Test.uuid, i, N, Test.path)
				if err = l.Rotate(); err != nil {
					t.Error("error rotating logfile", fmt.Sprintf("error on iteration:'%d' rotation as '%s', err:'%s'",
						i, Test.path, err))
					return
				}

				// sleeping to have timestamp for next file
				// to be correctly formed
				time.Sleep(1000)
			}
		}
	}
}
