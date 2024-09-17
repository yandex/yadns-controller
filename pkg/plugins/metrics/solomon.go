package metrics

import (
	"fmt"
	"strings"
)

const (

	// Solomon type of gauge could also be
	// as alias DGAUGE
	SensorSolomonTypeGauge = "GAUGE"

	// Solomon and Prometheus use this type of metric
	// for monotonic increasing data
	SensorSolomonTypeCounter = "COUNTER"

	// Histograms in solomon and promethues are
	// different, see below
	SensorSolomonTypeHistogram = "HIST"
)

// metrics could be used to send solomon metrics
type Value struct {
	ID    string            `json:"id"`
	Value float64           `json:"value"`
	Tags  map[string]string `json:"tags"`

	// values for histogram by default we have
	// empty value of SensorSolomonTypeGauge
	Type string `json:"type"`

	// not exported values
	timestamp int64

	Hist *THist `json:"hist,omitempty"`
}

type THist struct {
	Bounds  []float64 `json:"bounds"`
	Buckets []int64   `json:"buckets"`
}

func (t *THist) AsString() string {
	var out []string

	var bounds []string
	for _, b := range t.Bounds {
		bounds = append(bounds, fmt.Sprintf("%2.2f", b))
	}

	var buckets []string
	for _, b := range t.Buckets {
		buckets = append(buckets, fmt.Sprintf("%d", b))
	}

	out = append(out, fmt.Sprintf("bounds:['%s']",
		strings.Join(bounds, ",")))

	out = append(out, fmt.Sprintf("buckets:['%s']",
		strings.Join(buckets, ",")))

	return strings.Join(out, ";")
}

func (v *Value) String() string {
	tags := ""
	if v.Tags != nil {
		for k, w := range v.Tags {
			t := fmt.Sprintf("'%s':'%s'", k, w)
			if len(tags) > 0 {
				tags = fmt.Sprintf("%s;%s", tags, t)
				continue
			}
			tags = t
		}
	}

	if len(tags) == 0 {
		return fmt.Sprintf("id:'%s', v:'%2.2f'", v.ID, v.Value)
	}

	if v.timestamp > 0 {

		t := SensorSolomonTypeGauge
		value := fmt.Sprintf("'%2.2f'", v.Value)
		if len(v.Type) > 0 {
			t = v.Type
		}

		switch t {
		case SensorSolomonTypeHistogram:
			if v.Hist != nil {
				value = v.Hist.AsString()
			}
		}

		return fmt.Sprintf("id:'%s' '%s' v:'%s', tags:'%s' timestamp:'%d'",
			v.ID, t, value, tags, v.timestamp)
	}

	return fmt.Sprintf("id:'%s' v:'%2.2f', tags:'%s'",
		v.ID, v.Value, tags)
}

func NewValue() Value {
	var v Value
	v.Tags = make(map[string]string)
	v.Type = SensorSolomonTypeGauge
	return v
}
