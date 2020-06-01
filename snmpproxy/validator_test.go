package snmpproxy_test

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/grongor/go-snmp-proxy/snmpproxy"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		request snmpproxy.Request
		err     string
	}{
		{
			name: "no error",
			request: snmpproxy.Request{
				RequestType: snmpproxy.Get,
				Oids:        []string{".1.2.3"},
			},
		},
		{
			name: "missing oids",
			request: snmpproxy.Request{
				RequestType: snmpproxy.Get,
				Oids:        nil,
			},
			err: "at least one OID must be provided",
		},
		{
			name: "multiple OIDs with walk",
			request: snmpproxy.Request{
				RequestType: snmpproxy.Walk,
				Oids:        []string{".1.2.3", ".4.5.6."},
			},
			err: "only single OID is supported with RequestType = Walk, got 2",
		},
		{
			name: "OID without dot prefix",
			request: snmpproxy.Request{
				RequestType: snmpproxy.Get,
				Oids:        []string{".1.2.3", "4.5.6"},
			},
			err: "all OIDs must begin with a dot",
		},
		{
			name: "too large timeout",
			request: snmpproxy.Request{
				RequestType: snmpproxy.Get,
				Timeout:     100 * time.Second,
				Oids:        []string{".1.2.3"},
			},
			err: "maximum allowed timeout is 10 seconds, got 100 seconds",
		},
		{
			name: "too many retries",
			request: snmpproxy.Request{
				RequestType: snmpproxy.Get,
				Retries:     15,
				Oids:        []string{".1.2.3"},
			},
			err: "maximum allowed number of retries is 10, got 15",
		},
		{
			name: "missing maxRepetitions",
			request: snmpproxy.Request{
				RequestType: snmpproxy.Walk,
				Oids:        []string{".1.2.3"},
			},
			err: "field max_repetitions is required for RequestType Walk, and it mustn't be zero",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			validator := snmpproxy.NewRequestValidator(10, 10)

			err := validator.Validate(test.request)

			if test.err == "" {
				require.NoError(t, err)
			} else {
				require.EqualError(t, err, test.err)
			}
		})
	}
}
