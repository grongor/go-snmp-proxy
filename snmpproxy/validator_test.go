package snmpproxy_test

import (
	"testing"
	"time"

	"github.com/grongor/go-snmp-proxy/snmpproxy"
	"github.com/stretchr/testify/require"
)

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		raw     string
		request *snmpproxy.ApiRequest
		err     string
	}{
		{
			name: "no error",
			request: &snmpproxy.ApiRequest{
				Requests: []snmpproxy.Request{
					{
						RequestType: snmpproxy.Get,
						Oids:        []string{".1.2.3"},
					},
				},
			},
		},
		{
			name: "no error, multiple requests",
			request: &snmpproxy.ApiRequest{
				Requests: []snmpproxy.Request{
					{
						RequestType: snmpproxy.Get,
						Oids:        []string{".1.2.3", ".4.5.6"},
					},
					{
						RequestType:    snmpproxy.Walk,
						Oids:           []string{".7.8.9"},
						MaxRepetitions: 5,
					},
				},
			},
		},
		{
			name: "too large timeout",
			request: &snmpproxy.ApiRequest{
				Timeout: 100 * time.Second,
				Requests: []snmpproxy.Request{
					{
						RequestType: snmpproxy.Get,
						Oids:        []string{".1.2.3"},
					},
				},
			},
			err: "maximum allowed timeout is 10 seconds, got 100 seconds",
		},
		{
			name: "too many retries",
			request: &snmpproxy.ApiRequest{
				Retries: 15,
				Requests: []snmpproxy.Request{
					{
						RequestType: snmpproxy.Get,
						Oids:        []string{".1.2.3"},
					},
				},
			},
			err: "maximum allowed number of retries is 10, got 15",
		},
		{
			name:    "no requests",
			request: &snmpproxy.ApiRequest{},
			err:     "at least one Request must be provided",
		},
		{
			name: "unexpected request type",
			request: &snmpproxy.ApiRequest{
				Requests: []snmpproxy.Request{
					{
						RequestType: snmpproxy.RequestType("wow"),
					},
				},
			},
			err: "request[0]: unexpected RequestType: wow",
		},
		{
			name: "missing oids",
			request: &snmpproxy.ApiRequest{
				Requests: []snmpproxy.Request{
					{
						RequestType: snmpproxy.Get,
						Oids:        nil,
					},
				},
			},
			err: "request[0]: at least one OID must be provided",
		},
		{
			name: "multiple OIDs with walk",
			request: &snmpproxy.ApiRequest{
				Requests: []snmpproxy.Request{
					{
						RequestType: snmpproxy.Walk,
						Oids:        []string{".1.2.3", ".4.5.6"},
					},
				},
			},
			err: "request[0]: only single OID is supported with RequestType = Walk, got 2: .1.2.3, .4.5.6",
		},
		{
			name: "OID without dot prefix",
			request: &snmpproxy.ApiRequest{
				Requests: []snmpproxy.Request{
					{
						RequestType: snmpproxy.Get,
						Oids:        []string{".1.2.3", "4.5.6"},
					},
				},
			},
			err: "request[0]: all OIDs must begin with a dot, got: 4.5.6",
		},
		{
			name: "missing maxRepetitions",
			request: &snmpproxy.ApiRequest{
				Requests: []snmpproxy.Request{
					{
						RequestType: snmpproxy.Walk,
						Oids:        []string{".1.2.3"},
					},
				},
			},
			err: "request[0]: field max_repetitions is required for RequestType = Walk, " +
				"and it mustn't be zero, oid: .1.2.3",
		},
		{
			name: "error in one of the requests",
			request: &snmpproxy.ApiRequest{
				Requests: []snmpproxy.Request{
					{
						RequestType:    snmpproxy.Walk,
						Oids:           []string{".1.2.3"},
						MaxRepetitions: 10,
					},
					{
						RequestType: snmpproxy.Get,
						Oids:        []string{".4.5.6", "7.8.9"},
					},
				},
			},
			err: "request[1]: all OIDs must begin with a dot, got: 7.8.9",
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
