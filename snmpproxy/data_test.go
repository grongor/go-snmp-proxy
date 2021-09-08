package snmpproxy_test

import (
	"testing"
	"time"

	"github.com/gosnmp/gosnmp"
	"github.com/grongor/go-snmp-proxy/snmpproxy"
	"github.com/stretchr/testify/require"
)

func TestUnmarshalRequestType(t *testing.T) {
	tests := []struct {
		name     string
		raw      []byte
		expected snmpproxy.RequestType
		err      string
	}{
		{name: "get", raw: []byte("\"get\""), expected: snmpproxy.Get, err: ""},
		{name: "getNext", raw: []byte("\"getNext\""), expected: snmpproxy.GetNext, err: ""},
		{name: "walk", raw: []byte("\"walk\""), expected: snmpproxy.Walk, err: ""},
		{
			name:     "not a string",
			raw:      []byte("123"),
			expected: "",
			err: "RequestType must be a string, got 123: json: " +
				"cannot unmarshal number into Go value of type string",
		},
		{name: "missing", raw: []byte("\"\""), expected: "", err: "RequestType mustn't be empty"},
		{name: "invalid", raw: []byte("\"whatever\""), expected: "", err: "unknown RequestType \"whatever\""},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var requestType snmpproxy.RequestType
			err := requestType.UnmarshalJSON(test.raw)
			if test.err == "" {
				require.NoError(t, err)
				require.Equal(t, test.expected, requestType)
			} else {
				require.EqualError(t, err, test.err)
			}
		})
	}
}

func TestUnmarshalSnmpVersion(t *testing.T) {
	tests := []struct {
		name     string
		raw      []byte
		expected snmpproxy.SnmpVersion
		err      string
	}{
		{name: "v1", raw: []byte("\"1\""), expected: snmpproxy.SnmpVersion(gosnmp.Version1), err: ""},
		{name: "v2", raw: []byte("\"2c\""), expected: snmpproxy.SnmpVersion(gosnmp.Version2c), err: ""},
		{
			name:     "not a string",
			raw:      []byte("123"),
			expected: 0,
			err: "snmpVersion must be a string, got 123: json: " +
				"cannot unmarshal number into Go value of type string",
		},
		{name: "missing", raw: []byte("\"\""), expected: 0, err: "snmpVersion mustn't be empty"},
		{
			name:     "invalid",
			raw:      []byte("\"whatever\""),
			expected: 0,
			err:      "unknown or unsupported snmpVersion \"whatever\", supported are: 1, 2c",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var version snmpproxy.SnmpVersion
			err := version.UnmarshalJSON(test.raw)
			if test.err == "" {
				require.NoError(t, err)
				require.Equal(t, test.expected, version)
			} else {
				require.EqualError(t, err, test.err)
			}
		})
	}
}

func TestUnmarshalRequest(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected snmpproxy.Request
		err      string
	}{
		{
			name: "all fields filled",
			raw: `
{
    "request_type": "walk",
    "oids": [".1.2.3"],
    "max_repetitions": 10
}
`,
			expected: snmpproxy.Request{
				RequestType:    snmpproxy.Walk,
				Oids:           []string{".1.2.3"},
				MaxRepetitions: 10,
			},
			err: "",
		},
		{
			name: "only required fields filled",
			raw: `
{
    "request_type": "get",
    "oids": [".1.2.3"]
}
`,
			expected: snmpproxy.Request{
				RequestType: snmpproxy.Get,
				Oids:        []string{".1.2.3"},
			},
			err: "",
		},
		{
			name:     "missing request type",
			raw:      "{}",
			expected: snmpproxy.Request{},
			err:      "field request_type mustn't be empty",
		},
		{
			name:     "invalid json",
			raw:      "{",
			expected: snmpproxy.Request{},
			err:      `failed to unmarshal Request struct, got {: unexpected end of JSON input`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request snmpproxy.Request
			err := request.UnmarshalJSON([]byte(test.raw))
			if test.err == "" {
				require.NoError(t, err)
				require.Equal(t, test.expected, request)
			} else {
				require.EqualError(t, err, test.err)
			}
		})
	}
}

func TestUnmarshalApiRequest(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		expected snmpproxy.ApiRequest
		err      string
	}{
		{
			name: "all fields filled",
			raw: `
{
    "host": "localhost",
    "community": "public",
    "version": "2c",
    "timeout": 10,
    "retries": 3,
    "requests": [
        {"request_type": "walk", "oids": [".1.2.3"], "max_repetitions": 10}
    ]
}
`,
			expected: snmpproxy.ApiRequest{
				Host:      "localhost",
				Community: "public",
				Version:   snmpproxy.SnmpVersion(gosnmp.Version2c),
				Timeout:   10 * time.Second,
				Retries:   3,
				Requests: []snmpproxy.Request{
					{RequestType: snmpproxy.Walk, Oids: []string{".1.2.3"}, MaxRepetitions: 10},
				},
			},
			err: "",
		},
		{
			name: "only required fields filled",
			raw: `
{
    "host": "localhost",
    "version": "2c",
    "timeout": 3,
    "requests": [
        {"request_type": "get", "oids": [".1.2.3", ".4.5.6"]}
    ]
}
`,
			expected: snmpproxy.ApiRequest{
				Host:      "localhost",
				Community: "public",
				Version:   snmpproxy.SnmpVersion(gosnmp.Version2c),
				Timeout:   3 * time.Second,
				Retries:   0,
				Requests: []snmpproxy.Request{
					{RequestType: snmpproxy.Get, Oids: []string{".1.2.3", ".4.5.6"}},
				},
			},
			err: "",
		},
		{
			name: "only required fields filled, multiple requests",
			raw: `
{
    "host": "localhost",
    "version": "2c",
    "timeout": 3,
    "requests": [
        {"request_type": "get", "oids": [".1.2.3", ".4.5.6"]},
        {"request_type": "walk", "oids": [".7.8.9"], "max_repetitions": 5}
    ]
}
`,
			expected: snmpproxy.ApiRequest{
				Host:      "localhost",
				Community: "public",
				Version:   snmpproxy.SnmpVersion(gosnmp.Version2c),
				Timeout:   3 * time.Second,
				Retries:   0,
				Requests: []snmpproxy.Request{
					{RequestType: snmpproxy.Get, Oids: []string{".1.2.3", ".4.5.6"}},
					{RequestType: snmpproxy.Walk, Oids: []string{".7.8.9"}, MaxRepetitions: 5},
				},
			},
			err: "",
		},
		{
			name:     "missing host",
			raw:      "{}",
			expected: snmpproxy.ApiRequest{},
			err:      "field host mustn't be empty",
		},
		{
			name: "missing version",
			raw: `
{
    "host": "localhost"
}
`,
			expected: snmpproxy.ApiRequest{},
			err:      "field version mustn't be empty",
		},
		{
			name: "missing timeout",
			raw: `
{
    "host": "localhost",
    "version": "2c"
}
`,
			expected: snmpproxy.ApiRequest{},
			err:      "field timeout mustn't be empty or zero",
		},
		{
			name:     "invalid json",
			raw:      "{",
			expected: snmpproxy.ApiRequest{},
			err:      `failed to unmarshal request body into ApiRequest struct, got {: unexpected end of JSON input`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var request snmpproxy.ApiRequest
			err := request.UnmarshalJSON([]byte(test.raw))
			if test.err == "" {
				require.NoError(t, err)
				require.Equal(t, test.expected, request)
			} else {
				require.EqualError(t, err, test.err)
			}
		})
	}
}

func TestMarshalResponse(t *testing.T) {
	tests := []struct {
		name     string
		response snmpproxy.Response
		expected string
	}{
		{
			name:     "success",
			response: snmpproxy.Response{Result: [][]interface{}{{".1.2.3", 123, ".4.5.6", "lorem"}}},
			expected: `{"result":[[".1.2.3",123,".4.5.6","lorem"]]}`,
		},
		{
			name:     "failure",
			response: snmpproxy.Response{Error: "some error"},
			expected: `{"error":"some error"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, []byte(test.expected), test.response.Bytes())
		})
	}
}

func TestMarshalResponseWithError(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			require.EqualError(t, r.(error), "json: unsupported type: chan struct {}")
		}
	}()

	(&snmpproxy.Response{Result: [][]interface{}{{make(chan struct{})}}}).Bytes()
}
