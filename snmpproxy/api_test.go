package snmpproxy_test

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/grongor/go-snmp-proxy/snmpproxy"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

type mockRequester struct {
	mock.Mock
}

func (r *mockRequester) ExecuteRequest(apiRequest *snmpproxy.ApiRequest) ([][]any, error) {
	args := r.Mock.Called(apiRequest)

	result := args.Get(0)
	if result == nil {
		return nil, args.Error(1)
	}

	return result.([][]any), args.Error(1)
}

type errReader struct{}

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("test error")
}

const getRequestBody = `
{
    "host": "localhost",
    "version": "2c",
    "timeout": 3,
    "requests": [
        {"request_type": "get", "oids": [".1.2.3"]}
    ]
}
`

func TestListenerErrorNotPost(t *testing.T) {
	assert := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "", 0)

	request := httptest.NewRequest("GET", "/snmp-proxy", errReader{})

	recorder := httptest.NewRecorder()
	listener.ServeHTTP(recorder, request)

	response := recorder.Result()
	assert.Equal(http.StatusMethodNotAllowed, response.StatusCode)
}

func TestListenerErrorReadingRequest(t *testing.T) {
	assert := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "", 0)

	request := httptest.NewRequest("POST", "/snmp-proxy", errReader{})

	recorder := httptest.NewRecorder()
	listener.ServeHTTP(recorder, request)

	response := recorder.Result()
	assert.Equal(http.StatusBadRequest, response.StatusCode)
	assert.Equal(`{"error":"test error"}`, read(response.Body))
}

func TestListenerErrorUnmarshalingRequest(t *testing.T) {
	tests := []struct {
		name        string
		requestBody string
		err         string
	}{
		{
			name:        "unexpected input",
			requestBody: "whatever",
			err:         `{"error":"invalid character 'w' looking for beginning of value"}`,
		},
		{
			name:        "not expected json struct",
			requestBody: `{"something": "else"}`,
			err:         `{"error":"field host mustn't be empty"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := require.New(t)

			prometheus.DefaultRegisterer = prometheus.NewRegistry()

			requester := &mockRequester{}
			defer requester.AssertExpectations(t)

			listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "", 0)

			request := httptest.NewRequest("POST", "/snmp-proxy", strings.NewReader(test.requestBody))

			recorder := httptest.NewRecorder()
			listener.ServeHTTP(recorder, request)

			response := recorder.Result()
			assert.Equal(http.StatusBadRequest, response.StatusCode)
			assert.Equal(test.err, read(response.Body))
		})
	}
}

func TestListenerErrorRequestValidatorError(t *testing.T) {
	assert := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "", 0)

	const requestBody = `
{
    "host": "localhost",
    "version": "2c",
    "timeout": 100,
    "requests": [
        {"request_type": "get", "oids": [".1.2.3"]}
    ]
}
`

	request := httptest.NewRequest("POST", "/snmp-proxy", strings.NewReader(requestBody))

	recorder := httptest.NewRecorder()
	listener.ServeHTTP(recorder, request)

	response := recorder.Result()

	assert.Equal(http.StatusBadRequest, response.StatusCode)
	assert.Equal(`{"error":"maximum allowed timeout is 10 seconds, got 100 seconds"}`, read(response.Body))
}

func TestListenerErrorRequesterError(t *testing.T) {
	assert := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}
	defer requester.AssertExpectations(t)

	requester.On("ExecuteRequest", mock.Anything).Once().Return(nil, errors.New("some error"))

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "", 0)

	request := httptest.NewRequest("POST", "/snmp-proxy", strings.NewReader(getRequestBody))

	recorder := httptest.NewRecorder()
	listener.ServeHTTP(recorder, request)

	response := recorder.Result()

	assert.Equal(http.StatusInternalServerError, response.StatusCode)
	assert.Equal(`{"error":"some error"}`, read(response.Body))
}

func TestListenerNoError(t *testing.T) {
	assert := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}
	defer requester.AssertExpectations(t)

	requester.On("ExecuteRequest", mock.Anything).Once().Return([][]any{{".1.2.3", 123}}, nil)

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "", 0)

	request := httptest.NewRequest("POST", "/snmp-proxy", strings.NewReader(getRequestBody))

	recorder := httptest.NewRecorder()
	listener.ServeHTTP(recorder, request)

	response := recorder.Result()

	assert.Equal(http.StatusOK, response.StatusCode)
	assert.Equal(`{"result":[[".1.2.3",123]]}`, read(response.Body))
}

func TestStartAndClose(t *testing.T) {
	assert := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}
	defer requester.AssertExpectations(t)

	requester.On("ExecuteRequest", mock.Anything).Once().Return([][]any{{".1.2.3", 123}}, nil)

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "localhost:15721", 0)
	listener.Start()

	time.Sleep(time.Millisecond * 10)

	response, err := http.Post("http://localhost:15721/snmp-proxy", "", strings.NewReader(getRequestBody))
	assert.NoError(err)
	assert.Equal(http.StatusOK, response.StatusCode)
	assert.Equal(`{"result":[[".1.2.3",123]]}`, read(response.Body))

	listener.Close()

	response, err = http.Post("http://localhost:15721/snmp-proxy", "", strings.NewReader(getRequestBody))
	assert.Nil(response)
	assert.Error(err)
}

func TestStartAndCloseOnSocket(t *testing.T) {
	assert := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}
	defer requester.AssertExpectations(t)

	requester.On("ExecuteRequest", mock.Anything).Once().Return([][]any{{".1.2.3", 123}}, nil)

	f, err := os.CreateTemp("", "snmp-proxy-test-*.sock")
	assert.NoError(err)
	assert.NoError(f.Close())
	assert.NoError(os.Remove(f.Name()))

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), f.Name(), 0)
	err = listener.Start()
	assert.NoError(err)

	time.Sleep(time.Millisecond * 10)

	client := http.Client{
		Transport: &http.Transport{
			DialContext: func(context.Context, string, string) (net.Conn, error) {
				return net.Dial("unix", f.Name())
			},
		},
	}

	response, err := client.Post("http://socket/snmp-proxy", "", strings.NewReader(getRequestBody))
	assert.NoError(err)
	assert.Equal(http.StatusOK, response.StatusCode)
	assert.Equal(`{"result":[[".1.2.3",123]]}`, read(response.Body))

	listener.Close()

	response, err = client.Post("http://socket/snmp-proxy", "", strings.NewReader(getRequestBody))
	assert.Nil(response)
	assert.Error(err)
}

func TestStartSocketWithCorrectPermissions(t *testing.T) {
	assert := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}

	f, err := os.CreateTemp("", "snmp-proxy-test-*.sock")
	assert.NoError(err)
	assert.NoError(f.Close())
	assert.NoError(os.Remove(f.Name()))

	expectedMode := os.FileMode(0o124)

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), f.Name(), expectedMode)
	err = listener.Start()
	assert.NoError(err)

	stat, err := os.Stat(f.Name())
	assert.NoError(err)
	assert.Equal(expectedMode, stat.Mode().Perm())
}

func TestStartError(t *testing.T) {
	assert := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	listener := snmpproxy.NewApiListener(newValidator(), &mockRequester{}, zap.NewNop().Sugar(), "localhost:80", 0)
	err := listener.Start()
	assert.EqualError(err, "listen tcp 127.0.0.1:80: bind: permission denied")
}

func read(r io.Reader) string {
	b, err := io.ReadAll(r)
	if err != nil {
		panic(err)
	}

	return string(b)
}

func newValidator() *snmpproxy.RequestValidator {
	return snmpproxy.NewRequestValidator(10, 10)
}
