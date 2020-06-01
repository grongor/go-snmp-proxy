package snmpproxy_test

import (
	"errors"
	"io"
	"io/ioutil"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/mock"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/grongor/go-snmp-proxy/snmpproxy"
)

type mockRequester struct {
	mock.Mock
}

func (r *mockRequester) ExecuteRequest(request snmpproxy.Request) ([]interface{}, error) {
	args := r.Mock.Called(request)

	result := args.Get(0)
	if result == nil {
		return nil, args.Error(1)
	}

	return result.([]interface{}), args.Error(1)
}

type errReader struct {
}

func (errReader) Read(_ []byte) (n int, err error) {
	return 0, errors.New("test error")
}

const getRequestBody = `
{
    "request_type": "get",
    "host": "localhost",
    "oids": [".1.2.3"],
    "version": "2c",
    "timeout": 3
}
`

func TestHandlerErrorNotPost(t *testing.T) {
	require := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "")

	request := httptest.NewRequest("GET", "/snmp-proxy", errReader{})

	recorder := httptest.NewRecorder()
	listener.ServeHTTP(recorder, request)

	response := recorder.Result()
	require.Equal(http.StatusMethodNotAllowed, response.StatusCode)
}

func TestHandlerErrorReadingRequest(t *testing.T) {
	require := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "")

	request := httptest.NewRequest("POST", "/snmp-proxy", errReader{})

	recorder := httptest.NewRecorder()
	listener.ServeHTTP(recorder, request)

	response := recorder.Result()
	require.Equal(http.StatusBadRequest, response.StatusCode)
	require.Equal(`{"error":"test error"}`, read(response.Body))
}

func TestHandlerErrorUnmarshalingRequest(t *testing.T) {
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
			err:         `{"error":"field request_type mustn't be empty"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require := require.New(t)

			prometheus.DefaultRegisterer = prometheus.NewRegistry()

			requester := &mockRequester{}
			defer requester.AssertExpectations(t)

			listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "")

			request := httptest.NewRequest("POST", "/snmp-proxy", strings.NewReader(test.requestBody))

			recorder := httptest.NewRecorder()
			listener.ServeHTTP(recorder, request)

			response := recorder.Result()
			require.Equal(http.StatusBadRequest, response.StatusCode)
			require.Equal(test.err, read(response.Body))
		})
	}
}

func TestHandlerErrorRequestValidatorError(t *testing.T) {
	require := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "")

	requestBody := `
{
    "request_type": "get",
    "host": "localhost",
    "oids": [".1.2.3"],
    "version": "2c",
    "timeout": 100
}
`

	request := httptest.NewRequest("POST", "/snmp-proxy", strings.NewReader(requestBody))

	recorder := httptest.NewRecorder()
	listener.ServeHTTP(recorder, request)

	response := recorder.Result()

	require.Equal(http.StatusBadRequest, response.StatusCode)
	require.Equal(`{"error":"maximum allowed timeout is 10 seconds, got 100 seconds"}`, read(response.Body))
}

func TestHandlerErrorRequesterError(t *testing.T) {
	require := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}
	defer requester.AssertExpectations(t)

	requester.On("ExecuteRequest", mock.Anything).Once().Return(nil, errors.New("some error"))

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "")

	request := httptest.NewRequest("POST", "/snmp-proxy", strings.NewReader(getRequestBody))

	recorder := httptest.NewRecorder()
	listener.ServeHTTP(recorder, request)

	response := recorder.Result()

	require.Equal(http.StatusInternalServerError, response.StatusCode)
	require.Equal(`{"error":"some error"}`, read(response.Body))
}

func TestHandlerNoError(t *testing.T) {
	require := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}
	defer requester.AssertExpectations(t)

	requester.On("ExecuteRequest", mock.Anything).Once().Return([]interface{}{".1.2.3", 123}, nil)

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "")

	request := httptest.NewRequest("POST", "/snmp-proxy", strings.NewReader(getRequestBody))

	recorder := httptest.NewRecorder()
	listener.ServeHTTP(recorder, request)

	response := recorder.Result()

	require.Equal(http.StatusOK, response.StatusCode)
	require.Equal(`{"result":[".1.2.3",123]}`, read(response.Body))
}

func TestStartAndClose(t *testing.T) {
	require := require.New(t)

	prometheus.DefaultRegisterer = prometheus.NewRegistry()

	requester := &mockRequester{}
	defer requester.AssertExpectations(t)

	requester.On("ExecuteRequest", mock.Anything).Once().Return([]interface{}{".1.2.3", 123}, nil)

	listener := snmpproxy.NewApiListener(newValidator(), requester, zap.NewNop().Sugar(), "localhost:15721")
	listener.Start()

	time.Sleep(time.Millisecond * 10)

	response, err := http.Post("http://localhost:15721/snmp-proxy", "", strings.NewReader(getRequestBody))
	require.NoError(err)
	require.Equal(http.StatusOK, response.StatusCode)
	require.Equal(`{"result":[".1.2.3",123]}`, read(response.Body))

	listener.Close()

	response, err = http.Post("http://localhost:15721/snmp-proxy", "", strings.NewReader(getRequestBody))
	require.Nil(response)
	require.Error(err)
}

func read(r io.Reader) string {
	b, err := ioutil.ReadAll(r)
	if err != nil {
		panic(err)
	}

	return string(b)
}

func newValidator() *snmpproxy.RequestValidator {
	return snmpproxy.NewRequestValidator(10, 10)
}
