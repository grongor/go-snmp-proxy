package snmpproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

type ApiListener struct {
	validator         *RequestValidator
	requester         Requester
	logger            *zap.SugaredLogger
	server            *http.Server
	socketPermissions os.FileMode
}

func (l *ApiListener) Start() error {
	var (
		ln  net.Listener
		err error
	)

	if strings.HasSuffix(l.server.Addr, ".sock") {
		ln, err = net.Listen("unix", l.server.Addr)
		if err == nil && l.socketPermissions != 0 {
			err = os.Chmod(l.server.Addr, l.socketPermissions)
			if err != nil {
				ln.Close()
			}
		}
	} else {
		ln, err = net.Listen("tcp", l.server.Addr)
	}

	if err != nil {
		return err
	}

	go func() {
		err := l.server.Serve(ln)
		if !errors.Is(err, http.ErrServerClosed) {
			l.logger.Fatalw("http.Serve error", zap.Error(err))
		}
	}()

	l.logger.Info("API listener started")

	return nil
}

func (l *ApiListener) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		writer.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	apiRequest := &ApiRequest{}
	var response = Response{}

	defer func() {
		_, _ = writer.Write(response.Bytes())
	}()

	body, err := ioutil.ReadAll(request.Body)
	if err != nil {
		l.logger.Debugw("failed to read request body", zap.Error(err))
		writer.WriteHeader(http.StatusBadRequest)

		response.Error = err.Error()

		return
	}

	err = json.Unmarshal(body, apiRequest)
	if err != nil {
		l.logger.Debugw("failed unmarshal API request", zap.Error(err), "requestBody", string(body))
		writer.WriteHeader(http.StatusBadRequest)

		response.Error = err.Error()

		return
	}

	err = l.validator.Validate(apiRequest)
	if err != nil {
		l.logger.Debugw("invalid API request", zap.Error(err), "request", apiRequest)
		writer.WriteHeader(http.StatusBadRequest)

		response.Error = err.Error()

		return
	}

	result, err := l.requester.ExecuteRequest(apiRequest)
	if err == nil {
		l.logger.Debugw("request successful", "request", apiRequest)

		writer.WriteHeader(http.StatusOK)

		response.Result = result
	} else {
		l.logger.Debugw("request failed", zap.Error(err), "request", apiRequest)

		writer.WriteHeader(http.StatusInternalServerError)

		response.Error = err.Error()
	}
}

func (l *ApiListener) Close() {
	ctx, cancel := context.WithTimeout(context.Background(), time.Second*5)
	defer cancel()

	err := l.server.Shutdown(ctx)
	if errors.Is(err, ctx.Err()) {
		l.server.Close()
	}
}

func NewApiListener(
	validator *RequestValidator,
	requester Requester,
	logger *zap.SugaredLogger,
	listen string,
	socketPermissions os.FileMode,
) *ApiListener {
	mux := http.NewServeMux()

	listener := &ApiListener{
		validator:         validator,
		requester:         requester,
		logger:            logger,
		server:            &http.Server{Addr: listen, Handler: mux},
		socketPermissions: socketPermissions,
	}

	metricOpts := prometheus.HistogramOpts{
		Namespace: "snmpproxy",
		Name:      "requests",
		Help:      "Number of issued requests and their duration",
	}
	handler := promhttp.InstrumentHandlerDuration(promauto.NewHistogramVec(metricOpts, nil), listener)

	mux.Handle("/snmp-proxy", handler)

	return listener
}
