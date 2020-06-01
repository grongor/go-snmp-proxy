package snmpproxy

import (
	"context"
	"encoding/json"
	"errors"
	"io/ioutil"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

type ApiListener struct {
	validator *RequestValidator
	requester Requester
	logger    *zap.SugaredLogger
	server    *http.Server
}

func (l *ApiListener) Start() {
	go func() {
		err := l.server.ListenAndServe()
		if !errors.Is(err, http.ErrServerClosed) {
			l.logger.Fatalw("failed to start API listener", zap.Error(err))
		}
	}()

	l.logger.Info("API listener started")
}

func (l *ApiListener) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != "POST" {
		writer.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	var apiRequest Request
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

	err = json.Unmarshal(body, &apiRequest)
	if err != nil {
		l.logger.Debugw("failed unmarshal API request", zap.Error(err))
		writer.WriteHeader(http.StatusBadRequest)

		response.Error = err.Error()

		return
	}

	err = l.validator.Validate(apiRequest)
	if err != nil {
		l.logger.Debugw("invalid API request", zap.Error(err))
		writer.WriteHeader(http.StatusBadRequest)

		response.Error = err.Error()

		return
	}

	result, err := l.requester.ExecuteRequest(apiRequest)
	if err == nil {
		writer.WriteHeader(http.StatusOK)

		response.Result = result
	} else {
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
) *ApiListener {
	mux := http.NewServeMux()

	listener := &ApiListener{
		validator: validator,
		requester: requester,
		logger:    logger,
		server:    &http.Server{Addr: listen, Handler: mux},
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
