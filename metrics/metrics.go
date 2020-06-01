package metrics

import (
	"errors"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.uber.org/zap"
)

func Start(logger *zap.SugaredLogger, listen string) {
	stdLogger, err := zap.NewStdLogAt(logger.Desugar().Named("prometheus"), zap.ErrorLevel)
	if err != nil {
		logger.Fatalw("failed to create stdLogger for Prometheus", zap.Error(err))
	}

	http.Handle(
		"/metrics",
		promhttp.InstrumentMetricHandler(
			prometheus.DefaultRegisterer,
			promhttp.HandlerFor(prometheus.DefaultGatherer, promhttp.HandlerOpts{ErrorLog: stdLogger}),
		),
	)

	go func() {
		err = http.ListenAndServe(listen, nil)
		if !errors.Is(err, http.ErrServerClosed) {
			logger.Fatalw("failed to start metrics listener", zap.Error(err))
		}
	}()
}
