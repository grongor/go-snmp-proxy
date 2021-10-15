package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/grongor/go-snmp-proxy/metrics"
	"github.com/grongor/go-snmp-proxy/snmpproxy"
	"github.com/grongor/go-snmp-proxy/snmpproxy/mib"
	"github.com/grongor/panicwatch"
	"go.uber.org/zap"
)

func main() {
	config := NewConfiguration()

	if config.Common.Panicwatch {
		startPanicwatch(config.Logger)
	}

	if config.Metrics.Listen != "" {
		metrics.Start(config.Logger, config.Metrics.Listen)
	}

	validator := snmpproxy.NewRequestValidator(config.Snmp.MaxTimeoutSeconds, config.Snmp.MaxRetries)

	mibParser := mib.NewNetsnmpMibParser(config.Logger, config.Snmp.StrictMibParsing)

	displayHints, err := mibParser.Parse()
	if err != nil {
		config.Logger.Fatalw("mib parser error: ", zap.Error(err))
	}

	requester := snmpproxy.NewGosnmpRequester(snmpproxy.NewValueFormatter(mib.NewDataProvider(displayHints)))

	apiListener := snmpproxy.NewApiListener(
		validator,
		requester,
		config.Logger,
		config.Api.Listen,
		config.Api.SocketPermissions,
	)

	err = apiListener.Start()
	if err != nil {
		config.Logger.Fatalw("failed to start API listener", zap.Error(err))
	}

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)

	<-signals
	config.Logger.Info("received shutdown signal, exiting")
	apiListener.Close()
}

func startPanicwatch(logger *zap.SugaredLogger) {
	log := logger.Named("panicwatch")

	config := panicwatch.Config{
		OnPanic: func(p panicwatch.Panic) {
			log.Fatalw(p.Message, "panic", p)
		},
		OnWatcherError: func(err error) {
			log.Fatalw("watcher error", zap.Error(err))
		},
		OnWatcherDied: func(err error) {
			log.Fatalw("watcher died", zap.Error(err))
		},
	}

	err := panicwatch.Start(config)
	if err != nil {
		logger.Fatalw("failed to start panicwatch", zap.Error(err))
	}
}
