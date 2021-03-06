package main

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/grongor/panicwatch"
	"go.uber.org/zap"

	"github.com/grongor/go-snmp-proxy/metrics"
	"github.com/grongor/go-snmp-proxy/snmpproxy"
	"github.com/grongor/go-snmp-proxy/snmpproxy/mib"
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

	mibDataProvider := mib.NewDataProvider(displayHints)
	requester := snmpproxy.NewGosnmpRequester(mibDataProvider)

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

	panicwatch.Config.OnError = func(err error) {
		log.Error(err.Error())
	}

	err := panicwatch.Start(func(p panicwatch.Panic) {
		log.Fatalw("panic: "+p.Message, "stack", p.Stack)
	})
	if err != nil {
		logger.Fatalw("failed to start panicwatch", zap.Error(err))
	}
}
