package main

import (
	"flag"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/TheZeroSlave/zapsentry"
	"github.com/spf13/viper"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

type Configuration struct {
	Api struct {
		Listen            string
		SocketPermissions os.FileMode // only ever used when Listen is a Unix socket
	}
	Common struct {
		Debug      bool
		Panicwatch bool
		Sentry     struct {
			Dsn string
		}
	}
	Metrics struct {
		Listen string
	}
	Snmp struct {
		MaxTimeoutSeconds uint
		MaxRetries        uint8
		StrictMibParsing  bool
	}
	Logger *zap.SugaredLogger
}

func (c *Configuration) setupLogger() {
	loggerConfig := zap.NewDevelopmentConfig()
	loggerConfig.DisableCaller = true
	loggerConfig.DisableStacktrace = true

	if !c.Common.Debug {
		loggerConfig.Level = zap.NewAtomicLevelAt(zap.InfoLevel)
	}

	logger, err := loggerConfig.Build()
	if err != nil {
		panic("failed to create logger: " + err.Error())
	}

	if c.Common.Sentry.Dsn != "" {
		logger = c.setupSentryLogging(logger)
	}

	c.Logger = logger.Sugar()
}

func (c *Configuration) setupSentryLogging(logger *zap.Logger) *zap.Logger {
	cfg := zapsentry.Configuration{Level: zapcore.WarnLevel}
	core, err := zapsentry.NewCore(cfg, zapsentry.NewSentryClientFromDSN(c.Common.Sentry.Dsn))

	if err != nil {
		logger.Fatal("failed to initialize zapsentry core", zap.Error(err))
	}

	return zapsentry.AttachCoreToLogger(core, logger)
}

func NewConfiguration() *Configuration {
	configFile := flag.String("config", "", "path to a config file (default is to look for config.toml in "+
		"the working directory and the directory of this executable)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\nAvailable options:\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	time.Local = time.UTC

	v := viper.New()

	if *configFile != "" {
		v.SetConfigFile(*configFile)
	} else {
		v.SetConfigType("toml")

		v.AddConfigPath(".")

		executable, _ := os.Executable()
		v.AddConfigPath(path.Dir(executable))
	}

	err := v.ReadInConfig()
	if err != nil {
		panic("failed to read the configuration file: " + err.Error())
	}

	config := &Configuration{}
	if err = v.Unmarshal(&config); err != nil {
		panic("failed to unmarshal Configuration: " + err.Error())
	}

	config.setupLogger()

	if config.Api.Listen == "" {
		config.Logger.Fatal("missing config option Api.Listen")
	}

	return config
}
