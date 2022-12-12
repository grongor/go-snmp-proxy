//go:build nonetsnmp

package mib

import (
	"go.uber.org/zap"
)

type NopMibParser struct {
}

func (n NopMibParser) Parse() (DisplayHints, error) {
	return nil, nil
}

func NewNopMibParser() *NopMibParser {
	return &NopMibParser{}
}

func NewNetsnmpMibParser(*zap.SugaredLogger, bool) Parser {
	return NewNopMibParser()
}
