//go:build !nonetsnmp
// +build !nonetsnmp

package mib_test

import (
	"testing"

	"github.com/grongor/go-snmp-proxy/snmpproxy/mib"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestNetsnmpMibParser_Parse(t *testing.T) {
	assert := require.New(t)

	mibParser := mib.NewNetsnmpMibParser(zap.NewNop().Sugar(), false)
	displayHints, err := mibParser.Parse()

	assert.NoError(err)
	assert.NotEmpty(displayHints)
	assert.Equal(mib.DisplayHintString, displayHints[".1.3.6.1.2.1.2.2.1.2"])
	assert.Equal(mib.DisplayHintHexadecimal, displayHints[".1.3.6.1.2.1.4.22.1.2"])
}
