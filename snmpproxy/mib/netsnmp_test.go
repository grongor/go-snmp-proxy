// +build !nonetsnmp

package mib_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/grongor/go-snmp-proxy/snmpproxy/mib"
)

func TestNetsnmpMibParser_Parse(t *testing.T) {
	require := require.New(t)

	mibParser := mib.NewNetsnmpMibParser(zap.NewNop().Sugar(), false)
	displayHints, err := mibParser.Parse()

	require.NoError(err)
	require.NotEmpty(displayHints)
	require.Equal(mib.DisplayHintString, displayHints[".1.3.6.1.2.1.2.2.1.2"])
	require.Equal(mib.DisplayHintHexadecimal, displayHints[".1.3.6.1.2.1.4.22.1.2"])
}
