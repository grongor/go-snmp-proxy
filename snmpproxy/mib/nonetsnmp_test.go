// +build nonetsnmp

package mib_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/grongor/go-snmp-proxy/snmpproxy/mib"
)

func TestNopMibParser_Parse(t *testing.T) {
	parser := mib.NewNetsnmpMibParser(nil, false)
	hints, err := parser.Parse()
	require.Nil(t, hints)
	require.Nil(t, err)
}
