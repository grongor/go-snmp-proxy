package snmpproxy_test

import (
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/grongor/go-snmp-proxy/snmpproxy"
)

func TestNetsnmpMibParser_Parse(t *testing.T) {
	require := require.New(t)

	mibParser := snmpproxy.NewNetsnmpMibParser(zap.NewNop().Sugar(), false)
	displayHints, err := mibParser.Parse()

	require.NoError(err)
	require.NotEmpty(displayHints)
	require.Equal(snmpproxy.DisplayHintString, displayHints[".1.3.6.1.2.1.2.2.1.2"])
	require.Equal(snmpproxy.DisplayHintHexadecimal, displayHints[".1.3.6.1.2.1.4.22.1.2"])
}

func TestMibDataProvider_GetStringType(t *testing.T) {
	tests := []struct {
		name        string
		stringTypes snmpproxy.DisplayHints
		oid         string
		expected    snmpproxy.DisplayHint
	}{
		{
			name: "exact match",
			stringTypes: snmpproxy.DisplayHints{
				".1.2.3.1.1.5.15.2": snmpproxy.DisplayHintString,
				".1.2.3.1.1.5.15":   snmpproxy.DisplayHintHexadecimal,
			},
			oid:      ".1.2.3.1.1.5.15.2",
			expected: snmpproxy.DisplayHintString,
		},
		{
			name: "parent matched",
			stringTypes: snmpproxy.DisplayHints{
				".1.2.3.1.1.5.15.22": snmpproxy.DisplayHintHexadecimal,
				".1.2.3.1.1.5.15":    snmpproxy.DisplayHintString,
			},
			oid:      ".1.2.3.1.1.5.15.2",
			expected: snmpproxy.DisplayHintString,
		},
		{
			name: "parent matched (multiple steps back)",
			stringTypes: snmpproxy.DisplayHints{
				".1.2.3.1.1.5.15.22": snmpproxy.DisplayHintString,
				".1.2.3.1.1.5.1":     snmpproxy.DisplayHintString,
				".1.2.3.1.1.1":       snmpproxy.DisplayHintString,
				".1.2.3.1.11":        snmpproxy.DisplayHintString,
				".1.2.3.1":           snmpproxy.DisplayHintHexadecimal,
			},
			oid:      ".1.2.3.1.1.5.15.2",
			expected: snmpproxy.DisplayHintHexadecimal,
		},
		{
			name:        "OID is too short to consider -> unknown type",
			stringTypes: snmpproxy.DisplayHints{".1.2.3": snmpproxy.DisplayHintHexadecimal},
			oid:         ".1.2.3",
			expected:    snmpproxy.DisplayHintUnknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, snmpproxy.NewMibDataProvider(test.stringTypes).GetDisplayHint(test.oid))
		})
	}
}
