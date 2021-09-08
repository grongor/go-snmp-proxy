package mib_test

import (
	"testing"

	"github.com/grongor/go-snmp-proxy/snmpproxy/mib"
	"github.com/stretchr/testify/require"
)

func TestMibDataProvider_GetStringType(t *testing.T) {
	tests := []struct {
		name        string
		stringTypes mib.DisplayHints
		oid         string
		expected    mib.DisplayHint
	}{
		{
			name: "exact match",
			stringTypes: mib.DisplayHints{
				".1.2.3.1.1.5.15.2": mib.DisplayHintString,
				".1.2.3.1.1.5.15":   mib.DisplayHintHexadecimal,
			},
			oid:      ".1.2.3.1.1.5.15.2",
			expected: mib.DisplayHintString,
		},
		{
			name: "parent matched",
			stringTypes: mib.DisplayHints{
				".1.2.3.1.1.5.15.22": mib.DisplayHintHexadecimal,
				".1.2.3.1.1.5.15":    mib.DisplayHintString,
			},
			oid:      ".1.2.3.1.1.5.15.2",
			expected: mib.DisplayHintString,
		},
		{
			name: "parent matched (multiple steps back)",
			stringTypes: mib.DisplayHints{
				".1.2.3.1.1.5.15.22": mib.DisplayHintString,
				".1.2.3.1.1.5.1":     mib.DisplayHintString,
				".1.2.3.1.1.1":       mib.DisplayHintString,
				".1.2.3.1.11":        mib.DisplayHintString,
				".1.2.3.1":           mib.DisplayHintHexadecimal,
			},
			oid:      ".1.2.3.1.1.5.15.2",
			expected: mib.DisplayHintHexadecimal,
		},
		{
			name:        "OID is too short to consider -> unknown type",
			stringTypes: mib.DisplayHints{".1.2.3": mib.DisplayHintHexadecimal},
			oid:         ".1.2.3",
			expected:    mib.DisplayHintUnknown,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, mib.NewDataProvider(test.stringTypes).GetDisplayHint(test.oid))
		})
	}
}
