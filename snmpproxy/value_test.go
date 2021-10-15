package snmpproxy_test

import (
	"testing"

	"github.com/gosnmp/gosnmp"
	"github.com/grongor/go-snmp-proxy/snmpproxy"
	"github.com/grongor/go-snmp-proxy/snmpproxy/mib"
	"github.com/stretchr/testify/require"
)

func TestValueFormatter_Format(t *testing.T) {
	formatter := snmpproxy.NewValueFormatter(
		mib.NewDataProvider(
			map[string]mib.DisplayHint{
				".1.3.6.3": mib.DisplayHintString,
				".1.3.6.4": mib.DisplayHintHexadecimal,
				".1.3.6.5": mib.DisplayHintDateAndTime,
			},
		),
	)

	tests := []struct {
		name     string
		pdu      gosnmp.SnmpPDU
		expected interface{}
	}{
		{
			name:     "not octet string",
			pdu:      gosnmp.SnmpPDU{Name: ".666", Type: gosnmp.Integer, Value: 123},
			expected: 123,
		},
		{
			name:     "no display hint, not printable",
			pdu:      gosnmp.SnmpPDU{Name: ".666", Type: gosnmp.OctetString, Value: []byte{0, 1, 2}},
			expected: "00 01 02",
		},
		{
			name:     "no display hint, not valid utf8",
			pdu:      gosnmp.SnmpPDU{Name: ".666", Type: gosnmp.OctetString, Value: []byte{145, 226, 186, 227, 90, 97}},
			expected: "91 E2 BA E3 5A 61",
		},
		{
			name:     "no display hint, printable",
			pdu:      gosnmp.SnmpPDU{Name: ".666", Type: gosnmp.OctetString, Value: []byte{'a', 'b', 'c'}},
			expected: "abc",
		},
		{
			name:     "hint string",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.3", Type: gosnmp.OctetString, Value: []byte{'a', 'b', 'c'}},
			expected: "abc",
		},
		{
			name:     "hint hexadecimal",
			pdu:      gosnmp.SnmpPDU{Name: ".1.3.6.4", Type: gosnmp.OctetString, Value: []byte{0, 255, 9, 17}},
			expected: "00 FF 09 11",
		},
		{
			name: "hint dateAndTime",
			pdu: gosnmp.SnmpPDU{
				Name:  ".1.3.6.5",
				Type:  gosnmp.OctetString,
				Value: []byte{0o7, 229, 10, 15, 14, 56, 8, 0o0, 43, 0o0, 0o0},
			},
			expected: "2021-10-15,14:56:8.0,+0:0",
		},
		{
			name: "hint dateAndTime without timezone",
			pdu: gosnmp.SnmpPDU{
				Name:  ".1.3.6.5",
				Type:  gosnmp.OctetString,
				Value: []byte{0o7, 229, 10, 15, 14, 56, 8, 0o0},
			},
			expected: "2021-10-15,14:56:8.0",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.expected, formatter.Format(test.pdu))
		})
	}
}
