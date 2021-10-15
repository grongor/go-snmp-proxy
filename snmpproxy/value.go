package snmpproxy

import (
	"encoding/binary"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
	"unsafe"

	"github.com/gosnmp/gosnmp"
	"github.com/grongor/go-snmp-proxy/snmpproxy/mib"
)

type ValueFormatter struct {
	mibDataProvider *mib.DataProvider
}

func (f *ValueFormatter) Format(dataUnit gosnmp.SnmpPDU) interface{} {
	if dataUnit.Type != gosnmp.OctetString {
		return dataUnit.Value
	}

	switch f.mibDataProvider.GetDisplayHint(dataUnit.Name) {
	case mib.DisplayHintString:
		return f.getValueAsString(dataUnit.Value.([]byte))
	case mib.DisplayHintDateAndTime:
		return f.formatDateAndTime(dataUnit.Value.([]byte))
	case mib.DisplayHintUnknown:
		if f.isStringPrintable(dataUnit.Value.([]byte)) {
			return f.getValueAsString(dataUnit.Value.([]byte))
		}

		fallthrough
	default:
		value := dataUnit.Value.([]byte)
		result := make([]byte, len(value)*3-1) // 2 chars per byte + space separator between each (hence -1)

		const hexTable = "0123456789ABCDEF"

		var j int

		for i, v := range value {
			if i != 0 {
				result[j] = ' '
				j++
			}

			result[j] = hexTable[v>>4]
			result[j+1] = hexTable[v&0x0f]
			j += 2
		}

		return f.getValueAsString(result)
	}
}

func (*ValueFormatter) formatDateAndTime(value []byte) string {
	valueSize := len(value)
	withoutTimezone := valueSize == 8

	buf := strings.Builder{}
	if withoutTimezone {
		buf.Grow(valueSize*2 + 6) // approx 2 chars per byte + separators
	} else {
		buf.Grow(valueSize*2 + 6 - 1 + 2) // same as above (except timezone sign) + timezone separators
	}

	// year
	buf.WriteString(strconv.FormatUint(uint64(binary.BigEndian.Uint16(value[0:2])), 10))
	buf.WriteByte('-')
	// month
	buf.WriteString(strconv.FormatUint(uint64(value[2]), 10))
	buf.WriteByte('-')
	// day
	buf.WriteString(strconv.FormatUint(uint64(value[3]), 10))
	buf.WriteByte(',')
	// hours
	buf.WriteString(strconv.FormatUint(uint64(value[4]), 10))
	buf.WriteByte(':')
	// minutes
	buf.WriteString(strconv.FormatUint(uint64(value[5]), 10))
	buf.WriteByte(':')
	// seconds
	buf.WriteString(strconv.FormatUint(uint64(value[6]), 10))
	buf.WriteByte('.')
	// deci-seconds
	buf.WriteString(strconv.FormatUint(uint64(value[7]), 10))

	if withoutTimezone {
		return buf.String()
	}

	buf.WriteByte(',')
	// direction from UTC: + or -
	buf.WriteByte(value[8])
	// hours from UTC
	buf.WriteString(strconv.FormatUint(uint64(value[9]), 10))
	buf.WriteByte(':')
	// minutes from UTC
	buf.WriteString(strconv.FormatUint(uint64(value[10]), 10))

	return buf.String()
}

func (*ValueFormatter) getValueAsString(value []byte) string {
	return *(*string)(unsafe.Pointer(&value))
}

func (*ValueFormatter) isStringPrintable(value []byte) bool {
	if !utf8.Valid(value) {
		return false
	}

	for _, b := range value {
		if unicode.IsPrint(rune(b)) || unicode.IsSpace(rune(b)) {
			continue
		}

		return false
	}

	return true
}

func NewValueFormatter(mibDataProvider *mib.DataProvider) *ValueFormatter {
	return &ValueFormatter{mibDataProvider: mibDataProvider}
}
