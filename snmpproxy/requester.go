package snmpproxy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/soniah/gosnmp"
)

type Requester interface {
	ExecuteRequest(request Request) ([]interface{}, error)
}

type GosnmpRequester struct {
	mibDataProvider *MibDataProvider
}

func (r *GosnmpRequester) ExecuteRequest(request Request) ([]interface{}, error) {
	snmp, err := r.getSnmp(request)
	if err != nil {
		return nil, err
	}

	switch request.RequestType {
	case Get, GetNext:
		return r.executeGet(snmp, request)
	default:
		return r.executeWalk(snmp, request)
	}
}

func (r *GosnmpRequester) getSnmp(request Request) (gosnmp.Handler, error) {
	snmp := gosnmp.NewHandler()

	hostAndPort := strings.Split(request.Host, ":")
	if len(hostAndPort) > 2 {
		return nil, errors.New("invalid host, expected host[:port]")
	}

	snmp.SetTarget(hostAndPort[0])

	if len(hostAndPort) == 2 {
		port, err := strconv.ParseUint(hostAndPort[1], 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid port: %w", err)
		}

		snmp.SetPort(uint16(port))
	}

	snmp.SetCommunity(request.Community)
	snmp.SetVersion(gosnmp.SnmpVersion(request.Version))
	snmp.SetTimeout(request.Timeout)
	snmp.SetExponentialTimeout(false)
	snmp.SetRetries(int(request.Retries))

	err := snmp.Connect()
	if err != nil {
		return nil, err
	}

	return snmp, nil
}

func (r *GosnmpRequester) executeGet(snmp gosnmp.Handler, request Request) ([]interface{}, error) {
	var getter func(oids []string) (*gosnmp.SnmpPacket, error)
	if request.RequestType == Get {
		getter = snmp.Get
	} else {
		getter = snmp.GetNext
	}

	packet, err := getter(request.Oids)
	if err != nil {
		return nil, err
	}

	if packet.Error == gosnmp.NoSuchName {
		var oidsString string
		if len(request.Oids) == 1 {
			oidsString = request.Oids[0]
		} else {
			oidsString = "one of " + strings.Join(request.Oids, " ")
		}

		if request.RequestType == Get {
			return nil, fmt.Errorf("no such instance: %s", oidsString)
		} else {
			return nil, fmt.Errorf("end of mib: %s", oidsString)
		}
	}

	result := make([]interface{}, 0, len(packet.Variables))

	for _, dataUnit := range packet.Variables {
		if dataUnit.Type == gosnmp.NoSuchObject {
			return nil, fmt.Errorf("no such object: %s", dataUnit.Name)
		}

		if dataUnit.Type == gosnmp.NoSuchInstance {
			return nil, fmt.Errorf("no such instance: %s", dataUnit.Name)
		}

		if dataUnit.Type == gosnmp.EndOfMibView {
			return nil, fmt.Errorf("end of mib: %s", dataUnit.Name)
		}

		result = append(result, dataUnit.Name, r.getPduValue(dataUnit))
	}

	return result, nil
}

func (r *GosnmpRequester) executeWalk(snmp gosnmp.Handler, request Request) ([]interface{}, error) {
	snmp.SetMaxRepetitions(request.MaxRepetitions)

	var walker func(string, gosnmp.WalkFunc) error
	if request.Version == SnmpVersion(gosnmp.Version1) {
		walker = snmp.Walk
	} else {
		walker = snmp.BulkWalk
	}

	oid := request.Oids[0]
	var result []interface{}

	err := walker(oid, func(dataUnit gosnmp.SnmpPDU) error {
		result = append(result, dataUnit.Name, r.getPduValue(dataUnit))

		return nil
	})
	if err != nil {
		return nil, err
	}

	if len(result) == 0 {
		packet, err := snmp.GetNext([]string{oid})
		if err != nil {
			return nil, err
		}

		if len(packet.Variables) != 1 || packet.Variables[0].Type == gosnmp.NoSuchObject {
			return nil, fmt.Errorf("no such object: %s", oid)
		}

		if packet.Variables[0].Type != gosnmp.EndOfMibView && packet.Variables[0].Type != gosnmp.Null {
			return nil, fmt.Errorf("no such instance: %s", oid)
		}

		return nil, fmt.Errorf("end of mib: %s", oid)
	}

	return result, nil
}

func (r *GosnmpRequester) getPduValue(dataUnit gosnmp.SnmpPDU) interface{} {
	switch dataUnit.Type {
	case gosnmp.OctetString:
		displayHint := r.mibDataProvider.GetDisplayHint(dataUnit.Name)
		if displayHint == DisplayHintString ||
			// best effort to display octet strings correctly without the MIBs
			displayHint == DisplayHintUnknown && r.isStringPrintable(dataUnit.Value.([]byte)) {
			return string(dataUnit.Value.([]byte))
		}

		return fmt.Sprintf("% X", dataUnit.Value)
	default:
		return dataUnit.Value
	}
}

func (r *GosnmpRequester) isStringPrintable(value []byte) bool {
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

func NewGosnmpRequester(mibDataProvider *MibDataProvider) *GosnmpRequester {
	return &GosnmpRequester{mibDataProvider: mibDataProvider}
}
