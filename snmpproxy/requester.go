package snmpproxy

import (
	"errors"
	"fmt"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/soniah/gosnmp"

	"github.com/grongor/go-snmp-proxy/snmpproxy/mib"
)

type requestResult struct {
	requestNo int
	result    []interface{}
	error     error
}

type Requester interface {
	ExecuteRequest(apiRequest *ApiRequest) ([][]interface{}, error)
}

type GosnmpRequester struct {
	mibDataProvider *mib.DataProvider
}

func (r *GosnmpRequester) ExecuteRequest(apiRequest *ApiRequest) ([][]interface{}, error) {
	resultsChan := make(chan requestResult)

	for requestNo, request := range apiRequest.Requests {
		switch request.RequestType {
		case Get, GetNext:
			go r.executeGet(apiRequest, requestNo, resultsChan)
		default:
			go r.executeWalk(apiRequest, requestNo, resultsChan)
		}
	}

	errChan := make(chan error)
	results := make([][]interface{}, len(apiRequest.Requests))

	go func() {
		var errored bool

		for i := len(apiRequest.Requests); i > 0; i-- {
			result := <-resultsChan

			if errored {
				continue
			}

			if result.error != nil {
				errored = true
				errChan <- result.error

				continue
			}

			results[result.requestNo] = result.result
		}

		close(errChan)
	}()

	err := <-errChan
	if err != nil {
		return nil, err
	}

	return results, nil
}

func (r *GosnmpRequester) executeGet(apiRequest *ApiRequest, requestNo int, resultChan chan<- requestResult) {
	var (
		err    error
		result = requestResult{requestNo: requestNo}
	)

	defer func() {
		result.error = err

		resultChan <- result
	}()

	snmp, err := r.createSnmpHandler(apiRequest)
	if err != nil {
		return
	}

	request := apiRequest.Requests[requestNo]

	var getter func(oids []string) (*gosnmp.SnmpPacket, error)
	if request.RequestType == Get {
		getter = snmp.Get
	} else {
		getter = snmp.GetNext
	}

	packet, err := getter(request.Oids)
	if err != nil {
		return
	}

	if packet.Error == gosnmp.NoSuchName {
		var oidsString string

		if len(request.Oids) == 1 {
			oidsString = request.Oids[0]
		} else {
			oidsString = "one of " + strings.Join(request.Oids, " ")
		}

		if request.RequestType == Get {
			err = fmt.Errorf("no such instance: %s", oidsString)
		} else {
			err = fmt.Errorf("end of mib: %s", oidsString)
		}

		return
	}

	result.result = make([]interface{}, 0, len(packet.Variables))

	for _, dataUnit := range packet.Variables {
		if dataUnit.Type == gosnmp.NoSuchObject {
			err = fmt.Errorf("no such object: %s", dataUnit.Name)

			return
		}

		if dataUnit.Type == gosnmp.NoSuchInstance {
			err = fmt.Errorf("no such instance: %s", dataUnit.Name)

			return
		}

		if dataUnit.Type == gosnmp.EndOfMibView {
			err = fmt.Errorf("end of mib: %s", dataUnit.Name)

			return
		}

		result.result = append(result.result, dataUnit.Name, r.getPduValue(dataUnit))
	}
}

func (r *GosnmpRequester) executeWalk(apiRequest *ApiRequest, requestNo int, resultChan chan<- requestResult) {
	var (
		err    error
		result = requestResult{requestNo: requestNo}
	)

	defer func() {
		result.error = err

		resultChan <- result
	}()

	snmp, err := r.createSnmpHandler(apiRequest)
	if err != nil {
		return
	}

	request := apiRequest.Requests[requestNo]

	snmp.SetMaxRepetitions(request.MaxRepetitions)

	var walker func(string, gosnmp.WalkFunc) error
	if apiRequest.Version == SnmpVersion(gosnmp.Version1) {
		walker = snmp.Walk
	} else {
		walker = snmp.BulkWalk
	}

	oid := request.Oids[0]

	err = walker(oid, func(dataUnit gosnmp.SnmpPDU) error {
		result.result = append(result.result, dataUnit.Name, r.getPduValue(dataUnit))

		return nil
	})
	if err != nil {
		return
	}

	if len(result.result) != 0 {
		return
	}

	packet, err := snmp.GetNext([]string{oid})
	if err != nil {
		return
	}

	if len(packet.Variables) != 1 || packet.Variables[0].Type == gosnmp.NoSuchObject {
		err = fmt.Errorf("no such object: %s", oid)

		return
	}

	if packet.Variables[0].Type != gosnmp.EndOfMibView && packet.Variables[0].Type != gosnmp.Null {
		err = fmt.Errorf("no such instance: %s", oid)

		return
	}

	err = fmt.Errorf("end of mib: %s", oid)
}

func (r *GosnmpRequester) createSnmpHandler(apiRequest *ApiRequest) (gosnmp.Handler, error) {
	snmp := gosnmp.NewHandler()

	hostAndPort := strings.Split(apiRequest.Host, ":")
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

	snmp.SetCommunity(apiRequest.Community)
	snmp.SetVersion(gosnmp.SnmpVersion(apiRequest.Version))
	snmp.SetTimeout(apiRequest.Timeout)
	snmp.SetExponentialTimeout(false)
	snmp.SetRetries(int(apiRequest.Retries))

	err := snmp.Connect()
	if err != nil {
		return nil, err
	}

	return snmp, nil
}

func (r *GosnmpRequester) getPduValue(dataUnit gosnmp.SnmpPDU) interface{} {
	switch dataUnit.Type {
	case gosnmp.OctetString:
		displayHint := r.mibDataProvider.GetDisplayHint(dataUnit.Name)
		if displayHint == mib.DisplayHintString ||
			// best effort to display octet strings correctly without the MIBs
			displayHint == mib.DisplayHintUnknown && r.isStringPrintable(dataUnit.Value.([]byte)) {
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

func NewGosnmpRequester(mibDataProvider *mib.DataProvider) *GosnmpRequester {
	return &GosnmpRequester{mibDataProvider: mibDataProvider}
}
