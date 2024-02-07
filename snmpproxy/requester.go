package snmpproxy

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/gosnmp/gosnmp"
)

type requestResult struct {
	requestNo int
	result    []any
	error     error
}

type Requester interface {
	ExecuteRequest(apiRequest *ApiRequest) ([][]any, error)
}

type GosnmpRequester struct {
	valueFormatter *ValueFormatter
}

func (r *GosnmpRequester) ExecuteRequest(apiRequest *ApiRequest) ([][]any, error) {
	resultsChan := make(chan requestResult)

	for requestNo, request := range apiRequest.Requests {
		switch request.RequestType {
		case Get, GetNext:
			go r.executeGet(apiRequest, requestNo, resultsChan)
		case Walk:
			go r.executeWalk(apiRequest, requestNo, resultsChan)
		}
	}

	errChan := make(chan error)
	results := make([][]any, len(apiRequest.Requests))

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

	if err := <-errChan; err != nil {
		return nil, err
	}

	return results, nil
}

func (r *GosnmpRequester) executeGet(apiRequest *ApiRequest, requestNo int, resultChan chan<- requestResult) {
	var (
		err     error
		request = apiRequest.Requests[requestNo]
		result  = requestResult{requestNo: requestNo}
	)

	defer func() {
		result.error = err

		resultChan <- result
	}()

	snmp, err := r.createSnmpHandler(apiRequest)
	if err != nil {
		err = r.maybeConvertErrToTimeout(err, request.Oids)

		return
	}

	var getter func(oids []string) (*gosnmp.SnmpPacket, error)
	if request.RequestType == Get {
		getter = snmp.Get
	} else {
		getter = snmp.GetNext
	}

	packet, err := getter(request.Oids)
	if err != nil {
		err = r.maybeConvertErrToTimeout(err, request.Oids)

		return
	}

	result.result, err = r.processGetPacket(packet, request)
}

func (r *GosnmpRequester) processGetPacket(packet *gosnmp.SnmpPacket, request Request) ([]any, error) {
	if packet.Error == gosnmp.NoSuchName {
		var oidsString string

		if len(request.Oids) == 1 {
			oidsString = request.Oids[0]
		} else {
			oidsString = "one of " + strings.Join(request.Oids, " ")
		}

		if request.RequestType == Get {
			return nil, fmt.Errorf("no such instance: %s", oidsString)
		}

		return nil, fmt.Errorf("end of mib: %s", oidsString)
	}

	result := make([]any, 0, len(packet.Variables)*2)

	for _, dataUnit := range packet.Variables {
		if dataUnit.Type == gosnmp.NoSuchObject {
			return result, fmt.Errorf("no such object: %s", dataUnit.Name)
		}

		if dataUnit.Type == gosnmp.NoSuchInstance {
			return result, fmt.Errorf("no such instance: %s", dataUnit.Name)
		}

		if dataUnit.Type == gosnmp.EndOfMibView {
			return result, fmt.Errorf("end of mib: %s", dataUnit.Name)
		}

		result = append(result, dataUnit.Name, r.valueFormatter.Format(dataUnit))
	}

	return result, nil
}

func (r *GosnmpRequester) executeWalk(apiRequest *ApiRequest, requestNo int, resultChan chan<- requestResult) {
	var (
		err     error
		request = apiRequest.Requests[requestNo]
		result  = requestResult{requestNo: requestNo}
	)

	defer func() {
		result.error = err

		resultChan <- result
	}()

	snmp, err := r.createSnmpHandler(apiRequest)
	if err != nil {
		err = r.maybeConvertErrToTimeout(err, request.Oids)

		return
	}

	snmp.SetMaxRepetitions(request.MaxRepetitions)

	var walker func(string, gosnmp.WalkFunc) error
	if apiRequest.Version == SnmpVersion(gosnmp.Version1) {
		walker = snmp.Walk
	} else {
		walker = snmp.BulkWalk
	}

	oid := request.Oids[0]

	err = walker(oid, func(dataUnit gosnmp.SnmpPDU) error {
		result.result = append(result.result, dataUnit.Name, r.valueFormatter.Format(dataUnit))

		return nil
	})
	if err != nil {
		err = r.maybeConvertErrToTimeout(err, []string{oid})

		return
	}

	if len(result.result) != 0 {
		return
	}

	err = r.getWalkFailureReason(snmp, oid)
}

func (r *GosnmpRequester) getWalkFailureReason(snmp gosnmp.Handler, oid string) error {
	packet, err := snmp.GetNext([]string{oid})
	if err != nil {
		return r.maybeConvertErrToTimeout(err, []string{oid})
	}

	if len(packet.Variables) != 1 || packet.Variables[0].Type == gosnmp.NoSuchObject {
		return fmt.Errorf("no such object: %s", oid)
	}

	if packet.Variables[0].Type != gosnmp.EndOfMibView && packet.Variables[0].Type != gosnmp.Null {
		return fmt.Errorf("no such instance: %s", oid)
	}

	return fmt.Errorf("end of mib: %s", oid)
}

func (*GosnmpRequester) maybeConvertErrToTimeout(err error, oids []string) error {
	if strings.Contains(err.Error(), "timeout") {
		return fmt.Errorf("timeout: %s", strings.Join(oids, ", "))
	}

	return err
}

func (*GosnmpRequester) createSnmpHandler(apiRequest *ApiRequest) (gosnmp.Handler, error) {
	snmp := gosnmp.NewHandler()

	var addrErr *net.AddrError
	host, port, err := net.SplitHostPort(apiRequest.Host)

	switch {
	case err == nil:
		snmp.SetTarget(host)

		port, err := strconv.ParseUint(port, 10, 16)
		if err != nil {
			return nil, fmt.Errorf("invalid host port: %w", err)
		}

		snmp.SetPort(uint16(port))
	case errors.As(err, &addrErr):
		if addrErr.Err == "missing port in address" {
			snmp.SetTarget(apiRequest.Host)

			break
		}

		if addrErr.Err == "too many colons in address" {
			if addr, err := netip.ParseAddr(apiRequest.Host); err == nil {
				snmp.SetTarget(addr.String())

				break
			}
		}

		fallthrough
	default:
		return nil, fmt.Errorf("invalid host: %w", err)
	}

	snmp.SetCommunity(apiRequest.Community)
	snmp.SetVersion(gosnmp.SnmpVersion(apiRequest.Version))
	snmp.SetTimeout(apiRequest.Timeout)
	snmp.SetExponentialTimeout(false)
	snmp.SetRetries(int(apiRequest.Retries))

	if err := snmp.Connect(); err != nil {
		return nil, err
	}

	return snmp, nil
}

func NewGosnmpRequester(valueFormatter *ValueFormatter) *GosnmpRequester {
	return &GosnmpRequester{valueFormatter: valueFormatter}
}
