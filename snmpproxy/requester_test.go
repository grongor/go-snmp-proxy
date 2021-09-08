package snmpproxy_test

import (
	"bytes"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/gosnmp/gosnmp"
	"github.com/grongor/go-snmp-proxy/snmpproxy"
	"github.com/grongor/go-snmp-proxy/snmpproxy/mib"
	"github.com/stretchr/testify/require"
)

type syncBuffer struct {
	b bytes.Buffer
	m sync.Mutex
}

func (b *syncBuffer) Write(p []byte) (n int, err error) {
	b.m.Lock()
	defer b.m.Unlock()

	return b.b.Write(p)
}

func (b *syncBuffer) String() string {
	b.m.Lock()
	defer b.m.Unlock()

	return b.b.String()
}

func TestMain(m *testing.M) {
	wd, err := os.Getwd()
	if err != nil {
		panic(err)
	}

	// #nosec
	cmd := exec.Command(
		"snmpsimd.py",
		"--v2c-arch",
		"--data-dir", path.Join(wd, "test_data"),
		"--agent-udpv4-endpoint", "127.0.0.1:15728",
	)

	buffer := syncBuffer{}
	cmd.Stderr = &buffer

	err = cmd.Start()
	if err != nil {
		panic(err)
	}

	t := time.Now()

	for {
		if strings.Contains(buffer.String(), "127.0.0.1:15728") {
			break
		}

		if time.Since(t) > time.Second*5 {
			panic("failed to start snmpsimd")
		}
	}

	code := m.Run()

	_ = cmd.Process.Kill()

	os.Exit(code)
}

func TestGet(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(get([]string{".1.3.6.1.2.1.25.2.3.1.2.1", ".1.3.6.1.2.1.25.2.3.1.2.4"}))

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.NoError(err)

	assert.Equal(
		[][]interface{}{
			{
				".1.3.6.1.2.1.25.2.3.1.2.1", ".1.3.6.1.2.1.25.2.1.2",
				".1.3.6.1.2.1.25.2.3.1.2.4", ".1.3.6.1.2.1.25.2.1.9",
			},
		},
		result,
	)
}

func TestGetStringDisplayHintGuessedString(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(get([]string{".1.3.6.1.2.1.2.2.1.2.48"}))

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.NoError(err)

	assert.Equal(
		[][]interface{}{{".1.3.6.1.2.1.2.2.1.2.48", "Ethernet48"}},
		result,
	)
}

func TestGetStringDisplayHintGuessedHexadecimalBecauseNotUtf8Valid(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(get([]string{".1.3.6.1.2.1.4.22.1.2.2000955.185.152.67.97"}))

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.NoError(err)

	assert.Equal(
		[][]interface{}{{".1.3.6.1.2.1.4.22.1.2.2000955.185.152.67.97", "91 E2 BA E3 5A 61"}},
		result,
	)
}

func TestGetStringDisplayHintGuessedHexadecimalBecauseNotPrintable(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(get([]string{".1.3.6.1.2.1.4.22.1.2.2000955.185.152.67.100"}))

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.NoError(err)

	assert.True(utf8.Valid([]byte{}))

	assert.Equal(
		[][]interface{}{{".1.3.6.1.2.1.4.22.1.2.2000955.185.152.67.100", "53 54 00 4C 5A 5D"}},
		result,
	)
}

func TestGetNext(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(getNext([]string{".1.3.6.1.2.1.25.2.3.1.2", ".1.3.6.1.2.1.25.2.3.1.2.3"}))

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.NoError(err)

	assert.Equal(
		[][]interface{}{
			{
				".1.3.6.1.2.1.25.2.3.1.2.1", ".1.3.6.1.2.1.25.2.1.2",
				".1.3.6.1.2.1.25.2.3.1.2.4", ".1.3.6.1.2.1.25.2.1.9",
			},
		},
		result,
	)
}

func TestWalk(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(walk(".1.3.6.1.2.1.31.1.1.1.15"))

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.NoError(err)

	assert.Equal(
		[][]interface{}{
			{
				".1.3.6.1.2.1.31.1.1.1.15.1000001", uint(100000),
				".1.3.6.1.2.1.31.1.1.1.15.1000003", uint(60000),
				".1.3.6.1.2.1.31.1.1.1.15.1000005", uint(80000),
			},
		},
		result,
	)
}

func TestWalkWithSnmpVersion1(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(walk(".1.3.6.1.2.1.31.1.1.1.15"))
	apiRequest.Version = snmpproxy.SnmpVersion(gosnmp.Version1)

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.NoError(err)

	assert.Equal(
		[][]interface{}{
			{
				".1.3.6.1.2.1.31.1.1.1.15.1000001", uint(100000),
				".1.3.6.1.2.1.31.1.1.1.15.1000003", uint(60000),
				".1.3.6.1.2.1.31.1.1.1.15.1000005", uint(80000),
			},
		},
		result,
	)
}

func TestWalkWholeTree(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(walk(".1.3"))

	mibDataProvider := mib.NewDataProvider(mib.DisplayHints{
		".1.3.6.1.2.1.2.2.1.2":  mib.DisplayHintString,
		".1.3.6.1.2.1.4.22.1.2": mib.DisplayHintHexadecimal,
	})

	requester := snmpproxy.NewGosnmpRequester(mibDataProvider)
	result, err := requester.ExecuteRequest(apiRequest)
	assert.NoError(err)

	assert.Equal(
		[][]interface{}{
			{
				".1.3.6.1.2.1.1.1.0",
				`Cisco IOS Software, C2960S Software (C2960S-UNIVERSALK9-M), Version 12.2(58)SE2, RELEASE SOFTWARE (fc1)
Technical Support: http://www.cisco.com/techsupport
Copyright (c) 1986-2011 by "Cisco Systems, Inc."
Compiled Thu 21-Jul-11 02:22 by prod_rel_team`,
				".1.3.6.1.2.1.1.3.0", uint32(293718542),
				".1.3.6.1.2.1.2.2.1.2.47", "Ethernet47",
				".1.3.6.1.2.1.2.2.1.2.48", "Ethernet48",
				".1.3.6.1.2.1.2.2.1.2.49001", "Ethernet49/1",
				".1.3.6.1.2.1.2.2.1.2.50001", "Ethernet50/1",
				".1.3.6.1.2.1.2.2.1.2.1000008", "Port-Channel8",
				".1.3.6.1.2.1.2.2.1.2.1000009", "Port-Channel9",
				".1.3.6.1.2.1.2.2.1.2.2002002", "Vlan2002",
				".1.3.6.1.2.1.2.2.1.2.2002019", "Vlan2019",
				".1.3.6.1.2.1.2.2.1.2.2002020", "Vlan2020",
				".1.3.6.1.2.1.2.2.1.2.5000000", "Loopback0",
				".1.3.6.1.2.1.2.2.1.14.8", uint(0),
				".1.3.6.1.2.1.2.2.1.14.9", uint(226),
				".1.3.6.1.2.1.2.2.1.14.10", uint(256),
				".1.3.6.1.2.1.2.2.1.14.11", uint(296),
				".1.3.6.1.2.1.4.20.1.1.10.100.192.2", "10.100.192.2",
				".1.3.6.1.2.1.4.20.1.1.10.110.27.254", "10.110.27.254",
				".1.3.6.1.2.1.4.20.1.1.66.208.216.74", "66.208.216.74",
				".1.3.6.1.2.1.4.22.1.2.2000955.185.152.67.97", "91 E2 BA E3 5A 61",
				".1.3.6.1.2.1.4.22.1.2.2000955.185.152.67.99", "53 54 00 5F 41 D0",
				".1.3.6.1.2.1.4.22.1.2.2000955.185.152.67.100", "53 54 00 4C 5A 5D",
				".1.3.6.1.2.1.4.22.1.2.2000955.185.152.67.102", "53 54 00 A9 A8 3B",
				".1.3.6.1.2.1.4.22.1.2.2000955.185.152.67.104", "53 54 00 5A A0 CA",
				".1.3.6.1.2.1.25.2.3.1.2.1", ".1.3.6.1.2.1.25.2.1.2",
				".1.3.6.1.2.1.25.2.3.1.2.2", ".1.3.6.1.2.1.25.2.1.2",
				".1.3.6.1.2.1.25.2.3.1.2.3", ".1.3.6.1.2.1.25.2.1.2",
				".1.3.6.1.2.1.25.2.3.1.2.4", ".1.3.6.1.2.1.25.2.1.9",
				".1.3.6.1.2.1.31.1.1.1.6.46", uint64(1884401752869190),
				".1.3.6.1.2.1.31.1.1.1.6.47", uint64(1883620653799494),
				".1.3.6.1.2.1.31.1.1.1.6.48", uint64(1884283891426650),
				".1.3.6.1.2.1.31.1.1.1.6.49001", uint64(2494191363092125),
				".1.3.6.1.2.1.31.1.1.1.6.50001", uint64(17658827020872235),
				".1.3.6.1.2.1.31.1.1.1.15.1000001", uint(100000),
				".1.3.6.1.2.1.31.1.1.1.15.1000003", uint(60000),
				".1.3.6.1.2.1.31.1.1.1.15.1000005", uint(80000),
				".1.3.6.1.2.1.47.1.1.1.1.13.30", "4E 4D 2D 33 32 41 20 20 20 20 20 20 20 20 20 20 20 20 FF FF FF FF FF FF FF",
				".1.3.6.1.6.3.10.2.1.3.0", 2937024,
			},
		},
		result,
	)
}

func TestWalkLastMibElement(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(walk(".1.7"))

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))

	result, err := requester.ExecuteRequest(apiRequest)
	assert.NoError(err)

	assert.Equal([][]interface{}{{".1.7.8.9", "Don't know what I'm"}}, result)
}

func TestWalkLastMibElementAndSnmpVersion1(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(walk(".1.7"))
	apiRequest.Version = snmpproxy.SnmpVersion(gosnmp.Version1)

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))

	result, err := requester.ExecuteRequest(apiRequest)
	assert.NoError(err)

	assert.Equal([][]interface{}{{".1.7.8.9", "Don't know what I'm"}}, result)
}

func TestMultipleRequests(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(
		get([]string{".1.3.6.1.2.1.1.3.0"}),
		walk(".1.7"),
		getNext([]string{".1.3.6.1.2.1.2.2.1.14.9", ".1.3.6.1.2.1.2.2.1.14.10"}),
	)

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))

	result, err := requester.ExecuteRequest(apiRequest)
	assert.NoError(err)

	assert.Equal(
		[][]interface{}{
			{".1.3.6.1.2.1.1.3.0", uint32(293718542)},
			{".1.7.8.9", "Don't know what I'm"},
			{
				".1.3.6.1.2.1.2.2.1.14.10", uint(256),
				".1.3.6.1.2.1.2.2.1.14.11", uint(296),
			},
		},
		result,
	)
}

func TestMultipleRequestsWithSingleError(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(
		get([]string{".1.3.6.1.2.1.1.3.0"}),
		walk(".1.7"),
		getNext([]string{".1.3.6.1.2.1.2.2.1.14.9", ".1.7.9"}),
	)

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))

	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "end of mib: .1.7.9")
}

func TestMultipleRequestsAllError(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(
		get([]string{".1.7.9"}),
		walk(".1.7.9"),
		getNext([]string{".1.3.6.1.2.1.2.2.1.14.9", ".1.7.9"}),
	)

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))

	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.Error(err)
	assert.Regexp(`(end of mib|no such instance): .1.7.9`, err.Error())
}

func TestWalkWithTimeout(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(walk(".1.15"))
	apiRequest.Host = "8.8.8.8"
	apiRequest.Version = snmpproxy.SnmpVersion(gosnmp.Version1)
	apiRequest.Timeout = time.Millisecond

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "timeout: .1.15")
}

func TestWalkWithNoSuchInstanceError(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(walk(".1.3.5"))

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "no such instance: .1.3.5")
}

func TestWalkWithSnmpVersion1AndNoSuchInstanceError(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(walk(".1.3.5"))
	apiRequest.Version = snmpproxy.SnmpVersion(gosnmp.Version1)

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "no such instance: .1.3.5")
}

func TestWalkWithEndOfMibError(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(walk(".1.15"))

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "end of mib: .1.15")
}

func TestWalkWithSnmpVersion1AndEndOfMibError(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(walk(".1.15"))
	apiRequest.Version = snmpproxy.SnmpVersion(gosnmp.Version1)

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "end of mib: .1.15")
}

func TestGetWithTimeout(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(get([]string{".1.15"}))
	apiRequest.Host = "8.8.8.8"
	apiRequest.Version = snmpproxy.SnmpVersion(gosnmp.Version1)
	apiRequest.Timeout = time.Millisecond

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "timeout: .1.15")
}

func TestGetWithNoSuchInstanceError(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(get([]string{".1.3.5"}))

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "no such instance: .1.3.5")
}

func TestGetWithSnmpVersion1AndNoSuchInstanceError(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(get([]string{".1.3.5"}))
	apiRequest.Version = snmpproxy.SnmpVersion(gosnmp.Version1)

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "no such instance: .1.3.5")
}

func TestGetWithMultipleOidsAndSnmpVersion1AndNoSuchInstanceError(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(get([]string{".1.3.5", "1.3.2"}))
	apiRequest.Version = snmpproxy.SnmpVersion(gosnmp.Version1)

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "no such instance: one of .1.3.5 1.3.2")
}

func TestGetNextWithEndOfMib(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(getNext([]string{".1.15"}))

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "end of mib: .1.15")
}

func TestGetNextWithSnmpVersion1AndEndOfMib(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(getNext([]string{".1.15"}))
	apiRequest.Version = snmpproxy.SnmpVersion(gosnmp.Version1)

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.EqualError(err, "end of mib: .1.15")
}

func TestGetWithSnmpError(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(get([]string{".1.1"}))
	apiRequest.Host = "localhost"

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.Error(err)
	assert.Contains(err.Error(), "read: connection refused")
}

func TestWalkWithSnmpError(t *testing.T) {
	assert := require.New(t)

	apiRequest := apiRequest(walk(""))
	apiRequest.Host = "localhost"

	requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
	result, err := requester.ExecuteRequest(apiRequest)
	assert.Nil(result)
	assert.Error(err)
	assert.Contains(err.Error(), "read: connection refused")
}

func TestInvalidHost(t *testing.T) {
	tests := []struct {
		name string
		host string
		err  string
	}{
		{
			name: "non-existing host",
			host: "fsdafasdfsddasfegfasdf",
			err:  `error establishing connection to host`,
		},
		{
			name: "port is too large",
			host: "localhost:154124",
			err:  `invalid port: strconv.ParseUint: parsing "154124": value out of range`,
		},
		{
			name: "port isn't integer",
			host: "localhost:lorem",
			err:  `invalid port: strconv.ParseUint: parsing "lorem": invalid syntax`,
		},
		{name: "invalid host", host: "localhost:invalid:123", err: "invalid host, expected host[:port]"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			assert := require.New(t)

			apiRequest := apiRequest(get([]string{}), walk(""))
			apiRequest.Host = test.host

			requester := snmpproxy.NewGosnmpRequester(mib.NewDataProvider(nil))
			result, err := requester.ExecuteRequest(apiRequest)
			assert.Nil(result)
			assert.Error(err)
			assert.Contains(err.Error(), test.err)
		})
	}
}

func apiRequest(requests ...snmpproxy.Request) *snmpproxy.ApiRequest {
	return &snmpproxy.ApiRequest{
		Host:      "127.0.0.1:15728",
		Community: "public",
		Version:   snmpproxy.SnmpVersion(gosnmp.Version2c),
		Timeout:   time.Second,
		Requests:  requests,
	}
}

func get(oids []string) snmpproxy.Request {
	return snmpproxy.Request{
		RequestType: snmpproxy.Get,
		Oids:        oids,
	}
}

func getNext(oids []string) snmpproxy.Request {
	return snmpproxy.Request{
		RequestType: snmpproxy.GetNext,
		Oids:        oids,
	}
}

func walk(oid string) snmpproxy.Request {
	return snmpproxy.Request{
		RequestType: snmpproxy.Walk,
		Oids:        []string{oid},
	}
}
