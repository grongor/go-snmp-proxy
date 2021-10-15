// +build !nonetsnmp

package mib

/*
#cgo LDFLAGS: -lnetsnmp -L/usr/local/lib
#cgo CFLAGS: -I/usr/local/include
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/mib_api.h>
*/
import "C"

import (
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"go.uber.org/zap"
	"golang.org/x/sys/unix"
)

// This parser was inspired by https://github.com/prometheus/snmp_exporter/tree/master/generator
type NetsnmpMibParser struct {
	logger        *zap.SugaredLogger
	strictParsing bool
}

func (p *NetsnmpMibParser) Parse() (DisplayHints, error) {
	err := os.Setenv("MIBS", "ALL")
	if err != nil {
		return nil, fmt.Errorf("failed to set ENV variable: %w", err)
	}

	p.logger.Infow("loading MIB files", "source", C.GoString(C.netsnmp_get_mib_directory()))

	// Redirect stderr to a pipe to catch netsnmp errors
	r, w, err := os.Pipe()
	if err != nil {
		return nil, fmt.Errorf("error creating pipe: %w", err)
	}
	defer r.Close()
	defer w.Close()

	originalStderrFd, err := unix.Dup(unix.Stderr)
	if err != nil {
		return nil, err
	}

	err = unix.Dup2(int(w.Fd()), unix.Stderr)
	if err != nil {
		return nil, err
	}

	outChan := make(chan string)
	errChan := make(chan error)

	go func() {
		data, err := io.ReadAll(r)
		if err != nil {
			errChan <- fmt.Errorf("error reading from pipe: %w", err)

			return
		}

		close(errChan)
		outChan <- string(data)
	}()

	// Initialize the MIBs
	C.netsnmp_init_mib()

	// Restore stderr
	_ = w.Close()
	_ = unix.Dup2(originalStderrFd, unix.Stderr)
	_ = unix.Close(originalStderrFd)

	if err := <-errChan; err != nil {
		return nil, err
	}

	output := strings.TrimSpace(<-outChan)
	if output != "" {
		if p.strictParsing {
			return nil, fmt.Errorf("netsnmp: %s", output)
		}

		p.logger.Warnw("encountered errors during MIB parsing", "errors", output)
	}

	displayHints := make(DisplayHints)

	p.findStringTypesDisplayHints(displayHints, C.get_tree_head(), "")

	return displayHints, nil
}

func (p *NetsnmpMibParser) findStringTypesDisplayHints(displayHints DisplayHints, t *C.struct_tree, oid string) {
	if t.child_list == nil && t._type != 2 { // we only care about OctetStr type
		return
	}

	oid = oid + "." + strconv.Itoa(int(t.subid))

	if t.child_list == nil {
		switch C.GoString(C.get_tc_descriptor(t.tc_index)) {
		case "DisplayString", "SnmpAdminString", "InetAddress", "OwnerString":
			displayHints[oid] = DisplayHintString
		case "PhysAddress":
			displayHints[oid] = DisplayHintHexadecimal
		case "DateAndTime":
			displayHints[oid] = DisplayHintDateAndTime
		}

		return
	}

	next := t.child_list
	for next != nil {
		p.findStringTypesDisplayHints(displayHints, next, oid)
		next = next.next_peer
	}
}

func NewNetsnmpMibParser(logger *zap.SugaredLogger, strictParsing bool) *NetsnmpMibParser {
	return &NetsnmpMibParser{logger: logger, strictParsing: strictParsing}
}
