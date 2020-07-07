package mib

import (
	"strings"
)

type DisplayHint uint8

const (
	DisplayHintUnknown = DisplayHint(iota)
	DisplayHintString
	DisplayHintHexadecimal
)

type DisplayHints map[string]DisplayHint

type Parser interface {
	Parse() (DisplayHints, error)
}

type DataProvider struct {
	displayHints DisplayHints
}

func (p *DataProvider) GetDisplayHint(oid string) DisplayHint {
	for length := len(oid); length > 7; length = strings.LastIndex(oid[:length], ".") {
		if displayHint, ok := p.displayHints[oid[:length]]; ok {
			return displayHint
		}
	}

	return DisplayHintUnknown
}

func NewDataProvider(displayHints DisplayHints) *DataProvider {
	return &DataProvider{displayHints: displayHints}
}
