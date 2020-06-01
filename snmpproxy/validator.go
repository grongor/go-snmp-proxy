package snmpproxy

import (
	"fmt"
	"time"
)

type RequestValidator struct {
	maxTimeout time.Duration
	maxRetries uint8
}

func (v *RequestValidator) Validate(request Request) error {
	if len(request.Oids) == 0 {
		return fmt.Errorf("at least one OID must be provided")
	}

	if request.RequestType == Walk && len(request.Oids) > 1 {
		return fmt.Errorf("only single OID is supported with RequestType = Walk, got %d", len(request.Oids))
	}

	for _, oid := range request.Oids {
		if oid[0] != '.' {
			return fmt.Errorf("all OIDs must begin with a dot")
		}
	}

	if request.Timeout > v.maxTimeout {
		return fmt.Errorf(
			"maximum allowed timeout is %d seconds, got %d seconds",
			v.maxTimeout/time.Second,
			request.Timeout/time.Second,
		)
	}

	if request.Retries > v.maxRetries {
		return fmt.Errorf("maximum allowed number of retries is %d, got %d", v.maxRetries, request.Retries)
	}

	if request.RequestType == Walk && request.MaxRepetitions == 0 {
		return fmt.Errorf("field max_repetitions is required for RequestType Walk, and it mustn't be zero")
	}

	return nil
}

func NewRequestValidator(maxTimeoutSeconds uint, maxRetries uint8) *RequestValidator {
	return &RequestValidator{maxTimeout: time.Duration(maxTimeoutSeconds) * time.Second, maxRetries: maxRetries}
}
