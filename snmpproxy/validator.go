package snmpproxy

import (
	"fmt"
	"strings"
	"time"
)

type RequestValidator struct {
	maxTimeout time.Duration
	maxRetries uint8
}

func (v *RequestValidator) Validate(apiRequest *ApiRequest) error { //nolint:cyclop // No need to split this
	if apiRequest.Timeout > v.maxTimeout {
		return fmt.Errorf(
			"maximum allowed timeout is %d seconds, got %d seconds",
			v.maxTimeout/time.Second,
			apiRequest.Timeout/time.Second,
		)
	}

	if apiRequest.Retries > v.maxRetries {
		return fmt.Errorf("maximum allowed number of retries is %d, got %d", v.maxRetries, apiRequest.Retries)
	}

	if len(apiRequest.Requests) == 0 {
		return fmt.Errorf("at least one Request must be provided")
	}

	for i, request := range apiRequest.Requests {
		switch request.RequestType {
		case Get, GetNext, Walk:
		default:
			return fmt.Errorf("request[%d]: unexpected RequestType: %s", i, request.RequestType)
		}

		if len(request.Oids) == 0 {
			return fmt.Errorf("request[%d]: at least one OID must be provided", i)
		}

		if request.RequestType == Walk && len(request.Oids) > 1 {
			return fmt.Errorf(
				"request[%d]: only single OID is supported with RequestType = Walk, got %d: %s",
				i,
				len(request.Oids),
				strings.Join(request.Oids, ", "),
			)
		}

		for _, oid := range request.Oids {
			if oid[0] != '.' {
				return fmt.Errorf("request[%d]: all OIDs must begin with a dot, got: %s", i, oid)
			}
		}

		if request.RequestType == Walk && request.MaxRepetitions == 0 {
			return fmt.Errorf(
				"request[%d]: field max_repetitions is required for RequestType = Walk, "+
					"and it mustn't be zero, oid: %s",
				i,
				request.Oids[0],
			)
		}
	}

	return nil
}

func NewRequestValidator(maxTimeoutSeconds uint, maxRetries uint8) *RequestValidator {
	return &RequestValidator{maxTimeout: time.Duration(maxTimeoutSeconds) * time.Second, maxRetries: maxRetries}
}
