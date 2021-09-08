package snmpproxy

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gosnmp/gosnmp"
)

type RequestType string

func (t *RequestType) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("RequestType must be a string, got %s: %w", string(data), err)
	}

	*t = RequestType(s)

	switch *t {
	case Get, GetNext, Walk:
		return nil
	case "":
		return errors.New("RequestType mustn't be empty")
	default:
		return fmt.Errorf("unknown RequestType \"%s\"", *t)
	}
}

const (
	Get     = RequestType("get")
	GetNext = RequestType("getNext")
	Walk    = RequestType("walk")
)

type SnmpVersion gosnmp.SnmpVersion

func (v *SnmpVersion) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return fmt.Errorf("snmpVersion must be a string, got %s: %w", string(data), err)
	}

	switch s {
	case "1":
		*v = SnmpVersion(gosnmp.Version1)
	case "2c":
		*v = SnmpVersion(gosnmp.Version2c)
	case "":
		return errors.New("snmpVersion mustn't be empty")
	default:
		return fmt.Errorf("unknown or unsupported snmpVersion \"%s\", supported are: 1, 2c", s)
	}

	return nil
}

type Request struct {
	RequestType    RequestType `json:"request_type"`
	Oids           []string    `json:"oids"`
	MaxRepetitions uint32      `json:"max_repetitions"`
}

func (r *Request) UnmarshalJSON(data []byte) error {
	type tmp Request

	var t tmp

	if err := json.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("failed to unmarshal Request struct, got %+v: %w", string(data), err)
	}

	if t.RequestType == "" {
		return fmt.Errorf("field request_type mustn't be empty")
	}

	*r = Request(t)

	return nil
}

type ApiRequest struct {
	Host      string        `json:"host"`
	Community string        `json:"community"`
	Version   SnmpVersion   `json:"version"`
	Retries   uint8         `json:"retries"`
	Timeout   time.Duration `json:"timeout"`
	Requests  []Request     `json:"requests"`
}

func (r *ApiRequest) UnmarshalJSON(data []byte) error {
	type tmp ApiRequest

	var t tmp

	if err := json.Unmarshal(data, &t); err != nil {
		return fmt.Errorf("failed to unmarshal request body into ApiRequest struct, got %+v: %w", string(data), err)
	}

	if t.Host == "" {
		return fmt.Errorf("field host mustn't be empty")
	}

	if t.Community == "" {
		t.Community = "public"
	}

	if t.Version == 0 {
		var v struct {
			Version string `json:"version"`
		}

		_ = json.Unmarshal(data, &v)

		if v.Version == "" {
			return fmt.Errorf("field version mustn't be empty")
		}
	}

	if t.Timeout == 0 {
		return fmt.Errorf("field timeout mustn't be empty or zero")
	}

	t.Timeout *= time.Second

	*r = ApiRequest(t)

	return nil
}

type Response struct {
	Error  string          `json:"error,omitempty"`
	Result [][]interface{} `json:"result,omitempty"`
}

func (r *Response) Bytes() []byte {
	b, err := json.Marshal(r)
	if err != nil {
		panic(err)
	}

	return b
}
