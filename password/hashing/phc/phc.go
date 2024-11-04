package phc

import (
	"encoding/base64"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

// Format is a modelisation of the Password Hashing Competition string format.
// Specifications can be found at: https://github.com/P-H-C/phc-string-format
type Format struct {
	ID      string
	Version string
	Params  []Parameter
	Salt    []byte
	Hash    []byte
}

type Parameter struct {
	Name  string
	Value string
}

var format = regexp.MustCompile(
	`^` +
		`\$([a-z0-9-]{1,32})` +
		`(?:\$v=([0-9]+))?` +
		`(?:\$([a-z0-9-]+=[a-zA-Z0-9/+.-]+(?:,[a-z0-9-]+=[a-zA-Z0-9/+.-]+)*))?` +
		`(?:\$([a-zA-Z0-9/+.-]+)(?:\$([a-zA-Z0-9/+.-]+))?)?` +
		`$`,
)

func Decode(raw string) (*Format, error) {
	var f Format
	if err := f.UnmarshalText([]byte(raw)); err != nil {
		return nil, err
	}

	return &f, nil
}

func (f *Format) UnmarshalText(text []byte) error {
	submatches := format.FindStringSubmatch(string(text))
	if submatches == nil {
		return errors.New("phc: not a valid format: " + strconv.Quote(string(text)))
	}

	ret := Format{
		ID:      submatches[1],
		Version: submatches[2],
	}

	if len(submatches[3]) > 0 {
		split := strings.Split(submatches[3], ",")
		ret.Params = make([]Parameter, len(split))
		for i, param := range split {
			kv := strings.Split(param, "=")
			ret.Params[i].Name = kv[0]
			ret.Params[i].Value = kv[1]
		}
	}

	if len(submatches[4]) > 0 {
		var err error
		ret.Salt, err = base64.RawStdEncoding.DecodeString(submatches[4])
		if err != nil {
			return fmt.Errorf("phc: salt decoding error: %w", err)
		}
		if len(submatches[5]) > 0 {
			ret.Hash, err = base64.RawStdEncoding.DecodeString(submatches[5])
			if err != nil {
				return fmt.Errorf("phc: hash decoding error: %w", err)
			}
		}
	}

	*f = ret

	return nil
}

func (f *Format) MarshalText() (text []byte, err error) {
	return []byte(f.String()), nil
}

func (f *Format) String() string {
	var builder strings.Builder
	builder.WriteRune('$')
	builder.WriteString(f.ID)

	if f.Version != "" {
		builder.WriteString("$v=")
		builder.WriteString(f.Version)
	}

	if len(f.Params) > 0 {
		builder.WriteRune('$')
		for i, param := range f.Params {
			if i > 0 {
				builder.WriteRune(',')
			}
			builder.WriteString(param.Name)
			builder.WriteRune('=')
			builder.WriteString(param.Value)
		}
	}

	if len(f.Salt) > 0 {
		builder.WriteRune('$')
		builder.WriteString(base64.RawStdEncoding.EncodeToString(f.Salt))

		if len(f.Hash) > 0 {
			builder.WriteRune('$')
			builder.WriteString(base64.RawStdEncoding.EncodeToString(f.Hash))
		}
	}

	return builder.String()
}
