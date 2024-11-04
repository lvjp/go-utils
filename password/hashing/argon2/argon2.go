package argon2

import (
	"crypto/rand"
	"crypto/subtle"
	"errors"
	"fmt"
	"io"
	"math"
	"strconv"

	"github.com/lvjp/go-utils/password/hashing"
	"github.com/lvjp/go-utils/password/hashing/phc"

	"golang.org/x/crypto/argon2"
)

const argon2ID = "argon2id"

type SaltGenerator func() ([]byte, error)

func NewSaltGenerator(length int, randSource io.Reader) SaltGenerator {
	return func() ([]byte, error) {
		salt := make([]byte, length)
		_, err := io.ReadFull(randSource, salt)
		if err != nil {
			return nil, err
		}

		return salt, nil
	}
}

type Parameters struct {
	Memory      uint32
	Time        uint32
	Parallelism uint8
	KeyLength   uint32
}

type Option func(*hasher)

func WithParameters(params Parameters) func(h *hasher) {
	return func(h *hasher) {
		h.params = params
	}
}

func WithSaltGenerator(g SaltGenerator) func(h *hasher) {
	return func(h *hasher) {
		h.salt = g
	}
}

func New(opts ...Option) hashing.PasswordHasher {
	h := &hasher{}

	defaultOptions := []Option{
		WithParameters(Parameters{
			Memory:      46 * 1024,
			Time:        1,
			Parallelism: 1,
			KeyLength:   32,
		}),
		WithSaltGenerator(NewSaltGenerator(16, rand.Reader)),
	}

	for _, opt := range append(defaultOptions, opts...) {
		opt(h)
	}

	return h
}

type hasher struct {
	params Parameters
	salt   SaltGenerator
}

func (h *hasher) Hash(password string) (hash string, err error) {
	salt, err := h.salt()
	if err != nil {
		return "", fmt.Errorf("salt generation error: %w", err)
	}

	derived := argon2.IDKey(
		[]byte(password),
		salt,
		h.params.Time,
		h.params.Memory,
		h.params.Parallelism,
		h.params.KeyLength,
	)

	phc := &phc.Format{
		ID:      argon2ID,
		Version: strconv.Itoa(argon2.Version),
		Params: []phc.Parameter{
			{Name: "m", Value: strconv.FormatUint(uint64(h.params.Memory), 10)},
			{Name: "t", Value: strconv.FormatUint(uint64(h.params.Time), 10)},
			{Name: "p", Value: strconv.FormatUint(uint64(h.params.Parallelism), 10)},
		},
		Hash: derived,
		Salt: salt,
	}

	return phc.String(), nil
}

func (h *hasher) IsSame(password string, hash string) (isSame bool, err error) {
	phc, params, err := Decode(hash)
	if err != nil {
		return false, err
	}

	newlyEncoded := EncodeWithSalt([]byte(password), phc.Salt, *params)

	return subtle.ConstantTimeCompare(phc.Hash, newlyEncoded.Hash) == 1, nil
}

func EncodeWithSalt(password, salt []byte, params Parameters) *phc.Format {
	copyedSalt := make([]byte, len(salt))
	subtle.ConstantTimeCopy(1, copyedSalt, salt)

	hash := argon2.IDKey(
		password,
		copyedSalt,
		params.Time,
		params.Memory,
		params.Parallelism,
		params.KeyLength,
	)

	return &phc.Format{
		ID:      argon2ID,
		Version: strconv.Itoa(argon2.Version),
		Params: []phc.Parameter{
			{Name: "m", Value: strconv.FormatUint(uint64(params.Memory), 10)},
			{Name: "t", Value: strconv.FormatUint(uint64(params.Time), 10)},
			{Name: "p", Value: strconv.FormatUint(uint64(params.Parallelism), 10)},
		},
		Hash: hash,
		Salt: copyedSalt,
	}
}

func Decode(encoded string) (*phc.Format, *Parameters, error) {
	decoded, err := phc.Decode(encoded)
	if err != nil {
		return nil, nil, fmt.Errorf("PHC decode error: %w", err)
	}

	if decoded.ID != argon2ID {
		return nil, nil, errors.New("unsupported hashing function: " + decoded.ID)
	}

	if decoded.Version != strconv.Itoa(argon2.Version) {
		return nil, nil, errors.New("unsupported argon2id version: " + decoded.Version)
	}

	if len(decoded.Params) != 3 {
		return nil, nil, errors.New("invalid parameter count: " + strconv.Itoa(len(decoded.Params)))
	}

	if decoded.Params[0].Name != "m" || decoded.Params[1].Name != "t" || decoded.Params[2].Name != "p" {
		return nil, nil, errors.New("parameters should be in the order: m, t, p")
	}

	memory, err := strconv.ParseUint(decoded.Params[0].Value, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("memory parameter decode error: %w", err)
	}

	time, err := strconv.ParseUint(decoded.Params[1].Value, 10, 32)
	if err != nil {
		return nil, nil, fmt.Errorf("time parameter decode error: %w", err)
	}

	parallelism, err := strconv.ParseUint(decoded.Params[2].Value, 10, 8)
	if err != nil {
		return nil, nil, fmt.Errorf("parallelims parameter decode error: %w", err)
	}

	if len(decoded.Hash) > math.MaxUint32 {
		return nil, nil, fmt.Errorf("hash is too long: %d", len(decoded.Hash))
	}

	params := &Parameters{
		KeyLength:   uint32(len(decoded.Hash)), // #nosec G115 -- Overflow is already check
		Memory:      uint32(memory),
		Time:        uint32(time),
		Parallelism: uint8(parallelism),
	}

	return decoded, params, nil
}
