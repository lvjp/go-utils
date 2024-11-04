package phc

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestFormat(t *testing.T) {
	salt, err := base64.RawStdEncoding.DecodeString("gZiV/M1gPc22ElAH/Jh1Hw")
	require.NoError(t, err)

	hash, err := base64.RawStdEncoding.DecodeString("CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno")
	require.NoError(t, err)

	testCases := []struct {
		name    string
		encoded string
		decoded *Format
	}{
		{
			name:    "full",
			encoded: "$argon2id$v=19$m=65536,t=2,p=1$gZiV/M1gPc22ElAH/Jh1Hw$CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno",
			decoded: &Format{
				ID:      "argon2id",
				Version: "19",
				Params: []Parameter{
					{Name: "m", Value: "65536"},
					{Name: "t", Value: "2"},
					{Name: "p", Value: "1"},
				},
				Salt: salt,
				Hash: hash,
			},
		},
		{
			name:    "id",
			encoded: "$argon2id",
			decoded: &Format{
				ID: "argon2id",
			},
		},
		{
			name:    "version",
			encoded: "$argon2id$v=19",
			decoded: &Format{
				ID:      "argon2id",
				Version: "19",
			},
		},
		{
			name:    "salt",
			encoded: "$argon2id$gZiV/M1gPc22ElAH/Jh1Hw",
			decoded: &Format{
				ID:   "argon2id",
				Salt: salt,
			},
		},
		{
			name:    "hash",
			encoded: "$argon2id$gZiV/M1gPc22ElAH/Jh1Hw$CWOrkoo7oJBQ/iyh7uJ0LO2aLEfrHwTWllSAxT0zRno",
			decoded: &Format{
				ID:   "argon2id",
				Salt: salt,
				Hash: hash,
			},
		},
		{
			name:    "params",
			encoded: "$argon2id$m=65536,t=2,p=1",
			decoded: &Format{
				ID: "argon2id",
				Params: []Parameter{
					{Name: "m", Value: "65536"},
					{Name: "t", Value: "2"},
					{Name: "p", Value: "1"},
				},
			},
		},
		{
			name:    "param named v first",
			encoded: "$argon2id$v=19,m=65536,t=2,p=1",
			decoded: &Format{
				ID: "argon2id",
				Params: []Parameter{
					{Name: "v", Value: "19"},
					{Name: "m", Value: "65536"},
					{Name: "t", Value: "2"},
					{Name: "p", Value: "1"},
				},
			},
		},
		{
			name:    "param named v only not version",
			encoded: "$argon2id$v=aparam",
			decoded: &Format{
				ID: "argon2id",
				Params: []Parameter{
					{Name: "v", Value: "aparam"},
				},
			},
		},
	}

	t.Run("UnmarshalText", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				f := &Format{}
				require.NoError(t, f.UnmarshalText([]byte(tc.encoded)))
				require.Equal(t, tc.decoded, f)
			})
		}
	})

	t.Run("MarshalText", func(t *testing.T) {
		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				encoded, err := tc.decoded.MarshalText()
				require.NoError(t, err)
				require.Equal(t, tc.encoded, string(encoded))
			})
		}
	})
}
