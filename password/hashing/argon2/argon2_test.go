package argon2

import (
	"strconv"
	"testing"

	"github.com/stretchr/testify/require"
)

var testCases = []struct {
	password string
	salt     string
	params   Parameters
	hashed   string
}{
	{
		password: "password",
		salt:     "somesalt",
		params: Parameters{
			Time:        2,
			Memory:      1 << 16,
			Parallelism: 1,
			KeyLength:   32,
		},
		hashed: "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
	},
	{
		password: "password",
		salt:     "somesalt",
		params: Parameters{
			Time:        2,
			Memory:      1 << 18,
			Parallelism: 1,
			KeyLength:   32,
		},
		hashed: "$argon2id$v=19$m=262144,t=2,p=1$c29tZXNhbHQ$eP4eyR+zqlZX1y5xCFTkw9m5GYx0L5YWwvCFvtlbLow",
	},
	{
		password: "password",
		salt:     "somesalt",
		params: Parameters{
			Time:        2,
			Memory:      1 << 8,
			Parallelism: 1,
			KeyLength:   32,
		},
		hashed: "$argon2id$v=19$m=256,t=2,p=1$c29tZXNhbHQ$nf65EOgLrQMR/uIPnA4rEsF5h7TKyQwu9U1bMCHGi/4",
	},
	{
		password: "password",
		salt:     "somesalt",
		params: Parameters{
			Time:        2,
			Memory:      1 << 8,
			Parallelism: 2,
			KeyLength:   32,
		},
		hashed: "$argon2id$v=19$m=256,t=2,p=2$c29tZXNhbHQ$bQk8UB/VmZZF4Oo79iDXuL5/0ttZwg2f/5U52iv1cDc",
	},
	{
		password: "password",
		salt:     "somesalt",
		params: Parameters{
			Time:        1,
			Memory:      1 << 16,
			Parallelism: 1,
			KeyLength:   32,
		},
		hashed: "$argon2id$v=19$m=65536,t=1,p=1$c29tZXNhbHQ$9qWtwbpyPd3vm1rB1GThgPzZ3/ydHL92zKL+15XZypg",
	},
	{
		password: "password",
		salt:     "somesalt",
		params: Parameters{
			Time:        4,
			Memory:      1 << 16,
			Parallelism: 1,
			KeyLength:   32,
		},
		hashed: "$argon2id$v=19$m=65536,t=4,p=1$c29tZXNhbHQ$kCXUjmjvc5XMqQedpMTsOv+zyJEf5PhtGiUghW9jFyw",
	},
	{
		password: "differentpassword",
		salt:     "somesalt",
		params: Parameters{
			Time:        2,
			Memory:      1 << 16,
			Parallelism: 1,
			KeyLength:   32,
		},
		hashed: "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94",
	},
	{
		password: "password",
		salt:     "diffsalt",
		params: Parameters{
			Time:        2,
			Memory:      1 << 16,
			Parallelism: 1,
			KeyLength:   32,
		},
		hashed: "$argon2id$v=19$m=65536,t=2,p=1$ZGlmZnNhbHQ$vfMrBczELrFdWP0ZsfhWsRPaHppYdP3MVEMIVlqoFBw",
	},
}

func TestHasher_Hash(t *testing.T) {
	for i, tc := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			saltCount := 0
			h := New(
				WithParameters(tc.params),
				WithSaltGenerator(func() ([]byte, error) {
					saltCount++
					return []byte(tc.salt), nil
				}),
			)
			actual, err := h.Hash(tc.password)
			require.Equal(t, 1, saltCount)
			require.NoError(t, err)
			require.Equal(t, tc.hashed, actual)
		})
	}
}

func TestHasher_IsSame(t *testing.T) {
	for i, tc := range testCases {
		t.Run(strconv.Itoa(i), func(t *testing.T) {
			hasher := New()
			hash, err := hasher.Hash(tc.password)
			require.NoError(t, err)

			testCases := []struct {
				name     string
				password string
				isSame   bool
			}{
				{name: "empty", password: "", isSame: false},
				{name: "same", password: tc.password, isSame: true},
				{name: "differ", password: "pwouet", isSame: false},
			}

			for _, tc := range testCases {
				t.Run(tc.name, func(t *testing.T) {
					actual, err := hasher.IsSame(tc.password, hash)
					require.NoError(t, err)
					if false || true {
						require.Equal(t, tc.isSame, actual)
					}
				})
			}
		})
	}
}
