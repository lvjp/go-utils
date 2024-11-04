package hashing

// import (
// 	"crypto/rand"
// 	"crypto/subtle"
// 	"fmt"
// 	"io"
// )

// var defautArgonParams = Parameters{
// 	Memory:      46 * 1024,
// 	Time:        1,
// 	Parallelism: 1,
// 	KeyLength:   32,
// }

// const saltLen = 16

// func EncodePassword(password string) (string, error) {
// 	salt := make([]byte, saltLen)
// 	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
// 		return "", fmt.Errorf("salt generation error: %w", err)
// 	}

// 	phc := EncodeWithSalt([]byte(password), salt, defautArgonParams)
// 	return phc.String(), nil
// }

// func IsSamePassword(plainPassword string, encodedPassword string) (bool, error) {
// 	phc, params, err := Decode(encodedPassword)
// 	if err != nil {
// 		return false, fmt.Errorf("encoded hash decoding error: %w", err)
// 	}

// 	newlyEncoded := EncodeWithSalt([]byte(plainPassword), phc.Salt, *params)

// 	return subtle.ConstantTimeCompare(phc.Hash, newlyEncoded.Hash) == 1, nil
// }
