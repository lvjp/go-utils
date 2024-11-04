package hashing

type PasswordHasher interface {
	Hash(password string) (hash string, err error)
	IsSame(password string, hash string) (isSame bool, err error)
}
