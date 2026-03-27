package core

import (
	"fmt"
	"os"
	"strings"
)

// Credential holds authentication information for one attempt.
type Credential struct {
	Username string
	Password string
	Hash     string
}

// ParseCredentials builds all credential combinations from the provided inputs.
// Each input can be a literal value, a file path, or an @file reference.
// If hash is set, it is used for all users (password ignored).
// Otherwise builds a Cartesian product of users × passwords.
func ParseCredentials(username, password, hash string) ([]Credential, error) {
	users, err := parseWordlist(username)
	if err != nil {
		return nil, fmt.Errorf("username: %w", err)
	}

	if hash != "" {
		creds := make([]Credential, len(users))
		for i, u := range users {
			creds[i] = Credential{Username: u, Hash: hash}
		}
		return creds, nil
	}

	passwords, err := parseWordlist(password)
	if err != nil {
		return nil, fmt.Errorf("password: %w", err)
	}

	creds := make([]Credential, 0, len(users)*len(passwords))
	for _, u := range users {
		for _, p := range passwords {
			creds = append(creds, Credential{Username: u, Password: p})
		}
	}
	return creds, nil
}

// parseWordlist returns the input as a slice.
// If it starts with @, treats the rest as a file path.
// If it's an existing file path, reads it line by line.
// Otherwise returns [input].
func parseWordlist(input string) ([]string, error) {
	if strings.HasPrefix(input, "@") {
		return readLines(input[1:])
	}
	if input != "" {
		if info, err := os.Stat(input); err == nil && !info.IsDir() {
			return readLines(input)
		}
	}
	return []string{input}, nil
}
