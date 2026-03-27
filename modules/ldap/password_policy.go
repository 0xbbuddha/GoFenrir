package ldapmodules

import (
	"fmt"

	"github.com/0xbbuddha/GoFenrir/protocols/ldap"
)

type PasswordPolicy struct {
	MinPwdLength        string
	MaxPwdAge           string
	MinPwdAge           string
	PwdHistoryLength    string
	LockoutThreshold    string
	LockoutDuration     string
	PwdProperties       string
	PwdComplexity       bool
}

func GetPasswordPolicy(s *ldap.Session) (*PasswordPolicy, error) {
	entries, err := s.LdapSession.QueryBaseObject(
		"defaultNamingContext",
		"(objectClass=domain)",
		[]string{
			"minPwdLength", "maxPwdAge", "minPwdAge",
			"pwdHistoryLength", "lockoutThreshold",
			"lockoutDuration", "pwdProperties",
		},
	)
	if err != nil {
		return nil, fmt.Errorf("failed to get password policy: %w", err)
	}
	if len(entries) == 0 {
		return nil, fmt.Errorf("no domain object found")
	}

	e := entries[0]
	pwdProp := e.GetAttributeValue("pwdProperties")
	complex := pwdProp == "1" || pwdProp == "17"

	return &PasswordPolicy{
		MinPwdLength:     e.GetAttributeValue("minPwdLength"),
		MaxPwdAge:        e.GetAttributeValue("maxPwdAge"),
		MinPwdAge:        e.GetAttributeValue("minPwdAge"),
		PwdHistoryLength: e.GetAttributeValue("pwdHistoryLength"),
		LockoutThreshold: e.GetAttributeValue("lockoutThreshold"),
		LockoutDuration:  e.GetAttributeValue("lockoutDuration"),
		PwdProperties:    pwdProp,
		PwdComplexity:    complex,
	}, nil
}
