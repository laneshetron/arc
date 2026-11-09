package gateway

import (
	"fmt"
	"strings"
)

// An Account is a set of clients isolated from every other account's: a
// client can reach the tunnel addresses of its own account's sessions,
// never another account's. Accounts share the relay's exit address.
type Account struct {
	// Name identifies the account in logs. It is unique among accounts.
	Name string
	// Tokens are the account's credentials; several allow rotating one
	// without disconnecting the account's other clients.
	Tokens [][]byte
	// RelayAccess lets the account's clients reach the relay's own tunnel
	// address (services the operator runs on the relay host). Other
	// addresses of the relay host are the host firewall's to protect.
	RelayAccess bool
}

// ParseAccounts reads the relay's accounts file, as keyfile.ReadLines
// returns it: one credential per line, either
//
//	NAME TOKEN [relay]
//
// where NAME may repeat to give an account several tokens and "relay"
// grants RelayAccess, or a bare
//
//	TOKEN
//
// which is an account of its own, named by its line number, with no
// relay access.
func ParseAccounts(lines []string) ([]Account, error) {
	var accounts []Account
	byName, bare := map[string]int{}, map[string]bool{}
	seen := map[string]bool{}
	for i, line := range lines {
		f := strings.Fields(line)
		var name, token string
		relay := false
		switch len(f) {
		case 1:
			name, token = fmt.Sprintf("line%d", i+1), f[0]
		case 2, 3:
			name, token = f[0], f[1]
			if len(f) == 3 {
				if f[2] != "relay" {
					return nil, fmt.Errorf("accounts line %d: unknown option %q (want relay)", i+1, f[2])
				}
				relay = true
			}
			if !validName(name) {
				return nil, fmt.Errorf("accounts line %d: invalid account name %q (letters, digits, '.', '_', '-')", i+1, name)
			}
		default:
			return nil, fmt.Errorf("accounts line %d: want NAME TOKEN [relay] or TOKEN", i+1)
		}
		if seen[token] {
			return nil, fmt.Errorf("accounts line %d: token repeated", i+1)
		}
		seen[token] = true
		if j, ok := byName[name]; ok && len(f) > 1 && !bare[name] {
			if accounts[j].RelayAccess != relay {
				return nil, fmt.Errorf("accounts line %d: account %s is listed with and without relay", i+1, name)
			}
			accounts[j].Tokens = append(accounts[j].Tokens, []byte(token))
			continue
		} else if ok {
			return nil, fmt.Errorf("accounts line %d: account name %s is taken", i+1, name)
		}
		byName[name] = len(accounts)
		bare[name] = len(f) == 1
		accounts = append(accounts, Account{Name: name, Tokens: [][]byte{[]byte(token)}, RelayAccess: relay})
	}
	return accounts, nil
}

func validName(s string) bool {
	if s == "" || len(s) > 64 {
		return false
	}
	for _, c := range []byte(s) {
		if !('a' <= c && c <= 'z' || 'A' <= c && c <= 'Z' || '0' <= c && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

// validate checks that names and tokens are unique across accounts.
func validate(accounts []Account) error {
	names, tokens := map[string]bool{}, map[string]bool{}
	for _, a := range accounts {
		if names[a.Name] {
			return fmt.Errorf("gateway: account name %q repeated", a.Name)
		}
		names[a.Name] = true
		if len(a.Tokens) == 0 {
			return fmt.Errorf("gateway: account %q has no tokens", a.Name)
		}
		for _, t := range a.Tokens {
			if len(t) == 0 {
				return fmt.Errorf("gateway: account %q has an empty token", a.Name)
			}
			if tokens[string(t)] {
				return fmt.Errorf("gateway: a token of account %q is repeated", a.Name)
			}
			tokens[string(t)] = true
		}
	}
	return nil
}
