package vault

import (
	"fmt"
	"regexp"
	"strings"
)

type Reference struct {
	Scheme   string
	Vault    string
	Item     string
	Field    string
	Provider string
	Owner    string
	Repo     string
	Name     string
}

var ownerPattern = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$`)
var repoPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
var namePattern = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,199}$`)

func ParseReference(value string) (Reference, error) {
	if strings.HasPrefix(value, "op://") {
		parts := strings.Split(strings.SplitN(strings.TrimPrefix(value, "op://"), "?", 2)[0], "/")
		if len(parts) < 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
			return Reference{}, fmt.Errorf("expected op://<vault>/<item>/<field>")
		}
		return Reference{Scheme: "op", Vault: parts[0], Item: parts[1], Field: parts[2]}, nil
	}
	if strings.HasPrefix(value, "vlt://") {
		parts := strings.Split(strings.TrimPrefix(value, "vlt://"), "/")
		if len(parts) < 3 || len(parts) > 4 || parts[0] != "github.com" {
			return Reference{}, fmt.Errorf("expected vlt://github.com/<owner>[/<repo>]/<NAME>")
		}
		owner := parts[1]
		name := parts[len(parts)-1]
		if !ownerPattern.MatchString(owner) || !namePattern.MatchString(name) || strings.HasPrefix(name, "GITHUB_") {
			return Reference{}, fmt.Errorf("invalid vlt reference")
		}
		repo := ""
		if len(parts) == 4 {
			repo = parts[2]
			if !repoPattern.MatchString(repo) {
				return Reference{}, fmt.Errorf("invalid repository")
			}
		}
		return Reference{Scheme: "cvlt", Provider: "github.com", Owner: strings.ToLower(owner), Repo: strings.ToLower(repo), Name: name}, nil
	}
	return Reference{}, fmt.Errorf("unsupported secret reference")
}
