//go:build linux

package vault

import (
	"errors"
	"os/exec"
	"strings"
)

func readOSCredential(account string) (string, error) {
	output, err := exec.Command("secret-tool", "lookup", "service", "circlesac.cvlt", "account", account).Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}
