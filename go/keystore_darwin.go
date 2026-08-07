//go:build darwin

package vault

import (
	"errors"
	"os/exec"
	"strings"
)

func readOSCredential(account string) (string, error) {
	output, err := exec.Command("security", "find-generic-password", "-s", "circlesac.cvlt", "-a", account, "-w").Output()
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return "", nil
		}
		return "", err
	}
	return strings.TrimSpace(string(output)), nil
}
