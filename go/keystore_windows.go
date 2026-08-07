//go:build windows

package vault

import "fmt"

func readOSCredential(account string) (string, error) {
	return "", fmt.Errorf("Windows DPAPI support is not implemented yet")
}
