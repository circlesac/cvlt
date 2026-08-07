package vault

import "testing"

func TestKeychainAccountMatchesNode(t *testing.T) {
	if got, want := keychainAccount("https://vault.circles.ac"), "0Qmbik9-0yopq2mPuBD3_7cdx5ZsHAs3"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}
