package vault

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDecryptNodeContentFixture(t *testing.T) {
	contents, err := os.ReadFile("../fixtures/e2ee-content.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixture struct {
		Key, Context, Plaintext string
		Envelope                ContentEnvelope
	}
	if err := json.Unmarshal(contents, &fixture); err != nil {
		t.Fatal(err)
	}
	key, err := decodeBase64(fixture.Key)
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := DecryptContent(fixture.Envelope, key, fixture.Context)
	if err != nil {
		t.Fatal(err)
	}
	if string(plaintext) != fixture.Plaintext {
		t.Fatalf("unexpected plaintext: %q", plaintext)
	}
}
