package vault

import (
	"encoding/json"
	"os"
	"testing"
)

func TestReferenceFixtures(t *testing.T) {
	contents, err := os.ReadFile("../fixtures/references.json")
	if err != nil {
		t.Fatal(err)
	}
	var fixtures struct {
		Valid   []struct{ Input, Scheme, Vault, Item, Field, Provider, Owner, Repo, Name string }
		Invalid []string
	}
	if err := json.Unmarshal(contents, &fixtures); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range fixtures.Valid {
		ref, err := ParseReference(fixture.Input)
		if err != nil {
			t.Fatalf("%s: %v", fixture.Input, err)
		}
		if ref.Scheme != fixture.Scheme || ref.Vault != fixture.Vault || ref.Item != fixture.Item || ref.Field != fixture.Field || ref.Provider != fixture.Provider || ref.Owner != fixture.Owner || ref.Repo != fixture.Repo || ref.Name != fixture.Name {
			t.Fatalf("%s: unexpected reference: %+v", fixture.Input, ref)
		}
	}
	for _, input := range fixtures.Invalid {
		if _, err := ParseReference(input); err == nil {
			t.Fatalf("%s: expected error", input)
		}
	}
}
