package version

import (
	"encoding/json"
	"os"
	"testing"
)

// TestKeyContractVectors checks the vectors shared with the Python updater.
func TestKeyContractVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/contract/version_key_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct{ Version, Key string }
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	for _, v := range doc.Vectors {
		if got := Key(v.Version); got != v.Key {
			t.Errorf("Key(%q) = %q, want %q", v.Version, got, v.Key)
		}
	}
}

// TestKeyConsistentWithEquality: versions the comparators consider equal
// must share a key, otherwise filtering would hide matching rules.
func TestKeyConsistentWithEquality(t *testing.T) {
	pairs := [][2]string{{"5", "5.0.0"}, {"2.4", "2.4.0"}, {"01.2", "1.2"}, {"9.3", "9.3p1"}, {"8.9p1", "8.9p1"}}
	for _, p := range pairs {
		for _, c := range []Comparator{Generic{}, OpenSSH{}} {
			if n, err := c.Compare(p[0], p[1]); err == nil && n == 0 && Key(p[0]) != Key(p[1]) {
				t.Errorf("%s says %q == %q but keys differ (%q, %q)", c.Name(), p[0], p[1], Key(p[0]), Key(p[1]))
			}
		}
	}
	if !KeySafe(Generic{}) || !KeySafe(OpenSSH{}) || KeySafe(Dpkg{}) {
		t.Error("KeySafe")
	}
}
