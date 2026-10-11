package version

import (
	"encoding/json"
	"os"
	"testing"
)

// TestRPMContractVectors checks the vectors shared with the Python updater
// (updater/src/bunyip_update/rpmversion.py).
func TestRPMContractVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/contract/rpm_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			A, B string
			Want int
		}
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	var r RPM
	for _, v := range doc.Vectors {
		got, err := r.Compare(v.A, v.B)
		if err != nil || got != v.Want {
			t.Errorf("Compare(%q, %q) = %d, %v; want %d", v.A, v.B, got, err, v.Want)
		}
		if back, _ := r.Compare(v.B, v.A); back != -v.Want {
			t.Errorf("Compare(%q, %q) not antisymmetric", v.B, v.A)
		}
	}
}

func TestParseRPM(t *testing.T) {
	v, err := ParseRPM("1:1.14.1-9.module+el8.4.0+542+81547229")
	if err != nil || v.Epoch != "1" || v.Upstream != "1.14.1" || v.Revision != "9.module+el8.4.0+542+81547229" {
		t.Fatalf("%+v %v", v, err)
	}
	for _, bad := range []string{"", "x:1.0", "1.0 1", ":1"} {
		if _, err := ParseRPM(bad); err == nil {
			t.Errorf("ParseRPM(%q) accepted", bad)
		}
	}
}
