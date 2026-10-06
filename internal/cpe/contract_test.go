package cpe

import (
	"encoding/json"
	"os"
	"testing"
)

// TestContractVectors checks the shared Go/Python contract: the Python
// updater derives cve_matches lookup columns with its own port of this
// package, and both must produce identical part/vendor/product values.
func TestContractVectors(t *testing.T) {
	data, err := os.ReadFile("../../testdata/contract/cpe_vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Vectors []struct {
			Criteria string `json:"criteria"`
			Part     string `json:"part"`
			Vendor   string `json:"vendor"`
			Product  string `json:"product"`
			Error    bool   `json:"error"`
		} `json:"vectors"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	if len(doc.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range doc.Vectors {
		c, err := ParsePattern(v.Criteria)
		if v.Error {
			if err == nil {
				t.Errorf("%q: accepted, want error", v.Criteria)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: %v", v.Criteria, err)
			continue
		}
		if c.Part != v.Part || c.Vendor != v.Vendor || c.Product != v.Product {
			t.Errorf("%q: got %s/%s/%s, want %s/%s/%s", v.Criteria,
				c.Part, c.Vendor, c.Product, v.Part, v.Vendor, v.Product)
		}
	}
}
