package build

import (
	"encoding/json"
	"fmt"
	"os"
)

// KEVRow is one CISA Known Exploited Vulnerabilities entry.
type KEVRow struct {
	CVEID             string
	VendorProject     string
	Product           string
	VulnerabilityName string
	DateAdded         string
	DueDate           string
	KnownRansomware   string
	Notes             string
}

// KEVCatalogue is the parsed KEV catalogue.
type KEVCatalogue struct {
	CatalogVersion string
	DateReleased   string
	Rows           []KEVRow
}

type kevDoc struct {
	CatalogVersion  string `json:"catalogVersion"`
	DateReleased    string `json:"dateReleased"`
	Vulnerabilities []struct {
		CVEID                      string `json:"cveID"`
		VendorProject              string `json:"vendorProject"`
		Product                    string `json:"product"`
		VulnerabilityName          string `json:"vulnerabilityName"`
		DateAdded                  string `json:"dateAdded"`
		DueDate                    string `json:"dueDate"`
		KnownRansomwareCampaignUse string `json:"knownRansomwareCampaignUse"`
		Notes                      string `json:"notes"`
	} `json:"vulnerabilities"`
}

// LoadKEV reads and validates the KEV JSON file. Unknown fields are ignored
// so new CISA additions do not break the build; duplicate CVE IDs are kept
// once (first wins), matching the Python updater.
func LoadKEV(path string) (KEVCatalogue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return KEVCatalogue{}, err
	}
	var doc kevDoc
	if err := json.Unmarshal(data, &doc); err != nil {
		return KEVCatalogue{}, fmt.Errorf("%s: not a KEV catalogue: %w", path, err)
	}
	if doc.CatalogVersion == "" {
		return KEVCatalogue{}, fmt.Errorf("%s: missing catalogVersion", path)
	}
	cat := KEVCatalogue{CatalogVersion: doc.CatalogVersion, DateReleased: doc.DateReleased}
	seen := map[string]bool{}
	for _, v := range doc.Vulnerabilities {
		if v.CVEID == "" || seen[v.CVEID] {
			continue
		}
		seen[v.CVEID] = true
		cat.Rows = append(cat.Rows, KEVRow{v.CVEID, v.VendorProject, v.Product, v.VulnerabilityName,
			v.DateAdded, v.DueDate, v.KnownRansomwareCampaignUse, v.Notes})
	}
	return cat, nil
}
