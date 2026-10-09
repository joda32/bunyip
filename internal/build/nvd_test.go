package build

import (
	"encoding/json"
	"os"
	"testing"
)

func transformFile(t *testing.T, path string) Record {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	r, err := Transform(raw)
	if err != nil {
		t.Fatalf("%s: %v", path, err)
	}
	return r
}

func findMatch(r Record, vendor, product string) *Match {
	for ci := range r.Configs {
		for ni := range r.Configs[ci].Nodes {
			for mi := range r.Configs[ci].Nodes[ni].Matches {
				m := &r.Configs[ci].Nodes[ni].Matches[mi]
				if m.Vendor == vendor && m.Product == product {
					return m
				}
			}
		}
	}
	return nil
}

func TestTransformApache(t *testing.T) {
	r := transformFile(t, "../../testdata/nvd/records/CVE-2021-41773.json")
	if r.CVEID != "CVE-2021-41773" || r.Rejected {
		t.Fatalf("id/rejected: %q %v", r.CVEID, r.Rejected)
	}
	if r.Severity != "CRITICAL" || r.CVSSv3Score == nil || *r.CVSSv3Score != 9.8 || r.CWE != "CWE-22" {
		t.Errorf("cvss/cwe: sev=%q score=%v cwe=%q", r.Severity, r.CVSSv3Score, r.CWE)
	}
	m := findMatch(r, "apache", "http_server")
	if m == nil || m.Part != "a" || !m.Vulnerable {
		t.Fatalf("apache match: %+v", m)
	}
	if len(r.Exploits) == 0 {
		t.Error("expected Exploit-tagged references")
	}
	for _, e := range r.Exploits {
		var meta map[string]any
		if json.Unmarshal([]byte(e.MetadataJSON), &meta) != nil || meta["tags"] == nil {
			t.Errorf("bad exploit metadata_json: %q", e.MetadataJSON)
		}
	}
}

func TestTransformRejected(t *testing.T) {
	r, err := Transform([]byte(`{"cve":{"id":"CVE-0000-0001","vulnStatus":"Rejected","descriptions":[{"lang":"en","value":"x"}]}}`))
	if err != nil {
		t.Fatal(err)
	}
	if !r.Rejected || r.CVEID != "CVE-0000-0001" || r.Description != "" || len(r.Configs) != 0 {
		t.Errorf("rejected record carried data: %+v", r)
	}
}

func TestTransformMetricPick(t *testing.T) {
	// v3.1 Primary/NVD wins over v3.0; v2 only supplies severity fallback.
	raw := `{"cve":{"id":"CVE-0000-0002","descriptions":[{"lang":"en","value":"d"}],"metrics":{
	 "cvssMetricV31":[{"type":"Primary","source":"nvd@nist.gov","cvssData":{"baseScore":7.5,"baseSeverity":"HIGH","vectorString":"V31"}},
	                  {"type":"Secondary","source":"other","cvssData":{"baseScore":5.0,"baseSeverity":"MEDIUM","vectorString":"X"}}],
	 "cvssMetricV30":[{"type":"Primary","source":"nvd@nist.gov","cvssData":{"baseScore":4.0,"baseSeverity":"MEDIUM","vectorString":"V30"}}]}}}`
	r, err := Transform([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if r.CVSSv3Score == nil || *r.CVSSv3Score != 7.5 || r.CVSSv3Vector != "V31" || r.Severity != "HIGH" {
		t.Errorf("metric pick: score=%v vec=%q sev=%q", r.CVSSv3Score, r.CVSSv3Vector, r.Severity)
	}
}

func TestTransformVersionKeyAndBounds(t *testing.T) {
	// Exact version -> version_key; a bounded rule -> no key.
	raw := `{"cve":{"id":"CVE-0000-0003","descriptions":[{"lang":"en","value":"d"}],"configurations":[{"nodes":[{"cpeMatch":[
	 {"criteria":"cpe:2.3:a:vendor:prod:1.2.3:*:*:*:*:*:*:*","vulnerable":true},
	 {"criteria":"cpe:2.3:a:vendor:prod:*:*:*:*:*:*:*:*","vulnerable":true,"versionEndExcluding":"2.0"}]}]}]}}`
	r, err := Transform([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	ms := r.Configs[0].Nodes[0].Matches
	if len(ms) != 2 || ms[0].VersionKey != "1.2" || ms[1].VersionKey != "" || ms[1].EndExcluding != "2.0" {
		t.Errorf("version_key/bounds: %+v", ms)
	}
}

func TestTransformSkipsBadCriteria(t *testing.T) {
	raw := `{"cve":{"id":"CVE-0000-0004","descriptions":[{"lang":"en","value":"d"}],"configurations":[{"nodes":[{"cpeMatch":[
	 {"criteria":"not-a-cpe","vulnerable":true}]}]}]}}`
	r, err := Transform([]byte(raw))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.SkippedRules) != 1 || len(r.Configs[0].Nodes[0].Matches) != 0 {
		t.Errorf("bad criteria not skipped: skipped=%v matches=%v", r.SkippedRules, r.Configs[0].Nodes[0].Matches)
	}
}
