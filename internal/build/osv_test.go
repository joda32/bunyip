package build

import (
	"encoding/json"
	"testing"
)

func mustRec(t *testing.T, s string) osvRecord {
	t.Helper()
	var r osvRecord
	if err := json.Unmarshal([]byte(s), &r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestUpstreamAndModuleStream(t *testing.T) {
	cases := map[string]string{"1:9.6p1-3ubuntu13.3": "9.6p1", "1.20.1-1.module+el8.4.0+1": "1.20.1", "2.4.58": "2.4.58"}
	for in, want := range cases {
		if got := upstreamOf(in); got != want {
			t.Errorf("upstreamOf(%q)=%q want %q", in, got, want)
		}
	}
	if s := moduleStream("1:1.14.1-9.module+el8.6.0+1"); s != "1.14" {
		t.Errorf("moduleStream=%q want 1.14", s)
	}
	if s := moduleStream("1.20.1-1.el8"); s != "" {
		t.Errorf("non-module stream=%q want empty", s)
	}
}

func TestTransformOSVUbuntu(t *testing.T) {
	d := Distros["ubuntu"]
	rec := mustRec(t, `{"id":"UBUNTU-CVE-2023-1111","modified":"2026-01-01T00:00:00Z",
	 "upstream":["CVE-2023-1111"],
	 "affected":[{"package":{"name":"openssh","ecosystem":"Ubuntu:22.04:LTS","purl":"pkg:deb/ubuntu/openssh?distro=jammy"},
	   "ranges":[{"events":[{"introduced":"0"},{"fixed":"1:8.9p1-3ubuntu0.4"}]}],
	   "versions":["1:8.9p1-3","1:8.9p1-3ubuntu0.4","1:8.9p1-3ubuntu0.6"],
	   "ecosystem_specific":{"ubuntu_priority":"medium"}}]}`)
	tr := transformOSV(rec, d, map[string]bool{"openssh": true}, true)
	if len(tr.Rows) != 1 {
		t.Fatalf("rows: %+v", tr.Rows)
	}
	r := tr.Rows[0]
	if r.CVEID != "CVE-2023-1111" || r.Release != "22.04" || r.Channel != "standard" || r.Package != "openssh" {
		t.Errorf("row basics: %+v", r)
	}
	if r.FixedVersion != "1:8.9p1-3ubuntu0.4" || r.Urgency != "medium" || r.Codename != "jammy" {
		t.Errorf("row fields: %+v", r)
	}
	// affected_upstreams: only versions OLDER than the fix (1:8.9p1-3 -> 8.9p1); the newer one excluded.
	if r.AffectedUpstreams != "8.9p1" {
		t.Errorf("affected_upstreams=%q want 8.9p1", r.AffectedUpstreams)
	}
	// package_versions: affected (older) + the fixed version itself.
	var hasFixed bool
	for _, v := range tr.Versions {
		if v.Version == "1:8.9p1-3ubuntu0.4" {
			hasFixed = true
		}
	}
	if !hasFixed {
		t.Errorf("fixed version not recorded in package_versions: %+v", tr.Versions)
	}
}

func TestTransformOSVWithdrawn(t *testing.T) {
	d := Distros["ubuntu"]
	rec := mustRec(t, `{"id":"UBUNTU-CVE-2023-2222","withdrawn":"2026-01-01T00:00:00Z","upstream":["CVE-2023-2222"],
	 "affected":[{"package":{"name":"openssh","ecosystem":"Ubuntu:22.04"},"versions":["1:1-1"]}]}`)
	tr := transformOSV(rec, d, map[string]bool{"openssh": true}, true)
	if !tr.Withdrawn || len(tr.Rows) != 0 {
		t.Errorf("withdrawn not honoured: %+v", tr)
	}
}

func TestCVEIDsPerAdvisory(t *testing.T) {
	// A DSA lists several CVEs; per-advisory keeps all, per-CVE keeps one.
	rec := mustRec(t, `{"id":"DSA-5555-1","upstream":["CVE-2023-3333","CVE-2023-4444"],"aliases":["DSA-5555-1"]}`)
	if ids := cveIDs(rec, false); len(ids) != 2 {
		t.Errorf("per-advisory ids: %v", ids)
	}
	if ids := cveIDs(rec, true); len(ids) != 1 || ids[0] != "CVE-2023-3333" {
		t.Errorf("per-cve ids: %v", ids)
	}
}
