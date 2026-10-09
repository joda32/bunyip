package identity

import "testing"

func TestDebRevision(t *testing.T) {
	cases := map[string]string{
		"9.18.39-0ubuntu0.24.04.7": "0ubuntu0.24.04.7", // single token (BIND)
		"1:9.6p1-3ubuntu13.18":     "3ubuntu13.18",     // epoch form
		"5.0.51a-3ubuntu5":         "3ubuntu5",         // MySQL on MS2
		"8.4p1 Debian 5+deb11u7":   "5+deb11u7",        // space-separated (OpenSSH)
		"9.6p1":                    "",                 // clean upstream, no revision
		"2.4.58":                   "",                 // plain
		"1.0-beta":                 "",                 // hyphen suffix without a digit: not a revision
		"":                         "",
	}
	for in, want := range cases {
		if got := debRevision(in); got != want {
			t.Errorf("debRevision(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestResolveObservationStripsDebRevision(t *testing.T) {
	r := NewResolver(nil)

	// Single-token dpkg version baked into the CPE (Nmap BIND on Ubuntu):
	// the candidate upstream is cleaned and the revision kept on DistroInfo.
	res := r.ResolveObservation(Observation{Product: "ISC BIND", Version: "9.18.39-0ubuntu0.24.04.7",
		CPEs: []string{"cpe:/a:isc:bind:9.18.39-0ubuntu0.24.04.7"}}, "nmap")
	if len(res.Candidates) != 1 || res.Candidates[0].CPE.Version != "9.18.39" {
		t.Fatalf("BIND candidate = %+v", res.Candidates)
	}
	if res.Candidates[0].Confidence != Exact {
		t.Errorf("BIND confidence = %s, want EXACT", res.Candidates[0].Confidence)
	}
	if res.Distro.Key != "ubuntu" || res.Distro.Revision != "0ubuntu0.24.04.7" {
		t.Errorf("BIND distro = %+v", res.Distro)
	}

	// OpenSSH keeps its already-clean upstream (revision comes from the
	// space-separated banner, not the CPE), so nothing is stripped.
	res = r.ResolveObservation(Observation{Product: "OpenSSH", Version: "9.6p1 Ubuntu 3ubuntu13.18",
		ExtraInfo: "Ubuntu Linux; protocol 2.0", CPEs: []string{"cpe:/a:openbsd:openssh:9.6p1"}}, "nmap")
	if res.Candidates[0].CPE.Version != "9.6p1" || res.Distro.Revision != "3ubuntu13.18" {
		t.Errorf("OpenSSH = %+v / %+v", res.Candidates[0].CPE, res.Distro)
	}

	// No distro detected (no marker): version left untouched even if it has a hyphen.
	res = r.ResolveObservation(Observation{Product: "Thing", Version: "1.2-3",
		CPEs: []string{"cpe:/a:acme:thing:1.2-3"}}, "nmap")
	if res.Distro.Detected() || res.Candidates[0].CPE.Version != "1.2-3" {
		t.Errorf("non-distro = %+v / distro %+v", res.Candidates[0].CPE, res.Distro)
	}
}
