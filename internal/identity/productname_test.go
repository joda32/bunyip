package identity

import (
	"slices"
	"strings"
	"testing"

	"offline-vulndb/internal/database"
)

var testNames = []database.ProductName{
	{Pattern: "ClamAV", Match: "exact", Kind: "product", Part: "a", Vendor: "clamav", Product: "clamav",
		Version: "nmap", Confidence: "HIGH", Source: "test"},
	{Pattern: "ClamAV", Match: "exact", Kind: "product", Part: "a", Vendor: "clam_anti-virus", Product: "clamav",
		Version: "nmap", Confidence: "HIGH", Source: "test"},
	{Pattern: "SLURM", Match: "exact", Kind: "product", Part: "a", Vendor: "schedmd", Product: "slurm",
		Version: "none", Confidence: "HIGH", Note: "Nmap's version is the API version.", Source: "test"},
	{Pattern: "^Kerio MailServer( (smtpd|nntpd))?$", Match: "regex", Kind: "product", Part: "a", Vendor: "kerio",
		Product: "kerio_mailserver", Version: "nmap", Confidence: "MEDIUM", Source: "test"},
	{Pattern: "Microsoft Windows RPC", Match: "exact", Kind: "os_component", OS: "windows", Version: "none",
		Confidence: "HIGH", Source: "test"},
	{Pattern: "Microsoft Windows Kerberos", Match: "exact", Kind: "os_component", OS: "windows", Version: "none",
		Confidence: "HIGH", Source: "test"},
	{Pattern: "^(Microsoft )?Windows .*microsoft-ds$", Match: "regex", Kind: "os_component", OS: "windows",
		Version: "none", Confidence: "HIGH", Source: "test"},
}

func nameResolver(t *testing.T) *Resolver {
	t.Helper()
	r := NewResolver(nil)
	if err := r.AddProductNames(testNames); err != nil {
		t.Fatal(err)
	}
	return r
}

func cands(res Resolution) []string {
	var out []string
	for _, c := range res.Candidates {
		out = append(out, c.CPE.String()+"|"+string(c.Confidence))
	}
	return out
}

func hasNote(res Resolution, sub string) bool {
	return slices.ContainsFunc(res.Notes, func(n string) bool { return strings.Contains(n, sub) })
}

func TestProductNameWithVersion(t *testing.T) {
	// Nmap: p/ClamAV/ v/$1 ($2)/: only the first token is the product version.
	res := nameResolver(t).ResolveObservation(Observation{Product: "ClamAV", Version: "0.103.2 (27019)"}, "nmap")
	want := []string{
		"cpe:2.3:a:clamav:clamav:0.103.2:*:*:*:*:*:*:*|HIGH",
		"cpe:2.3:a:clam_anti-virus:clamav:0.103.2:*:*:*:*:*:*:*|HIGH",
	}
	if got := cands(res); !slices.Equal(got, want) {
		t.Errorf("got %v want %v", got, want)
	}
	if res.OSComponent != "" || hasNote(res, "not in the curated") || !strings.HasPrefix(res.Candidates[0].Source, "product-name:") {
		t.Errorf("unexpected: %+v", res)
	}
}

func TestProductNameRegexAndConfidence(t *testing.T) {
	res := nameResolver(t).ResolveObservation(Observation{Product: "Kerio MailServer smtpd", Version: "6.7.3 patch 1"}, "nmap")
	if got := cands(res); !slices.Equal(got, []string{"cpe:2.3:a:kerio:kerio_mailserver:6.7.3:*:*:*:*:*:*:*|MEDIUM"}) {
		t.Errorf("got %v", got)
	}
	// No version reported: the identity is LOW, like a CPE without a version.
	res = nameResolver(t).ResolveObservation(Observation{Product: "Kerio MailServer"}, "nmap")
	if got := cands(res); !slices.Equal(got, []string{"cpe:2.3:a:kerio:kerio_mailserver:*:*:*:*:*:*:*:*|LOW"}) {
		t.Errorf("got %v", got)
	}
	// Patterns are anchored: a longer name is not a match.
	res = nameResolver(t).ResolveObservation(Observation{Product: "Kerio MailServer smtpd proxy"}, "nmap")
	if len(res.Candidates) != 0 || !hasNote(res, "not in the curated product-name map") {
		t.Errorf("anchoring: %+v", res)
	}
}

func TestProductNameVersionNotProduct(t *testing.T) {
	res := nameResolver(t).ResolveObservation(Observation{Product: "SLURM", Version: "API 2.7"}, "nmap")
	if got := cands(res); !slices.Equal(got, []string{"cpe:2.3:a:schedmd:slurm:*:*:*:*:*:*:*:*|LOW"}) {
		t.Errorf("got %v", got)
	}
	if !hasNote(res, `Nmap's version "API 2.7" for "SLURM" is not the product version`) || !hasNote(res, "API version") {
		t.Errorf("notes: %v", res.Notes)
	}
}

func TestProductNameNotUsedWhenCPEReported(t *testing.T) {
	res := nameResolver(t).ResolveObservation(Observation{Product: "ClamAV", Version: "0.103.2",
		CPEs: []string{"cpe:/a:clamav:clamav:0.103.2"}}, "nmap")
	if got := cands(res); !slices.Equal(got, []string{"cpe:2.3:a:clamav:clamav:0.103.2:*:*:*:*:*:*:*|EXACT"}) {
		t.Errorf("got %v", got)
	}
}

func TestOSComponent(t *testing.T) {
	r := nameResolver(t)
	for _, o := range []Observation{
		{Product: "Microsoft Windows RPC", CPEs: []string{"cpe:/o:microsoft:windows"}},
		{Product: "Windows Server 2016 Standard Evaluation 14393 microsoft-ds"},
	} {
		res := r.ResolveObservation(o, "nmap")
		if res.OSComponent != "windows" || len(res.Candidates) != 0 || !hasNote(res, "covered by the host's Windows build assessment") ||
			hasNote(res, "not assessed") {
			t.Errorf("%q: %+v", o.Product, res)
		}
	}
	// With an application CPE (Nmap reports microsoft:kerberos), the CPE is
	// still queried and the note says its results are incomplete.
	res := r.ResolveObservation(Observation{Product: "Microsoft Windows Kerberos",
		CPEs: []string{"cpe:/a:microsoft:kerberos", "cpe:/o:microsoft:windows"}}, "nmap")
	if res.OSComponent != "windows" || len(res.Candidates) != 1 || !hasNote(res, "results for this CPE are incomplete") {
		t.Errorf("kerberos: %+v", res)
	}
}

func TestProductNameEscapesVersion(t *testing.T) {
	r := NewResolver(nil)
	if err := r.AddProductNames([]database.ProductName{{Pattern: "X", Match: "exact", Kind: "product", Part: "a",
		Vendor: "v", Product: "p", Version: "nmap", Confidence: "HIGH"}}); err != nil {
		t.Fatal(err)
	}
	for ver, want := range map[string]string{
		"1.0(beta)": `cpe:2.3:a:v:p:1.0\(beta\):*:*:*:*:*:*:*`,
		"2.*":       `cpe:2.3:a:v:p:2.\*:*:*:*:*:*:*:*`, // a reported "*" is a literal, not a wildcard
		"-":         `cpe:2.3:a:v:p:\-:*:*:*:*:*:*:*`,
	} {
		res := r.ResolveObservation(Observation{Product: "X", Version: ver}, "nmap")
		if len(res.Candidates) != 1 || res.Candidates[0].CPE.String() != want {
			t.Errorf("%q: %v", ver, cands(res))
		}
	}
}

func TestAddProductNamesRejectsBadRegex(t *testing.T) {
	err := NewResolver(nil).AddProductNames([]database.ProductName{{Pattern: "^(a$", Match: "regex", Kind: "os_component"}})
	if err == nil {
		t.Error("bad regex accepted")
	}
}
