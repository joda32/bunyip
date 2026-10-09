package identity

import (
	"slices"
	"testing"

	"offline-vulndb/internal/database"
)

var testHTTPApps = []database.HTTPApp{
	{Evidence: "generator", Pattern: `^WordPress(?: ([0-9][0-9.]*))?`, Vendor: "wordpress", Product: "wordpress", VersionGroup: 1, Confidence: "HIGH", Source: "test"},
	{Evidence: "server", Pattern: `^Jetty\(([0-9]+(?:\.[0-9]+)*)`, Vendor: "eclipse", Product: "jetty", VersionGroup: 1, Confidence: "HIGH", Source: "test"},
	{Evidence: "header", Header: "x-jenkins", Pattern: `^([0-9][0-9.]*)`, Vendor: "jenkins", Product: "jenkins", VersionGroup: 1, Confidence: "HIGH", Source: "test"},
	{Evidence: "x_powered_by", Pattern: `^PHP/([0-9][0-9.]*)`, Vendor: "php", Product: "php", VersionGroup: 1, Confidence: "HIGH", Source: "test"},
	{Evidence: "server", Pattern: `^Apache-Coyote/`, Vendor: "apache", Product: "tomcat", VersionGroup: 0, Confidence: "MEDIUM", Note: "connector banner", Source: "test"},
}

func httpResolver(t *testing.T) *Resolver {
	t.Helper()
	r := NewResolver(nil)
	if err := r.AddHTTPApps(testHTTPApps); err != nil {
		t.Fatal(err)
	}
	return r
}

func candStr(res Resolution) []string {
	var out []string
	for _, c := range res.Candidates {
		out = append(out, c.CPE.String()+"|"+string(c.Confidence)+"|"+c.Source)
	}
	slices.Sort(out)
	return out
}

func TestHTTPAppGeneratorWithVersion(t *testing.T) {
	// WordPress behind nginx: the nginx CPE is kept, WordPress added from the generator.
	res := httpResolver(t).ResolveObservation(Observation{
		Product: "nginx", CPEs: []string{"cpe:/a:igor_sysoev:nginx:1.24.0"},
		HTTP: map[string]string{"generator": "WordPress 6.4.2"},
	}, "nmap")
	got := candStr(res)
	if !slices.Contains(got, "cpe:2.3:a:wordpress:wordpress:6.4.2:*:*:*:*:*:*:*|HIGH|http-app:test") {
		t.Errorf("wordpress identity missing: %v", got)
	}
	if !slices.Contains(got, "cpe:2.3:a:igor_sysoev:nginx:1.24.0:*:*:*:*:*:*:*|EXACT|nmap") {
		t.Errorf("nginx identity should be kept: %v", got)
	}
}

func TestHTTPAppNoVersionIsLow(t *testing.T) {
	// Generator without a version (security plugins strip it) -> LOW, still identifies the product.
	res := httpResolver(t).ResolveObservation(Observation{HTTP: map[string]string{"generator": "WordPress"}}, "nmap")
	if got := candStr(res); !slices.Contains(got, "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*|LOW|http-app:test") {
		t.Errorf("got %v", got)
	}
}

func TestHTTPAppSources(t *testing.T) {
	r := httpResolver(t)
	cases := []struct {
		http map[string]string
		want string
	}{
		{map[string]string{"server": "Jetty(9.4.51.v20230217)"}, "cpe:2.3:a:eclipse:jetty:9.4.51:*:*:*:*:*:*:*|HIGH|http-app:test"},
		{map[string]string{"header:x-jenkins": "2.426.1"}, "cpe:2.3:a:jenkins:jenkins:2.426.1:*:*:*:*:*:*:*|HIGH|http-app:test"},
		{map[string]string{"x_powered_by": "PHP/8.2.7"}, "cpe:2.3:a:php:php:8.2.7:*:*:*:*:*:*:*|HIGH|http-app:test"},
		{map[string]string{"server": "Apache-Coyote/1.1"}, "cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*|LOW|http-app:test"},
	}
	for _, tc := range cases {
		res := r.ResolveObservation(Observation{HTTP: tc.http}, "nmap")
		if got := candStr(res); !slices.Contains(got, tc.want) {
			t.Errorf("HTTP %v: want %q in %v", tc.http, tc.want, got)
		}
	}
	// Non-matching evidence yields nothing.
	res := r.ResolveObservation(Observation{HTTP: map[string]string{"server": "Microsoft-IIS/10.0"}}, "nmap")
	for _, c := range res.Candidates {
		if c.Source == "http-app:test" {
			t.Errorf("unexpected http-app candidate: %+v", c)
		}
	}
}

func TestHTTPAppBadRegexRejected(t *testing.T) {
	if err := NewResolver(nil).AddHTTPApps([]database.HTTPApp{{Evidence: "server", Pattern: "("}}); err == nil {
		t.Error("bad regex accepted")
	}
}
