package cpe

import (
	"errors"
	"testing"
)

func TestParseNormalises(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want string
	}{
		{"2.3 exact", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*",
			"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		{"2.3 upper case folded", "CPE:2.3:A:Apache:HTTP_Server:2.4.49:*:*:*:*:*:*:*",
			"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		{"2.3 surrounding whitespace", "  cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*\n",
			"cpe:2.3:a:nginx:nginx:1.20.0:*:*:*:*:*:*:*"},
		{"2.3 NA values preserved", "cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:x64:*",
			"cpe:2.3:o:microsoft:windows_10:-:*:*:*:*:*:x64:*"},
		{"2.3 escaped colon", `cpe:2.3:a:1c:1c\:enterprise:8.0:*:*:*:*:*:*:*`,
			`cpe:2.3:a:1c:1c\:enterprise:8.0:*:*:*:*:*:*:*`},
		{"2.3 needless escape of dot removed", `cpe:2.3:a:microsoft:\.net_framework:4\.8:*:*:*:*:*:*:*`,
			`cpe:2.3:a:microsoft:.net_framework:4.8:*:*:*:*:*:*:*`},
		{"2.3 escaped hyphen stays literal", `cpe:2.3:a:x:y:\-:*:*:*:*:*:*:*`,
			`cpe:2.3:a:x:y:\-:*:*:*:*:*:*:*`},
		{"2.2 nmap apache", "cpe:/a:apache:http_server:2.4.49",
			"cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		{"2.2 nmap openssh", "cpe:/a:openbsd:openssh:8.9p1",
			"cpe:2.3:a:openbsd:openssh:8.9p1:*:*:*:*:*:*:*"},
		{"2.2 no version", "cpe:/a:apache:http_server",
			"cpe:2.3:a:apache:http_server:*:*:*:*:*:*:*:*"},
		{"2.2 os with update", "cpe:/o:microsoft:windows_server_2008:r2:sp1",
			"cpe:2.3:o:microsoft:windows_server_2008:r2:sp1:*:*:*:*:*:*"},
		{"2.2 empty component is ANY", "cpe:/a:apache::2.4.49",
			"cpe:2.3:a:apache:*:2.4.49:*:*:*:*:*:*:*"},
		{"2.2 percent decoding escapes special chars", "cpe:/a:foo:bar%21:1.0%28beta%29",
			`cpe:2.3:a:foo:bar\!:1.0\(beta\):*:*:*:*:*:*:*`},
		{"2.2 tilde unencoded in plain component is escaped", "cpe:/a:foo:bar:1.0~rc1",
			`cpe:2.3:a:foo:bar:1.0\~rc1:*:*:*:*:*:*:*`},
		{"2.2 packed edition", "cpe:/a:hp:insight_diagnostics:7.4.0.1570:-:~~online~win2003~x64~",
			"cpe:2.3:a:hp:insight_diagnostics:7.4.0.1570:-:*:*:online:win2003:x64:*"},
		{"2.2 language", "cpe:/a:foo:bar:1.0:sp1:pro:en-us",
			"cpe:2.3:a:foo:bar:1.0:sp1:pro:en-us:*:*:*:*"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.in)
			if err != nil {
				t.Fatalf("Parse(%q) error: %v", tt.in, err)
			}
			if got.String() != tt.want {
				t.Errorf("Parse(%q) = %q, want %q", tt.in, got.String(), tt.want)
			}
			// Canonical output must round-trip.
			again, err := Parse(got.String())
			if err != nil || again != got {
				t.Errorf("round trip of %q failed: %v %+v", got.String(), err, again)
			}
		})
	}
}

func TestParseComponents(t *testing.T) {
	c, err := Parse("cpe:/a:apache:http_server:2.4.49")
	if err != nil {
		t.Fatal(err)
	}
	if c.Part != "a" || c.Vendor != "apache" || c.Product != "http_server" || c.Version != "2.4.49" {
		t.Errorf("unexpected components: %+v", c)
	}
	if c.Update != Any || c.TargetSW != Any {
		t.Errorf("omitted components should be ANY: %+v", c)
	}
}

func TestParseErrors(t *testing.T) {
	tests := []struct {
		name string
		in   string
	}{
		{"empty", ""},
		{"whitespace only", "   "},
		{"no prefix", "apache:http_server:2.4.49"},
		{"wrong 2.3 prefix", "cpe:2.2:a:apache:http_server"},
		{"2.3 too few attributes", "cpe:2.3:a:apache:http_server:2.4.49"},
		{"2.3 too many attributes", "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*:*"},
		{"2.3 empty attribute", "cpe:2.3:a::http_server:2.4.49:*:*:*:*:*:*:*"},
		{"2.3 bad part", "cpe:2.3:x:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		{"2.3 ANY part", "cpe:2.3:*:apache:http_server:2.4.49:*:*:*:*:*:*:*"},
		{"2.3 unescaped special", "cpe:2.3:a:apache:http server:2.4.49:*:*:*:*:*:*:*"},
		{"2.3 embedded wildcard in supplied", "cpe:2.3:a:apache:http_server:2.4.*:*:*:*:*:*:*:*"},
		{"2.3 trailing backslash", `cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:\`},
		{"2.2 too many components", "cpe:/a:a:b:c:d:e:f:g"},
		{"2.2 empty part", "cpe:/"},
		{"2.2 bad part", "cpe:/z:apache:http_server"},
		{"2.2 bad percent", "cpe:/a:foo:bar%zz"},
		{"2.2 truncated percent", "cpe:/a:foo:bar%2"},
		{"2.2 wildcard encoding", "cpe:/a:foo:bar:1.%02"},
		{"2.2 space", "cpe:/a:foo:bar baz"},
		{"2.2 bad packed edition", "cpe:/a:foo:bar:1:-:~a~b"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Parse(tt.in)
			if err == nil {
				t.Fatalf("Parse(%q) succeeded, want error", tt.in)
			}
			if !errors.Is(err, ErrMalformed) {
				t.Errorf("error %v does not wrap ErrMalformed", err)
			}
		})
	}
}

func TestParsePatternAllowsWildcards(t *testing.T) {
	c, err := ParsePattern("cpe:2.3:a:apache:http_server:2.4.*:*:*:*:*:*:*:*")
	if err != nil {
		t.Fatal(err)
	}
	if c.Version != "2.4.*" || !HasWildcard(c.Version) {
		t.Errorf("version = %q", c.Version)
	}
}

func TestUnescape(t *testing.T) {
	tests := map[string]string{
		"2.4.49":         "2.4.49",
		`1.0\(beta\)`:    "1.0(beta)",
		`1c\:enterprise`: "1c:enterprise",
		`a\\b`:           `a\b`,
		Any:              Any,
	}
	for in, want := range tests {
		if got := Unescape(in); got != want {
			t.Errorf("Unescape(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCompareAttribute(t *testing.T) {
	tests := []struct {
		criteria, supplied string
		want               Relation
	}{
		{Any, "2.4.49", RelMatch},
		{Any, Any, RelMatch},
		{Any, NA, RelMatch},
		{"apache", "apache", RelMatch},
		{"apache", "nginx", RelDisjoint},
		{"sp1", Any, RelUnknown},
		{NA, NA, RelMatch},
		{NA, "sp1", RelDisjoint},
		{"sp1", NA, RelDisjoint},
		{NA, Any, RelUnknown},
		{"2.4.*", "2.4.49", RelMatch},
		{"2.4.*", "2.5.0", RelDisjoint},
		{"?p1", "8p1", RelMatch},
		{`1.0\(*`, `1.0\(beta\)`, RelMatch},
		{`a\*`, "ab", RelDisjoint},
	}
	for _, tt := range tests {
		if got := CompareAttribute(tt.criteria, tt.supplied); got != tt.want {
			t.Errorf("CompareAttribute(%q, %q) = %v, want %v", tt.criteria, tt.supplied, got, tt.want)
		}
	}
}
