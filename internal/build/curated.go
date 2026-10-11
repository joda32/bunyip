package build

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	curated "bunyip/data"
	"bunyip/internal/cpe"
)

// Curated first-party data loaders (aliases, windows builds, product names,
// HTTP app fingerprints) and the webappanalyzer-derived http_tech map. These
// mirror the Python loaders exactly so the built tables are identical.

// unportableRe matches regex constructs Go's RE2 rejects (lookaround,
// back-references); curated patterns must avoid them.
var unportableRe = regexp.MustCompile(`\(\?[=!<]|\\[1-9]`)

// --- aliases ---

type AliasRow struct {
	Part, ObservedVendor, ObservedProduct, CanonicalVendor, CanonicalProduct, Source, Confidence string
}

func (a AliasRow) prefix() string {
	return fmt.Sprintf("cpe:2.3:%s:%s:%s", a.Part, a.CanonicalVendor, a.CanonicalProduct)
}

func triple(s, where string) (part, vendor, product string, err error) {
	bits := strings.Split(s, ":")
	if len(bits) != 3 {
		return "", "", "", fmt.Errorf("%s: %q must be part:vendor:product", where, s)
	}
	c, e := cpe.ParsePattern(fmt.Sprintf("cpe:2.3:%s:%s:%s:*:*:*:*:*:*:*:*", bits[0], bits[1], bits[2]))
	if e != nil {
		return "", "", "", fmt.Errorf("%s: %q: %w", where, s, e)
	}
	if !cpe.IsSpecific(c.Vendor) || !cpe.IsSpecific(c.Product) {
		return "", "", "", fmt.Errorf("%s: %q needs a specific vendor and product", where, s)
	}
	return c.Part, c.Vendor, c.Product, nil
}

// LoadAliases reads data/aliases.json.
func LoadAliases(path string) ([]AliasRow, error) {
	var doc struct {
		Source  string `json:"source"`
		Aliases []struct {
			Observed   string   `json:"observed"`
			Canonical  []string `json:"canonical"`
			Confidence string   `json:"confidence"`
		} `json:"aliases"`
	}
	if err := readJSON(path, &doc); err != nil {
		return nil, err
	}
	if doc.Source == "" {
		return nil, fmt.Errorf("%s: missing source", path)
	}
	var rows []AliasRow
	seen := map[[3]string]bool{}
	for i, a := range doc.Aliases {
		where := fmt.Sprintf("%s: aliases[%d]", path, i)
		op, ov, opr, err := triple(a.Observed, where)
		if err != nil {
			return nil, err
		}
		obs := [3]string{op, ov, opr}
		if seen[obs] {
			return nil, fmt.Errorf("%s: duplicate observed %q", where, a.Observed)
		}
		seen[obs] = true
		if a.Confidence != "HIGH" && a.Confidence != "MEDIUM" && a.Confidence != "LOW" {
			return nil, fmt.Errorf("%s: confidence must be HIGH/MEDIUM/LOW", where)
		}
		if len(a.Canonical) == 0 {
			return nil, fmt.Errorf("%s: no canonical targets", where)
		}
		for _, t := range a.Canonical {
			cp, cv, cpr, err := triple(t, where)
			if err != nil {
				return nil, err
			}
			if cp != op {
				return nil, fmt.Errorf("%s: alias may not change CPE part (%s -> %s)", where, op, cp)
			}
			if cv == ov && cpr == opr {
				return nil, fmt.Errorf("%s: alias maps %q to itself", where, a.Observed)
			}
			rows = append(rows, AliasRow{op, ov, opr, cv, cpr, doc.Source, a.Confidence})
		}
	}
	return rows, nil
}

// --- windows builds ---

type WindowsBuildRow struct {
	Build        int
	Kind, Name   string
	CPEs         string // space-joined full CPE 2.3 names
	EOL, Support string
	Source       string
}

// LoadWindowsBuilds reads data/windows_builds.json, expanding the short
// product:version:update CPEs to full CPE 2.3 names.
func LoadWindowsBuilds(path string) ([]WindowsBuildRow, error) {
	var doc struct {
		Source string `json:"source"`
		Builds []struct {
			Build   int      `json:"build"`
			Kind    string   `json:"kind"`
			Name    string   `json:"name"`
			CPEs    []string `json:"cpes"`
			EOL     string   `json:"eol"`
			Support string   `json:"support"`
		} `json:"builds"`
	}
	if err := readJSON(path, &doc); err != nil {
		return nil, err
	}
	if doc.Source == "" {
		return nil, fmt.Errorf("%s: missing source", path)
	}
	var rows []WindowsBuildRow
	seen := map[string]bool{}
	for i, b := range doc.Builds {
		where := fmt.Sprintf("%s: builds[%d]", path, i)
		if b.Build == 0 || (b.Kind != "server" && b.Kind != "client") {
			return nil, fmt.Errorf("%s: invalid build/kind", where)
		}
		key := fmt.Sprintf("%d/%s", b.Build, b.Kind)
		if seen[key] {
			return nil, fmt.Errorf("%s: duplicate %s", where, key)
		}
		seen[key] = true
		if !isISODate(b.EOL) {
			return nil, fmt.Errorf("%s: eol not YYYY-MM-DD", where)
		}
		var full []string
		for _, short := range b.CPEs {
			parts := strings.Split(short, ":")
			if len(parts) != 3 {
				return nil, fmt.Errorf("%s: cpe %q must be product:version:update", where, short)
			}
			bad := parts[1] == "*"
			for _, pp := range parts {
				if pp != "*" && hasWildcard(pp) {
					bad = true
				}
			}
			if bad {
				return nil, fmt.Errorf("%s: cpe %q must not use wildcards", where, short)
			}
			f := fmt.Sprintf("cpe:2.3:o:microsoft:%s:%s:%s:*:*:*:*:*:*", parts[0], parts[1], parts[2])
			if _, err := cpe.ParsePattern(f); err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			full = append(full, f)
		}
		if len(full) == 0 || b.Name == "" || b.Support == "" {
			return nil, fmt.Errorf("%s: name, support and >=1 cpe required", where)
		}
		rows = append(rows, WindowsBuildRow{b.Build, b.Kind, b.Name, strings.Join(full, " "), b.EOL, b.Support, doc.Source})
	}
	return rows, nil
}

func hasWildcard(s string) bool { return strings.ContainsAny(s, "*?") }

// --- product names ---

type ProductNameRow struct {
	Pattern, Match, Kind, Part, Vendor, Product, OS, Version, Confidence, Note, Source string
}

func curatedPattern(where string, pattern, match string) (string, string, error) {
	if pattern == "" {
		return "", "", fmt.Errorf("%s: pattern is required", where)
	}
	if match == "" {
		match = "exact"
	}
	if match != "exact" && match != "regex" {
		return "", "", fmt.Errorf("%s: match must be exact or regex", where)
	}
	if match == "regex" {
		if unportableRe.MatchString(pattern) {
			return "", "", fmt.Errorf("%s: lookaround/back-references not portable: %q", where, pattern)
		}
		if !strings.HasPrefix(pattern, "^") || !strings.HasSuffix(pattern, "$") {
			return "", "", fmt.Errorf("%s: regex must be anchored ^...$: %q", where, pattern)
		}
		if _, err := regexp.Compile(pattern); err != nil {
			return "", "", fmt.Errorf("%s: %w", where, err)
		}
	}
	return pattern, match, nil
}

// LoadProductNames reads data/product_names.json.
func LoadProductNames(path string) ([]ProductNameRow, error) {
	var doc struct {
		Source       string `json:"source"`
		OSComponents []struct {
			Pattern, Match, OS, Note string
		} `json:"os_components"`
		Products []struct {
			Pattern, Match            string
			CPEs                      []string `json:"cpes"`
			Version, Confidence, Note string
		} `json:"products"`
	}
	if err := readJSONCaseless(path, &doc); err != nil {
		return nil, err
	}
	if doc.Source == "" {
		return nil, fmt.Errorf("%s: missing source", path)
	}
	var rows []ProductNameRow
	seen := map[[4]string]bool{}
	add := func(r ProductNameRow, where string) error {
		k := [4]string{r.Pattern, r.Kind, r.Vendor, r.Product}
		if seen[k] {
			return fmt.Errorf("%s: duplicate entry", where)
		}
		seen[k] = true
		rows = append(rows, r)
		return nil
	}
	for i, e := range doc.OSComponents {
		where := fmt.Sprintf("%s: os_components[%d]", path, i)
		pat, m, err := curatedPattern(where, e.Pattern, e.Match)
		if err != nil {
			return nil, err
		}
		if e.OS != "windows" {
			return nil, fmt.Errorf("%s: os must be 'windows'", where)
		}
		if err := add(ProductNameRow{pat, m, "os_component", "", "", "", "windows", "none", "HIGH", e.Note, doc.Source}, where); err != nil {
			return nil, err
		}
	}
	for i, e := range doc.Products {
		where := fmt.Sprintf("%s: products[%d]", path, i)
		pat, m, err := curatedPattern(where, e.Pattern, e.Match)
		if err != nil {
			return nil, err
		}
		if e.Version != "nmap" && e.Version != "none" {
			return nil, fmt.Errorf("%s: version must be nmap/none", where)
		}
		if e.Confidence != "HIGH" && e.Confidence != "MEDIUM" {
			return nil, fmt.Errorf("%s: confidence must be HIGH/MEDIUM", where)
		}
		if len(e.CPEs) == 0 {
			return nil, fmt.Errorf("%s: at least one vendor:product required", where)
		}
		for _, t := range e.CPEs {
			parts := strings.Split(t, ":")
			if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
				return nil, fmt.Errorf("%s: %q must be vendor:product", where, t)
			}
			c, err := cpe.ParsePattern(fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", parts[0], parts[1]))
			if err != nil {
				return nil, fmt.Errorf("%s: %w", where, err)
			}
			if err := add(ProductNameRow{pat, m, "product", c.Part, c.Vendor, c.Product, "", e.Version, e.Confidence, e.Note, doc.Source}, where); err != nil {
				return nil, err
			}
		}
	}
	return rows, nil
}

// --- http apps ---

type HTTPAppRow struct {
	Evidence, Header, Pattern, Vendor, Product string
	VersionGroup                               int
	Confidence, Note, Source                   string
}

var httpEvidenceKinds = map[string]bool{"server": true, "generator": true, "header": true, "title": true, "x_powered_by": true}

// LoadHTTPApps reads data/http_apps.json.
func LoadHTTPApps(path string) ([]HTTPAppRow, error) {
	var doc struct {
		Source string `json:"source"`
		Apps   []struct {
			Evidence, Header, Pattern, Vendor, Product, Confidence, Note string
			VersionGroup                                                 int `json:"version_group"`
		} `json:"apps"`
	}
	if err := readJSONCaseless(path, &doc); err != nil {
		return nil, err
	}
	if doc.Source == "" {
		return nil, fmt.Errorf("%s: missing source", path)
	}
	var rows []HTTPAppRow
	seen := map[[5]string]bool{}
	for i, a := range doc.Apps {
		where := fmt.Sprintf("%s: apps[%d]", path, i)
		if !httpEvidenceKinds[a.Evidence] {
			return nil, fmt.Errorf("%s: bad evidence %q", where, a.Evidence)
		}
		header := strings.ToLower(a.Header)
		if (a.Evidence == "header") != (header != "") {
			return nil, fmt.Errorf("%s: 'header' required iff evidence=header", where)
		}
		if a.Pattern == "" {
			return nil, fmt.Errorf("%s: pattern required", where)
		}
		if unportableRe.MatchString(a.Pattern) {
			return nil, fmt.Errorf("%s: unportable regex %q", where, a.Pattern)
		}
		re, err := regexp.Compile(a.Pattern)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		if a.Vendor == "" || a.Product == "" {
			return nil, fmt.Errorf("%s: vendor and product required", where)
		}
		if _, err := cpe.ParsePattern(fmt.Sprintf("cpe:2.3:a:%s:%s:*:*:*:*:*:*:*:*", a.Vendor, a.Product)); err != nil {
			return nil, fmt.Errorf("%s: %w", where, err)
		}
		if a.VersionGroup < 0 || a.VersionGroup > re.NumSubexp() {
			return nil, fmt.Errorf("%s: version_group %d out of range", where, a.VersionGroup)
		}
		if a.Confidence != "HIGH" && a.Confidence != "MEDIUM" {
			return nil, fmt.Errorf("%s: confidence must be HIGH/MEDIUM", where)
		}
		k := [5]string{a.Evidence, header, a.Pattern, a.Vendor, a.Product}
		if seen[k] {
			return nil, fmt.Errorf("%s: duplicate entry", where)
		}
		seen[k] = true
		rows = append(rows, HTTPAppRow{a.Evidence, header, a.Pattern, a.Vendor, a.Product, a.VersionGroup, a.Confidence, a.Note, doc.Source})
	}
	return rows, nil
}

// --- http_tech (webappanalyzer-derived) ---

type HTTPTechRow struct{ Name, Vendor, Product, Source string }

var appCPERe = regexp.MustCompile(`^cpe:2\.3:a:([^:]+):([^:]+):`)

// DeriveHTTPTech reads a webappanalyzer technologies directory (the *.json
// fingerprint files) and derives the technology-name -> CPE vendor:product
// map from each technology's "cpe" field, matching scripts/gen_http_tech.py.
func DeriveHTTPTech(techDir string) ([]HTTPTechRow, error) {
	files, err := filepath.Glob(filepath.Join(techDir, "*.json"))
	if err != nil {
		return nil, err
	}
	type tech struct {
		CPE string `json:"cpe"`
	}
	all := map[string]string{} // name -> cpe
	var names []string
	for _, f := range files {
		var m map[string]tech
		if err := readJSON(f, &m); err != nil {
			return nil, err
		}
		for name, t := range m {
			if t.CPE != "" {
				if _, ok := all[name]; !ok {
					names = append(names, name)
				}
				all[name] = t.CPE
			}
		}
	}
	sort.Strings(names)
	var rows []HTTPTechRow
	seen := map[[3]string]bool{}
	for _, name := range names {
		mm := appCPERe.FindStringSubmatch(all[name])
		if mm == nil {
			continue
		}
		key := [3]string{strings.ToLower(name), mm[1], mm[2]}
		if seen[key] {
			continue
		}
		seen[key] = true
		rows = append(rows, HTTPTechRow{name, mm[1], mm[2], "generated:webappanalyzer"})
	}
	return rows, nil
}

// curatedData returns the bytes for a curated-data source. A path of the form
// "embedded:<name>" resolves to the first-party file compiled into the binary
// (data.Files); any other path is read from disk, so an explicit --flag still
// overrides the embedded default.
func curatedData(path string) ([]byte, error) {
	if name, ok := strings.CutPrefix(path, "embedded:"); ok {
		b, ok := curated.Files[name]
		if !ok {
			return nil, fmt.Errorf("no embedded curated file %q", name)
		}
		return b, nil
	}
	return os.ReadFile(path)
}

func readJSON(path string, v any) error {
	data, err := curatedData(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

// readJSONCaseless unmarshals with case-insensitive field matching (Go's
// default), used where JSON keys are lower-case but struct fields are not
// tagged.
func readJSONCaseless(path string, v any) error { return readJSON(path, v) }
