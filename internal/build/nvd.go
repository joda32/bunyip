// Package build reconstructs the vulnerability database from upstream sources
// inside the Go binary (the `vulndb build`/`update` path), replacing the
// separate Python updater. This file ports the NVD CVE JSON 2.0 record
// transform: applicability is kept with its structure (configurations over
// nodes over CPE match rules); criteria strings are stored verbatim and only
// the lookup columns are derived. The Python updater (updater/) remains the
// reference implementation to diff against.
package build

import (
	"bytes"
	"encoding/json"
	"fmt"

	"offline-vulndb/internal/cpe"
	"offline-vulndb/internal/version"
)

const (
	nvdSource     = "nvd@nist.gov"
	exploitSource = "nvd-reference"
)

// Match is one CPE match rule with its derived lookup columns.
type Match struct {
	Criteria       string
	Part           string
	Vendor         string
	Product        string
	Vulnerable     bool
	StartIncluding string
	StartExcluding string
	EndIncluding   string
	EndExcluding   string
	VersionKey     string
}

// Node is an AND/OR group of match rules, optionally negated.
type Node struct {
	Operator string
	Negate   bool
	Matches  []Match
}

// Configuration is an AND/OR group of nodes.
type Configuration struct {
	Operator string
	Nodes    []Node
}

// Exploit is an NVD reference tagged "Exploit" (evidence it was referenced,
// not that it was verified).
type Exploit struct {
	Reference    string
	MetadataJSON string
}

// Record is one transformed CVE.
type Record struct {
	CVEID        string
	PublishedAt  string
	ModifiedAt   string
	Description  string
	CVSSv3Score  *float64
	CVSSv3Vector string
	CVSSv4Score  *float64
	CVSSv4Vector string
	Severity     string
	CWE          string
	Configs      []Configuration
	Exploits     []Exploit
	Rejected     bool
	SkippedRules []string
}

// --- NVD 2.0 feed JSON shapes (only the fields used) ---

type nvdItem struct {
	CVE nvdCVE `json:"cve"`
}

type nvdCVE struct {
	ID             string                 `json:"id"`
	VulnStatus     string                 `json:"vulnStatus"`
	Published      string                 `json:"published"`
	LastModified   string                 `json:"lastModified"`
	Descriptions   []nvdLangValue         `json:"descriptions"`
	Metrics        map[string][]nvdMetric `json:"metrics"`
	Weaknesses     []nvdWeakness          `json:"weaknesses"`
	References     []nvdReference         `json:"references"`
	Configurations []nvdConfig            `json:"configurations"`
}

type nvdLangValue struct {
	Lang  string `json:"lang"`
	Value string `json:"value"`
}

type nvdMetric struct {
	Type         string   `json:"type"`
	Source       string   `json:"source"`
	BaseSeverity string   `json:"baseSeverity"` // CVSS v2 keeps severity here
	CVSSData     *nvdCVSS `json:"cvssData"`
}

type nvdCVSS struct {
	BaseScore    *float64 `json:"baseScore"`
	BaseSeverity string   `json:"baseSeverity"`
	VectorString string   `json:"vectorString"`
}

type nvdWeakness struct {
	Description []nvdLangValue `json:"description"`
}

type nvdReference struct {
	URL    string   `json:"url"`
	Source string   `json:"source"`
	Tags   []string `json:"tags"`
}

type nvdConfig struct {
	Operator string    `json:"operator"`
	Nodes    []nvdNode `json:"nodes"`
}

type nvdNode struct {
	Operator string        `json:"operator"`
	Negate   bool          `json:"negate"`
	CPEMatch []nvdCPEMatch `json:"cpeMatch"`
}

type nvdCPEMatch struct {
	Criteria              string `json:"criteria"`
	Vulnerable            bool   `json:"vulnerable"`
	VersionStartIncluding string `json:"versionStartIncluding"`
	VersionStartExcluding string `json:"versionStartExcluding"`
	VersionEndIncluding   string `json:"versionEndIncluding"`
	VersionEndExcluding   string `json:"versionEndExcluding"`
}

// Transform converts one element of a feed's "vulnerabilities" array. A
// rejected CVE returns Rejected=true with no other data (so the loader can
// drop any earlier copy). Unparseable criteria are reported in SkippedRules
// rather than aborting.
func Transform(raw json.RawMessage) (Record, error) {
	var item nvdItem
	dec := json.NewDecoder(bytes.NewReader(raw))
	if err := dec.Decode(&item); err != nil {
		return Record{}, fmt.Errorf("decoding NVD item: %w", err)
	}
	c := item.CVE
	if c.ID == "" {
		return Record{}, fmt.Errorf("NVD item has no cve.id")
	}
	if c.VulnStatus == "Rejected" {
		return Record{CVEID: c.ID, Rejected: true}, nil
	}

	v3 := pickMetric(c.Metrics, "cvssMetricV31", "cvssMetricV30")
	v4 := pickMetric(c.Metrics, "cvssMetricV40")
	v2 := pickMetric(c.Metrics, "cvssMetricV2")
	rec := Record{
		CVEID:        c.ID,
		PublishedAt:  c.Published,
		ModifiedAt:   c.LastModified,
		Description:  english(c.Descriptions),
		CVSSv3Score:  score(v3),
		CVSSv3Vector: vector(v3),
		CVSSv4Score:  score(v4),
		CVSSv4Vector: vector(v4),
		Severity:     firstNonEmpty(severity(v3), severity(v4), severity(v2)),
		CWE:          cwes(c.Weaknesses),
		Exploits:     exploits(c.References),
	}
	for _, cfg := range c.Configurations {
		conf := Configuration{Operator: operator(cfg.Operator)}
		for _, n := range cfg.Nodes {
			node := Node{Operator: operator(n.Operator), Negate: n.Negate}
			for _, m := range n.CPEMatch {
				crit, err := cpe.ParsePattern(m.Criteria)
				if err != nil {
					rec.SkippedRules = append(rec.SkippedRules, fmt.Sprintf("%s: %q: %v", c.ID, m.Criteria, err))
					continue
				}
				mt := Match{
					Criteria: m.Criteria, Part: crit.Part, Vendor: crit.Vendor, Product: crit.Product,
					Vulnerable:     m.Vulnerable,
					StartIncluding: m.VersionStartIncluding, StartExcluding: m.VersionStartExcluding,
					EndIncluding: m.VersionEndIncluding, EndExcluding: m.VersionEndExcluding,
				}
				if mt.StartIncluding == "" && mt.StartExcluding == "" && mt.EndIncluding == "" && mt.EndExcluding == "" {
					mt.VersionKey = version.Key(cpe.Unescape(crit.Version))
				}
				node.Matches = append(node.Matches, mt)
			}
			conf.Nodes = append(conf.Nodes, node)
		}
		rec.Configs = append(rec.Configs, conf)
	}
	return rec, nil
}

func operator(op string) string {
	if op == "AND" || op == "OR" {
		return op
	}
	return "OR"
}

// pickMetric chooses one CVSS metric: earlier keys win (v3.1 before v3.0),
// and within a key a Primary entry wins, then NVD's own source, then the
// first listed. Entries without cvssData are ignored.
func pickMetric(metrics map[string][]nvdMetric, keys ...string) *nvdMetric {
	for _, key := range keys {
		var best *nvdMetric
		for i := range metrics[key] {
			e := &metrics[key][i]
			if e.CVSSData == nil {
				continue
			}
			if best == nil || metricRank(e) < metricRank(best) {
				best = e
			}
		}
		if best != nil {
			return best
		}
	}
	return nil
}

// metricRank: lower is better. Primary beats non-Primary; NVD source beats
// others. Matches the Python (type!="Primary", source!="nvd@nist.gov") tuple.
func metricRank(m *nvdMetric) int {
	r := 0
	if m.Type != "Primary" {
		r |= 2
	}
	if m.Source != nvdSource {
		r |= 1
	}
	return r
}

func score(m *nvdMetric) *float64 {
	if m == nil || m.CVSSData == nil {
		return nil
	}
	return m.CVSSData.BaseScore
}

func vector(m *nvdMetric) string {
	if m == nil || m.CVSSData == nil {
		return ""
	}
	return m.CVSSData.VectorString
}

func severity(m *nvdMetric) string {
	if m == nil {
		return ""
	}
	if m.CVSSData != nil && m.CVSSData.BaseSeverity != "" {
		return m.CVSSData.BaseSeverity
	}
	return m.BaseSeverity
}

func english(ds []nvdLangValue) string {
	for _, d := range ds {
		if d.Lang == "en" {
			return d.Value
		}
	}
	if len(ds) > 0 {
		return ds[0].Value
	}
	return ""
}

func cwes(ws []nvdWeakness) string {
	var seen []string
	index := map[string]bool{}
	for _, w := range ws {
		for _, d := range w.Description {
			if len(d.Value) > 4 && d.Value[:4] == "CWE-" && !index[d.Value] {
				index[d.Value] = true
				seen = append(seen, d.Value)
			}
		}
	}
	out := ""
	for i, v := range seen {
		if i > 0 {
			out += ","
		}
		out += v
	}
	return out
}

func exploits(refs []nvdReference) []Exploit {
	var out []Exploit
	seen := map[string]bool{}
	for _, r := range refs {
		if r.URL == "" || seen[r.URL] || !contains(r.Tags, "Exploit") {
			continue
		}
		seen[r.URL] = true
		// Match the Python metadata: sorted keys, no HTML escaping.
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		_ = enc.Encode(map[string]any{"reference_source": r.Source, "tags": r.Tags})
		out = append(out, Exploit{Reference: r.URL, MetadataJSON: trimNewline(buf.String())})
	}
	return out
}

func contains(xs []string, s string) bool {
	for _, x := range xs {
		if x == s {
			return true
		}
	}
	return false
}

func firstNonEmpty(xs ...string) string {
	for _, x := range xs {
		if x != "" {
			return x
		}
	}
	return ""
}

func trimNewline(s string) string {
	if len(s) > 0 && s[len(s)-1] == '\n' {
		return s[:len(s)-1]
	}
	return s
}
