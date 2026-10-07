package database

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	"offline-vulndb/internal/cpe"
	"offline-vulndb/internal/version"
)

// Fixture is a small, self-contained dataset in a JSON shape that mirrors the
// NVD configuration tree. It exists so the matching model can be tested
// without the full NVD dataset; the production database will be built by the
// separate Python updater.
type Fixture struct {
	Metadata        map[string]string       `json:"metadata"`
	CVEs            []FixtureCVE            `json:"cves"`
	KEV             []FixtureKEV            `json:"kev"`
	ExploitEvidence []FixtureExploit        `json:"exploit_evidence"`
	Aliases         []FixtureAlias          `json:"aliases"`
	DistroPackages  []FixtureDistroPackage  `json:"distro_packages"`
	DistroVersions  []FixtureDistroVersion  `json:"distro_package_versions"`
	DistroAdvisory  []FixtureDistroAdvisory `json:"distro_advisories"`
	DistroReleases  []FixtureDistroRelease  `json:"distro_releases"`
	WindowsBuilds   []FixtureWindowsBuild   `json:"windows_builds"`
	ProductNames    []FixtureProductName    `json:"product_names"`
}

// FixtureProductName is one product_names row; Match defaults to "exact".
type FixtureProductName struct {
	Pattern    string `json:"pattern"`
	Match      string `json:"match"`
	Kind       string `json:"kind"`
	Vendor     string `json:"vendor"`
	Product    string `json:"product"`
	OS         string `json:"os"`
	Version    string `json:"version"`
	Confidence string `json:"confidence"`
	Note       string `json:"note"`
}

type FixtureWindowsBuild struct {
	Build   int      `json:"build"`
	Kind    string   `json:"kind"`
	Name    string   `json:"name"`
	CPEs    []string `json:"cpes"` // full CPE 2.3 names
	EOL     string   `json:"eol"`
	Support string   `json:"support"`
}

type FixtureDistroRelease struct {
	Distro        string `json:"distro"`
	Release       string `json:"release"`
	EOL           string `json:"eol"`
	ExtendedUntil string `json:"extended_until"`
	Extended      string `json:"extended"`
}

type FixtureDistroPackage struct {
	CPE     string `json:"cpe"` // part:vendor:product
	Distro  string `json:"distro"`
	Package string `json:"package"`
}

type FixtureDistroVersion struct {
	Distro  string `json:"distro"`
	Release string `json:"release"`
	Package string `json:"package"`
	Version string `json:"version"`
}

type FixtureDistroAdvisory struct {
	AdvisoryID        string `json:"advisory_id"`
	CVEID             string `json:"cve_id"`
	Distro            string `json:"distro"`
	Release           string `json:"release"`
	Channel           string `json:"channel"`
	Package           string `json:"package"`
	FixedVersion      string `json:"fixed_version"`
	AffectedUpstreams string `json:"affected_upstreams"`
	Urgency           string `json:"urgency"`
	Stream            string `json:"stream"`
}

type FixtureCVE struct {
	CVEID          string          `json:"cve_id"`
	PublishedAt    string          `json:"published_at"`
	ModifiedAt     string          `json:"modified_at"`
	Description    string          `json:"description"`
	CVSSv3Score    *float64        `json:"cvss_v3_score"`
	CVSSv3Vector   string          `json:"cvss_v3_vector"`
	CVSSv4Score    *float64        `json:"cvss_v4_score"`
	CVSSv4Vector   string          `json:"cvss_v4_vector"`
	Severity       string          `json:"severity"`
	CWE            string          `json:"cwe"`
	Configurations []FixtureConfig `json:"configurations"`
}

type FixtureConfig struct {
	Operator string        `json:"operator"` // "AND" or "OR"; default "OR"
	Nodes    []FixtureNode `json:"nodes"`
}

type FixtureNode struct {
	Operator string         `json:"operator"` // "AND" or "OR"; default "OR"
	Negate   bool           `json:"negate"`
	CPEMatch []FixtureMatch `json:"cpe_match"`
}

type FixtureMatch struct {
	Criteria              string `json:"criteria"`
	Vulnerable            bool   `json:"vulnerable"`
	VersionStartIncluding string `json:"version_start_including"`
	VersionStartExcluding string `json:"version_start_excluding"`
	VersionEndIncluding   string `json:"version_end_including"`
	VersionEndExcluding   string `json:"version_end_excluding"`
}

type FixtureKEV struct {
	CVEID             string `json:"cve_id"`
	VendorProject     string `json:"vendor_project"`
	Product           string `json:"product"`
	VulnerabilityName string `json:"vulnerability_name"`
	DateAdded         string `json:"date_added"`
	DueDate           string `json:"due_date"`
	KnownRansomware   string `json:"known_ransomware"`
	Notes             string `json:"notes"`
}

type FixtureExploit struct {
	CVEID         string          `json:"cve_id"`
	Source        string          `json:"source"`
	Reference     string          `json:"reference"`
	ReferenceType string          `json:"reference_type"`
	Verified      bool            `json:"verified"`
	Metadata      json.RawMessage `json:"metadata"`
}

type FixtureAlias struct {
	ObservedVendor     string `json:"observed_vendor"`
	ObservedProduct    string `json:"observed_product"`
	CanonicalVendor    string `json:"canonical_vendor"`
	CanonicalProduct   string `json:"canonical_product"`
	CanonicalCPEPrefix string `json:"canonical_cpe_prefix"`
	Source             string `json:"source"`
	Confidence         string `json:"confidence"`
}

// LoadFixture reads and strictly decodes a fixture file.
func LoadFixture(path string) (*Fixture, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	var f Fixture
	if err := dec.Decode(&f); err != nil {
		return nil, fmt.Errorf("decoding fixture %s: %w", path, err)
	}
	return &f, nil
}

// ImportFixture loads a fixture into the database in a single transaction.
// Fixture metadata is recorded, but schema_version cannot be overridden.
func (s *Store) ImportFixture(ctx context.Context, f *Fixture) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	for k, v := range f.Metadata {
		if k == "schema_version" {
			return fmt.Errorf("fixture may not set schema_version")
		}
		if err := setMetadata(ctx, tx, k, v); err != nil {
			return err
		}
	}
	for _, c := range f.CVEs {
		if err := insertCVE(ctx, tx, c); err != nil {
			return fmt.Errorf("%s: %w", c.CVEID, err)
		}
	}
	for _, k := range f.KEV {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO kev (cve_id, vendor_project, product, vulnerability_name, date_added, due_date, known_ransomware, notes)
VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			k.CVEID, k.VendorProject, k.Product, k.VulnerabilityName,
			k.DateAdded, k.DueDate, k.KnownRansomware, k.Notes); err != nil {
			return fmt.Errorf("kev %s: %w", k.CVEID, err)
		}
	}
	for _, e := range f.ExploitEvidence {
		var meta any
		if len(e.Metadata) > 0 {
			meta = string(e.Metadata)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO exploit_evidence (cve_id, source, reference, reference_type, verified, metadata_json)
VALUES (?, ?, ?, ?, ?, ?)`,
			e.CVEID, e.Source, e.Reference, e.ReferenceType, e.Verified, meta); err != nil {
			return fmt.Errorf("exploit evidence %s: %w", e.CVEID, err)
		}
	}
	for _, a := range f.Aliases {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO aliases (observed_vendor, observed_product, canonical_vendor, canonical_product, canonical_cpe_prefix, source, confidence)
VALUES (?, ?, ?, ?, ?, ?, ?)`,
			a.ObservedVendor, a.ObservedProduct, a.CanonicalVendor, a.CanonicalProduct,
			a.CanonicalCPEPrefix, a.Source, a.Confidence); err != nil {
			return fmt.Errorf("alias %s: %w", a.ObservedProduct, err)
		}
	}
	if err := importDistro(ctx, tx, f); err != nil {
		return err
	}
	for _, w := range f.WindowsBuilds {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO windows_builds (build, kind, name, cpes, eol, support, source) VALUES (?, ?, ?, ?, ?, ?, 'fixture')`,
			w.Build, w.Kind, w.Name, strings.Join(w.CPEs, " "), w.EOL, w.Support); err != nil {
			return fmt.Errorf("windows build %d: %w", w.Build, err)
		}
	}
	for _, n := range f.ProductNames {
		match, part := n.Match, ""
		if match == "" {
			match = "exact"
		}
		if n.Kind == "product" {
			part = "a"
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO product_names (pattern, match, kind, part, vendor, product, os, version, confidence, note, source)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'fixture')`,
			n.Pattern, match, n.Kind, part, n.Vendor, n.Product, n.OS, n.Version, n.Confidence, n.Note); err != nil {
			return fmt.Errorf("product name %q: %w", n.Pattern, err)
		}
	}
	return tx.Commit()
}

func importDistro(ctx context.Context, tx *sql.Tx, f *Fixture) error {
	for _, r := range f.DistroReleases {
		if _, err := tx.ExecContext(ctx, `
INSERT INTO distro_releases (distro, release, eol, extended_until, extended, source) VALUES (?, ?, ?, ?, ?, 'fixture')`,
			r.Distro, r.Release, r.EOL, nullStr(r.ExtendedUntil), nullStr(r.Extended)); err != nil {
			return err
		}
	}
	for _, p := range f.DistroPackages {
		bits := strings.Split(p.CPE, ":")
		if len(bits) != 3 {
			return fmt.Errorf("distro package cpe %q must be part:vendor:product", p.CPE)
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO distro_packages (cpe_part, cpe_vendor, cpe_product, distro, package, source) VALUES (?, ?, ?, ?, ?, 'fixture')`,
			bits[0], bits[1], bits[2], p.Distro, p.Package); err != nil {
			return err
		}
	}
	for _, v := range f.DistroVersions {
		dv, err := version.ParseDeb(v.Version)
		if err != nil {
			if dv, err = version.ParseRPM(v.Version); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO distro_package_versions (distro, release, package, version, upstream) VALUES (?, ?, ?, ?, ?)`,
			v.Distro, v.Release, v.Package, v.Version, dv.Upstream); err != nil {
			return err
		}
	}
	for _, a := range f.DistroAdvisory {
		channel := a.Channel
		if channel == "" {
			channel = "standard"
		}
		if _, err := tx.ExecContext(ctx, `
INSERT INTO distro_advisories (source, advisory_id, cve_id, distro, release, channel, package, fixed_version,
                               affected_upstreams, urgency, stream)
VALUES ('fixture', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
			a.AdvisoryID, a.CVEID, a.Distro, a.Release, channel, a.Package, nullStr(a.FixedVersion), a.AffectedUpstreams,
			nullStr(a.Urgency), a.Stream); err != nil {
			return err
		}
	}
	return nil
}

func insertCVE(ctx context.Context, tx *sql.Tx, c FixtureCVE) error {
	if c.CVEID == "" {
		return fmt.Errorf("missing cve_id")
	}
	if _, err := tx.ExecContext(ctx, `
INSERT INTO cves (cve_id, published_at, modified_at, description,
                  cvss_v3_score, cvss_v3_vector, cvss_v4_score, cvss_v4_vector, severity, cwe)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		c.CVEID, nullStr(c.PublishedAt), nullStr(c.ModifiedAt), c.Description,
		c.CVSSv3Score, nullStr(c.CVSSv3Vector), c.CVSSv4Score, nullStr(c.CVSSv4Vector),
		nullStr(c.Severity), nullStr(c.CWE)); err != nil {
		return err
	}
	for _, cfg := range c.Configurations {
		res, err := tx.ExecContext(ctx,
			`INSERT INTO cve_configurations (cve_id, operator) VALUES (?, ?)`,
			c.CVEID, operatorOrDefault(cfg.Operator))
		if err != nil {
			return err
		}
		cfgID, _ := res.LastInsertId()
		cfgOp := operatorOrDefault(cfg.Operator)
		for _, node := range cfg.Nodes {
			nodeOp := operatorOrDefault(node.Operator)
			res, err := tx.ExecContext(ctx,
				`INSERT INTO cve_config_nodes (configuration_id, operator, negate) VALUES (?, ?, ?)`,
				cfgID, nodeOp, node.Negate)
			if err != nil {
				return err
			}
			nodeID, _ := res.LastInsertId()
			rc := RuleContext{NodeID: nodeID, NodeOperator: nodeOp, NodeNegate: node.Negate, ConfigOperator: cfgOp,
				AndNodeSiblings:   nodeOp == "AND" && len(node.CPEMatch) > 1,
				AndConfigSiblings: cfgOp == "AND" && len(cfg.Nodes) > 1}
			for _, m := range node.CPEMatch {
				if err := InsertMatchRule(ctx, tx, c.CVEID, rc, m); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

// RuleContext is a rule's place in its NVD configuration, stored on the rule.
// A zero NodeID stores the rule without configuration structure.
type RuleContext struct {
	NodeID                             int64
	NodeOperator, ConfigOperator       string
	NodeNegate                         bool
	AndNodeSiblings, AndConfigSiblings bool
}

// InsertMatchRule validates a criteria string and stores the rule with its
// derived lookup columns and configuration context.
func InsertMatchRule(ctx context.Context, e execer, cveID string, rc RuleContext, m FixtureMatch) error {
	crit, err := cpe.ParsePattern(m.Criteria)
	if err != nil {
		return fmt.Errorf("criteria %q: %w", m.Criteria, err)
	}
	var node any
	if rc.NodeID != 0 {
		node = rc.NodeID
	}
	key := ""
	if m.VersionStartIncluding == "" && m.VersionStartExcluding == "" && m.VersionEndIncluding == "" && m.VersionEndExcluding == "" {
		key = version.Key(cpe.Unescape(crit.Version))
	}
	_, err = e.ExecContext(ctx, `
INSERT INTO cve_matches (cve_id, node_id, criteria, criteria_part, criteria_vendor, criteria_product, vulnerable,
                         version_start_including, version_start_excluding, version_end_including, version_end_excluding,
                         node_operator, node_negate, config_operator, and_node_siblings, and_config_siblings, version_key)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		cveID, node, m.Criteria, crit.Part, crit.Vendor, crit.Product, m.Vulnerable,
		nullStr(m.VersionStartIncluding), nullStr(m.VersionStartExcluding),
		nullStr(m.VersionEndIncluding), nullStr(m.VersionEndExcluding),
		operatorOrDefault(rc.NodeOperator), rc.NodeNegate, operatorOrDefault(rc.ConfigOperator),
		rc.AndNodeSiblings, rc.AndConfigSiblings, key)
	return err
}

func operatorOrDefault(op string) string {
	if op == "" {
		return "OR"
	}
	return op
}

func nullStr(s string) any {
	if s == "" {
		return nil
	}
	return s
}
