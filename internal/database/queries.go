package database

import (
	"context"
	"database/sql"
	"strings"

	"offline-vulndb/internal/version"
)

// MatchRule is one vulnerable CPE match rule together with the structure of
// the NVD configuration it belongs to.
type MatchRule struct {
	ID         int64
	CVEID      string
	Criteria   string
	Vulnerable bool
	Range      version.Range

	// Configuration context. HasNode is false for rules imported without
	// configuration structure, which are treated as standalone.
	HasNode        bool
	NodeOperator   string // "AND" or "OR"
	NodeNegate     bool
	ConfigOperator string // "AND" or "OR"
	// AndNodeSiblings: the rule's node is AND and contains other rules.
	// AndConfigSiblings: the configuration is AND and contains other nodes.
	// Only existence matters to the matcher, so these are EXISTS checks
	// rather than counts (counting is quadratic on huge nodes such as
	// linux_kernel's).
	AndNodeSiblings   bool
	AndConfigSiblings bool
}

// CandidateRules returns vulnerable match rules whose criteria share the
// given part, vendor and product (canonical CPE values). This is only an
// indexed pre-filter; callers must still evaluate each rule in full.
func (s *Store) CandidateRules(ctx context.Context, part, vendor, product string) ([]MatchRule, error) {
	const q = `
SELECT m.id, m.cve_id, m.criteria, m.vulnerable,
       COALESCE(m.version_start_including, ''), COALESCE(m.version_start_excluding, ''),
       COALESCE(m.version_end_including, ''),   COALESCE(m.version_end_excluding, ''),
       n.id IS NOT NULL,
       COALESCE(n.operator, 'OR'), COALESCE(n.negate, 0), COALESCE(c.operator, 'OR'),
       COALESCE(n.operator = 'AND' AND EXISTS
           (SELECT 1 FROM cve_matches m2 WHERE m2.node_id = n.id AND m2.id <> m.id), 0),
       COALESCE(c.operator = 'AND' AND EXISTS
           (SELECT 1 FROM cve_config_nodes n2 WHERE n2.configuration_id = c.id AND n2.id <> n.id), 0)
FROM cve_matches m
LEFT JOIN cve_config_nodes   n ON n.id = m.node_id
LEFT JOIN cve_configurations c ON c.id = n.configuration_id
WHERE m.criteria_part = ? AND m.criteria_vendor = ? AND m.criteria_product = ?
  AND m.vulnerable = 1
ORDER BY m.cve_id, m.id`
	rows, err := s.db.QueryContext(ctx, q, part, vendor, product)
	if err != nil {
		return nil, wrapQueryErr(err)
	}
	defer rows.Close()
	var out []MatchRule
	for rows.Next() {
		var r MatchRule
		if err := rows.Scan(&r.ID, &r.CVEID, &r.Criteria, &r.Vulnerable,
			&r.Range.StartIncluding, &r.Range.StartExcluding,
			&r.Range.EndIncluding, &r.Range.EndExcluding,
			&r.HasNode, &r.NodeOperator, &r.NodeNegate, &r.ConfigOperator,
			&r.AndNodeSiblings, &r.AndConfigSiblings); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, wrapQueryErr(rows.Err())
}

// CVE is the descriptive record for one vulnerability.
type CVE struct {
	CVEID        string
	PublishedAt  string
	ModifiedAt   string
	Description  string
	CVSSv3Score  sql.NullFloat64
	CVSSv3Vector string
	CVSSv4Score  sql.NullFloat64
	CVSSv4Vector string
	Severity     string
	CWE          string
}

// KEVEntry is a CISA Known Exploited Vulnerabilities record.
type KEVEntry struct {
	CVEID             string
	VendorProject     string
	Product           string
	VulnerabilityName string
	DateAdded         string
	DueDate           string
	KnownRansomware   string
	Notes             string
}

// ExploitEvidence is a reference indicating a public exploit exists.
type ExploitEvidence struct {
	CVEID         string
	Source        string
	Reference     string
	ReferenceType string
	Verified      bool
}

// CVEs loads CVE records keyed by CVE ID.
func (s *Store) CVEs(ctx context.Context, ids []string) (map[string]CVE, error) {
	out := map[string]CVE{}
	err := forChunks(ids, func(chunk []string) error {
		q := `SELECT cve_id, COALESCE(published_at, ''), COALESCE(modified_at, ''), description,
		             cvss_v3_score, COALESCE(cvss_v3_vector, ''), cvss_v4_score, COALESCE(cvss_v4_vector, ''),
		             COALESCE(severity, ''), COALESCE(cwe, '')
		      FROM cves WHERE cve_id IN (` + placeholders(len(chunk)) + `)`
		return s.each(ctx, q, chunk, func(rows *sql.Rows) error {
			var c CVE
			if err := rows.Scan(&c.CVEID, &c.PublishedAt, &c.ModifiedAt, &c.Description,
				&c.CVSSv3Score, &c.CVSSv3Vector, &c.CVSSv4Score, &c.CVSSv4Vector,
				&c.Severity, &c.CWE); err != nil {
				return err
			}
			out[c.CVEID] = c
			return nil
		})
	})
	return out, err
}

// KEV loads KEV entries keyed by CVE ID.
func (s *Store) KEV(ctx context.Context, ids []string) (map[string]KEVEntry, error) {
	out := map[string]KEVEntry{}
	err := forChunks(ids, func(chunk []string) error {
		q := `SELECT cve_id, COALESCE(vendor_project, ''), COALESCE(product, ''),
		             COALESCE(vulnerability_name, ''), COALESCE(date_added, ''), COALESCE(due_date, ''),
		             COALESCE(known_ransomware, ''), COALESCE(notes, '')
		      FROM kev WHERE cve_id IN (` + placeholders(len(chunk)) + `)`
		return s.each(ctx, q, chunk, func(rows *sql.Rows) error {
			var k KEVEntry
			if err := rows.Scan(&k.CVEID, &k.VendorProject, &k.Product, &k.VulnerabilityName,
				&k.DateAdded, &k.DueDate, &k.KnownRansomware, &k.Notes); err != nil {
				return err
			}
			out[k.CVEID] = k
			return nil
		})
	})
	return out, err
}

// Exploits loads exploit evidence grouped by CVE ID.
func (s *Store) Exploits(ctx context.Context, ids []string) (map[string][]ExploitEvidence, error) {
	out := map[string][]ExploitEvidence{}
	err := forChunks(ids, func(chunk []string) error {
		q := `SELECT cve_id, source, reference, COALESCE(reference_type, ''), verified
		      FROM exploit_evidence WHERE cve_id IN (` + placeholders(len(chunk)) + `)
		      ORDER BY cve_id, source, reference`
		return s.each(ctx, q, chunk, func(rows *sql.Rows) error {
			var e ExploitEvidence
			if err := rows.Scan(&e.CVEID, &e.Source, &e.Reference, &e.ReferenceType, &e.Verified); err != nil {
				return err
			}
			out[e.CVEID] = append(out[e.CVEID], e)
			return nil
		})
	})
	return out, err
}

// each runs a parameterised query and calls fn for every row.
func (s *Store) each(ctx context.Context, q string, args []string, fn func(*sql.Rows) error) error {
	anyArgs := make([]any, len(args))
	for i, a := range args {
		anyArgs[i] = a
	}
	rows, err := s.db.QueryContext(ctx, q, anyArgs...)
	if err != nil {
		return wrapQueryErr(err)
	}
	defer rows.Close()
	for rows.Next() {
		if err := fn(rows); err != nil {
			return err
		}
	}
	return wrapQueryErr(rows.Err())
}

// chunkSize keeps IN lists well below SQLite's bound-parameter limit.
const chunkSize = 500

func forChunks(ids []string, fn func([]string) error) error {
	for len(ids) > 0 {
		n := min(chunkSize, len(ids))
		if err := fn(ids[:n]); err != nil {
			return err
		}
		ids = ids[n:]
	}
	return nil
}

func placeholders(n int) string {
	return strings.TrimSuffix(strings.Repeat("?,", n), ",")
}
