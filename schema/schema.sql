-- Offline VulnDB SQLite schema.
--
-- The schema version is recorded in database_metadata('schema_version') and
-- must match database.SchemaVersion in the query engine.

-- Foreign keys are enforced by the connection (PRAGMA foreign_keys = ON).

CREATE TABLE database_metadata (
    key   TEXT PRIMARY KEY,
    value TEXT NOT NULL
);

CREATE TABLE cves (
    id             INTEGER PRIMARY KEY,
    cve_id         TEXT NOT NULL UNIQUE,
    published_at   TEXT,
    modified_at    TEXT,
    description    TEXT NOT NULL DEFAULT '',
    cvss_v3_score  REAL,
    cvss_v3_vector TEXT,
    cvss_v4_score  REAL,
    cvss_v4_vector TEXT,
    severity       TEXT,
    cwe            TEXT
);

-- NVD applicability is a tree: a CVE has one or more configurations; each
-- configuration combines one or more nodes with AND/OR; each node combines
-- CPE match rules with AND/OR and may be negated. The tree is kept so that a
-- rule which only applies "in combination with" another condition (e.g. an
-- application running on a specific OS) is not reported as unconditional.
CREATE TABLE cve_configurations (
    id       INTEGER PRIMARY KEY,
    cve_id   TEXT NOT NULL REFERENCES cves(cve_id),
    operator TEXT NOT NULL DEFAULT 'OR' CHECK (operator IN ('AND', 'OR'))
);

CREATE TABLE cve_config_nodes (
    id               INTEGER PRIMARY KEY,
    configuration_id INTEGER NOT NULL REFERENCES cve_configurations(id),
    operator         TEXT NOT NULL DEFAULT 'OR' CHECK (operator IN ('AND', 'OR')),
    negate           INTEGER NOT NULL DEFAULT 0 CHECK (negate IN (0, 1))
);

-- One CPE match rule. `criteria` is the source CPE 2.3 match string, kept
-- verbatim. criteria_part/vendor/product are derived from it purely to index
-- candidate lookup; the match decision always re-parses `criteria`.
CREATE TABLE cve_matches (
    id                      INTEGER PRIMARY KEY,
    cve_id                  TEXT NOT NULL REFERENCES cves(cve_id),
    node_id                 INTEGER REFERENCES cve_config_nodes(id),
    criteria                TEXT NOT NULL,
    criteria_part           TEXT NOT NULL,
    criteria_vendor         TEXT NOT NULL,
    criteria_product        TEXT NOT NULL,
    vulnerable              INTEGER NOT NULL CHECK (vulnerable IN (0, 1)),
    version_start_including TEXT,
    version_start_excluding TEXT,
    version_end_including   TEXT,
    version_end_excluding   TEXT
);

-- Evidence that a public exploit exists. References only; no exploit code.
CREATE TABLE exploit_evidence (
    id             INTEGER PRIMARY KEY,
    cve_id         TEXT NOT NULL,
    source         TEXT NOT NULL,
    reference      TEXT NOT NULL,
    reference_type TEXT,
    verified       INTEGER NOT NULL DEFAULT 0 CHECK (verified IN (0, 1)),
    metadata_json  TEXT
);

-- CISA Known Exploited Vulnerabilities catalogue.
CREATE TABLE kev (
    cve_id             TEXT PRIMARY KEY,
    vendor_project     TEXT,
    product            TEXT,
    vulnerability_name TEXT,
    date_added         TEXT,
    due_date           TEXT,
    known_ransomware   TEXT,
    notes              TEXT
);

-- Observed (e.g. Nmap) product names mapped to canonical CPE identities.
-- Not used by the milestone 1 exact-CPE query path.
CREATE TABLE aliases (
    id                   INTEGER PRIMARY KEY,
    observed_vendor      TEXT,
    observed_product     TEXT NOT NULL,
    canonical_vendor     TEXT NOT NULL,
    canonical_product    TEXT NOT NULL,
    canonical_cpe_prefix TEXT NOT NULL,
    source               TEXT NOT NULL,
    confidence           TEXT NOT NULL
);

CREATE INDEX idx_cve_matches_lookup  ON cve_matches (criteria_part, criteria_vendor, criteria_product, vulnerable);
CREATE INDEX idx_cve_matches_cve     ON cve_matches (cve_id);
CREATE INDEX idx_cve_matches_node    ON cve_matches (node_id);
CREATE INDEX idx_cve_matches_crit    ON cve_matches (criteria);
CREATE INDEX idx_config_nodes_config ON cve_config_nodes (configuration_id);
CREATE INDEX idx_configurations_cve  ON cve_configurations (cve_id);
CREATE INDEX idx_exploit_cve         ON exploit_evidence (cve_id);
CREATE INDEX idx_aliases_observed    ON aliases (observed_vendor, observed_product);
