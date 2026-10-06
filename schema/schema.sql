-- Offline VulnDB SQLite schema.
--
-- The schema version is set at the end of this file, so every database
-- builder (the Go CLI and the Python updater) gets it from one place. It must
-- match database.SchemaVersion in the query engine.

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

-- Distribution security advisories (from OSV ecosystem exports, e.g. Ubuntu).
-- One row per CVE x release x channel x source package, as published by the
-- distribution. A missing row means "no data" (not "not affected").
CREATE TABLE distro_advisories (
    id                 INTEGER PRIMARY KEY,
    source             TEXT NOT NULL,     -- e.g. 'osv:Ubuntu'
    advisory_id        TEXT NOT NULL,     -- e.g. 'UBUNTU-CVE-2024-6387'
    cve_id             TEXT NOT NULL,
    distro             TEXT NOT NULL,     -- e.g. 'ubuntu'
    release            TEXT NOT NULL,     -- e.g. '24.04'
    channel            TEXT NOT NULL DEFAULT 'standard' CHECK (channel IN ('standard', 'pro')),
    codename           TEXT,              -- e.g. 'noble'
    package            TEXT NOT NULL,     -- source package name
    fixed_version      TEXT,              -- NULL: affected, no fix released in this channel
    affected_upstreams TEXT NOT NULL DEFAULT '', -- space-separated upstream versions listed as affected
    urgency            TEXT,              -- distribution's own rating, e.g. Debian 'unimportant'
    modified_at        TEXT
);

-- Package versions known per release, for inferring a host's release from
-- what a scanner observed (e.g. OpenSSH 9.6p1-3ubuntu13.x -> Ubuntu 24.04).
CREATE TABLE distro_package_versions (
    distro   TEXT NOT NULL,
    release  TEXT NOT NULL,
    package  TEXT NOT NULL,
    version  TEXT NOT NULL,  -- full Debian version, e.g. '1:9.6p1-3ubuntu13.3'
    upstream TEXT NOT NULL,  -- e.g. '9.6p1'
    PRIMARY KEY (distro, package, release, version)
) WITHOUT ROWID;

-- Curated map from CPE identities to distribution source packages
-- (data/distro_packages.json), e.g. openbsd:openssh -> ubuntu/openssh.
CREATE TABLE distro_packages (
    id          INTEGER PRIMARY KEY,
    cpe_part    TEXT NOT NULL,
    cpe_vendor  TEXT NOT NULL,
    cpe_product TEXT NOT NULL,
    distro      TEXT NOT NULL,
    package     TEXT NOT NULL,
    source      TEXT NOT NULL
);

CREATE INDEX idx_distro_adv_lookup   ON distro_advisories (distro, package, release, cve_id);
CREATE INDEX idx_distro_adv_cve      ON distro_advisories (cve_id);
CREATE INDEX idx_distro_pkgver_up    ON distro_package_versions (distro, package, upstream);
CREATE INDEX idx_distro_packages_cpe ON distro_packages (cpe_part, cpe_vendor, cpe_product);

INSERT INTO database_metadata (key, value) VALUES ('schema_version', '3');
