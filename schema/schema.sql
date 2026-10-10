-- Bunyip SQLite schema.
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
--
-- The rule's configuration context is copied onto it when the database is
-- built (the tree above remains the source of truth), so a lookup is a
-- single indexed scan: popular products have >100k rules.
--   and_node_siblings:   the rule's node is AND and has other rules
--   and_config_siblings: the rule's configuration is AND and has other nodes
--   version_key:         for rules matching one exact version (no range
--                        bounds), that version's major.minor key
--                        (version.Key); '' for every other rule. A query only
--                        reads rules whose key is '' or the observed one.
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
    version_end_excluding   TEXT,
    node_operator           TEXT NOT NULL DEFAULT 'OR' CHECK (node_operator IN ('AND', 'OR')),
    node_negate             INTEGER NOT NULL DEFAULT 0 CHECK (node_negate IN (0, 1)),
    config_operator         TEXT NOT NULL DEFAULT 'OR' CHECK (config_operator IN ('AND', 'OR')),
    and_node_siblings       INTEGER NOT NULL DEFAULT 0 CHECK (and_node_siblings IN (0, 1)),
    and_config_siblings     INTEGER NOT NULL DEFAULT 0 CHECK (and_config_siblings IN (0, 1)),
    version_key             TEXT NOT NULL DEFAULT ''
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

-- FIRST EPSS (Exploit Prediction Scoring System): the probability a CVE will be
-- exploited in the wild within 30 days, and its percentile rank. One snapshot,
-- taken when the database is built; absent CVEs simply have no EPSS.
CREATE TABLE epss (
    cve_id     TEXT PRIMARY KEY,
    score      REAL NOT NULL,
    percentile REAL NOT NULL
) WITHOUT ROWID;

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

-- Only indexes the query engine uses ship in the database. Builders that
-- need more (e.g. the updater's overlay deletes by cve_id) create them and
-- drop them again before the database is finished.
CREATE INDEX idx_cve_matches_lookup  ON cve_matches (criteria_part, criteria_vendor, criteria_product, vulnerable, version_key);
-- Sibling nodes of an AND configuration ("X running on platform Y"), for
-- evaluating the platform condition when the host's OS is known.
CREATE INDEX idx_config_nodes_config ON cve_config_nodes (configuration_id);
CREATE INDEX idx_cve_matches_and_node ON cve_matches (node_id) WHERE and_config_siblings = 1;
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
    stream             TEXT NOT NULL DEFAULT '', -- module stream (RHEL AppStream, e.g. '1.20'); '' if none
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

-- Curated release lifecycle (data/distro_releases.json): a release past its
-- end of life gets no security fixes (or only paid extended ones), and
-- distributions stop publishing advisory data for it.
CREATE TABLE distro_releases (
    distro         TEXT NOT NULL,
    release        TEXT NOT NULL,
    codename       TEXT,
    eol            TEXT NOT NULL,  -- end of regular security support (YYYY-MM-DD)
    extended_until TEXT,           -- end of extended support, if known
    extended       TEXT,           -- extended support offering, e.g. 'Ubuntu Pro (ESM)'
    source         TEXT NOT NULL,
    PRIMARY KEY (distro, release)
) WITHOUT ROWID;

-- Curated Windows build map (data/windows_builds.json): the build number an
-- unauthenticated scan can see (e.g. rdp-ntlm-info Product_Version
-- 10.0.20348) -> the release and the NVD CPE identities that describe it.
CREATE TABLE windows_builds (
    build   INTEGER NOT NULL,
    kind    TEXT NOT NULL CHECK (kind IN ('server', 'client')),
    name    TEXT NOT NULL,          -- e.g. 'Windows Server 2022'
    cpes    TEXT NOT NULL,          -- space-separated CPE 2.3 names (version = release, not build)
    eol     TEXT NOT NULL,          -- end of support for every edition (YYYY-MM-DD)
    support TEXT NOT NULL,          -- edition-specific support summary
    source  TEXT NOT NULL,
    PRIMARY KEY (build, kind)
) WITHOUT ROWID;

-- Curated Nmap product names (data/product_names.json) for services Nmap
-- fingerprints without an application CPE. kind 'product' maps the name to
-- an NVD vendor:product; kind 'os_component' marks operating-system
-- built-ins (e.g. "Microsoft Windows RPC") whose vulnerabilities NVD records
-- against the OS itself.
CREATE TABLE product_names (
    pattern    TEXT NOT NULL,         -- Nmap product string, or a regular expression
    match      TEXT NOT NULL CHECK (match IN ('exact', 'regex')),
    kind       TEXT NOT NULL CHECK (kind IN ('product', 'os_component')),
    part       TEXT NOT NULL DEFAULT '',   -- product: CPE part/vendor/product (canonical)
    vendor     TEXT NOT NULL DEFAULT '',
    product    TEXT NOT NULL DEFAULT '',
    os         TEXT NOT NULL DEFAULT '',   -- os_component: e.g. 'windows'
    version    TEXT NOT NULL CHECK (version IN ('nmap', 'none')), -- is Nmap's version field the product version?
    confidence TEXT NOT NULL CHECK (confidence IN ('HIGH', 'MEDIUM')),
    note       TEXT NOT NULL DEFAULT '',
    source     TEXT NOT NULL,
    PRIMARY KEY (pattern, kind, vendor, product)
) WITHOUT ROWID;

-- Curated HTTP application fingerprints (data/http_apps.json). Web apps sit
-- behind a generic web server (nginx/Apache), so Nmap's service product does
-- not name them; their identity is in HTTP evidence -- the Server header, a
-- <meta generator> tag, a telltale response header, or the page title. Each
-- row maps a regex over one evidence source to an NVD vendor:product, with an
-- optional capture group for the version.
CREATE TABLE http_apps (
    evidence      TEXT NOT NULL CHECK (evidence IN ('server', 'generator', 'header', 'title', 'x_powered_by')),
    header        TEXT NOT NULL DEFAULT '',  -- for evidence='header': the header name, lower-case
    pattern       TEXT NOT NULL,             -- RE2 regex, anchored by the author
    vendor        TEXT NOT NULL,
    product       TEXT NOT NULL,
    version_group INTEGER NOT NULL DEFAULT 0,-- regex submatch holding the version; 0 = no version
    confidence    TEXT NOT NULL CHECK (confidence IN ('HIGH', 'MEDIUM')),
    note          TEXT NOT NULL DEFAULT '',
    source        TEXT NOT NULL,
    PRIMARY KEY (evidence, header, pattern, vendor, product)
) WITHOUT ROWID;

-- Web technology name -> NVD CPE vendor:product, for the `bunyip ingest`
-- adapter that consumes a web fingerprinter's output (httpx -td, webanalyze,
-- WhatWeb). Generated from the webappanalyzer corpus (data/http_tech.json);
-- a lead, not an authoritative identity, so ingested matches are reported at
-- reduced confidence.
CREATE TABLE http_tech (
    name    TEXT NOT NULL,   -- technology name as fingerprinters report it (lookup is case-insensitive)
    vendor  TEXT NOT NULL,   -- canonical CPE vendor
    product TEXT NOT NULL,   -- canonical CPE product
    source  TEXT NOT NULL,
    PRIMARY KEY (name, vendor, product)
) WITHOUT ROWID;

CREATE INDEX idx_distro_adv_lookup   ON distro_advisories (distro, package, release, cve_id);
CREATE INDEX idx_distro_adv_cve      ON distro_advisories (cve_id);
CREATE INDEX idx_distro_pkgver_up    ON distro_package_versions (distro, package, upstream);
CREATE INDEX idx_distro_packages_cpe ON distro_packages (cpe_part, cpe_vendor, cpe_product);

INSERT INTO database_metadata (key, value) VALUES ('schema_version', '13');
