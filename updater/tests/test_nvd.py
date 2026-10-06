from conftest import record
from vulndb_update import nvd


def rules(rec):
    return [m for c in rec.configurations for n in c.nodes for m in n.matches]


def test_exact_version_record():
    r = nvd.transform(record("CVE-2021-41773"))
    assert not r.rejected
    assert r.description.startswith("A flaw was found in a change made to path normalization")
    # NVD's Primary v3.1 score (9.8) wins over the CISA ADP Secondary score (7.5).
    assert (r.cvss_v3_score, r.severity) == (9.8, "CRITICAL")
    assert r.cvss_v3_vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert r.cwe == "CWE-22"
    apache = [m for m in rules(r) if m.product == "http_server"]
    assert len(apache) == 1
    m = apache[0]
    assert m.criteria == "cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*"  # verbatim
    assert (m.part, m.vendor, m.vulnerable) == ("a", "apache", True)
    assert m.end_excluding is None and m.start_including is None


def test_exploit_tagged_references_are_unverified_evidence():
    r = nvd.transform(record("CVE-2021-41773"))
    assert len(r.exploits) == 6
    assert all("Exploit" in e.metadata_json for e in r.exploits)
    assert len({e.reference for e in r.exploits}) == len(r.exploits)


def test_range_and_update_split_record():
    r = nvd.transform(record("CVE-2023-38408"))
    ssh = {(m.criteria, m.end_excluding) for m in rules(r) if m.product == "openssh"}
    assert ssh == {
        ("cpe:2.3:a:openbsd:openssh:*:*:*:*:*:*:*:*", "9.3"),
        ("cpe:2.3:a:openbsd:openssh:9.3:-:*:*:*:*:*:*", None),
        ("cpe:2.3:a:openbsd:openssh:9.3:p1:*:*:*:*:*:*", None),
    }


def test_and_configuration_structure_preserved():
    r = nvd.transform(record("CVE-2016-1019"))
    and_cfgs = [c for c in r.configurations if c.operator == "AND"]
    assert and_cfgs, "expected AND configurations"
    for c in and_cfgs:
        assert len(c.nodes) == 2
        app, platform = c.nodes
        assert all(m.vulnerable for m in app.matches)
        assert not any(m.vulnerable for m in platform.matches)
        assert all(m.part == "o" for m in platform.matches)


def test_rejected():
    r = nvd.transform(record("CVE-1999-1598"))
    assert r.rejected and r.configurations == []


def test_unenriched_record_keeps_cna_score():
    r = nvd.transform(record("CVE-2024-34393"))
    assert r.configurations == []
    assert (r.cvss_v3_score, r.severity) == (8.1, "HIGH")  # CNA Secondary score is all there is


def test_metric_selection():
    def entry(score, type_=None, source="cna@example", sev="HIGH"):
        e = {"source": source, "cvssData": {"baseScore": score, "baseSeverity": sev, "vectorString": f"v{score}"}}
        if type_:
            e["type"] = type_
        return e
    item = record("CVE-2024-34393")
    item["cve"]["metrics"] = {
        "ssvcV203": [{"source": "x", "content": {}}],                    # no cvssData: ignored
        "cvssMetricV30": [entry(9.0, "Primary", "nvd@nist.gov")],         # v3.1 preferred over v3.0
        "cvssMetricV31": [entry(5.0), entry(6.0, "Secondary", "nvd@nist.gov"), entry(7.0, "Primary", "x")],
        "cvssMetricV40": [entry(8.7, "Secondary", sev="CRITICAL")],
    }
    r = nvd.transform(item)
    assert r.cvss_v3_score == 7.0 and r.cvss_v3_vector == "v7.0"
    assert r.cvss_v4_score == 8.7
    assert r.severity == "HIGH"  # from v3


def test_v2_only_severity():
    item = record("CVE-2024-34393")
    item["cve"]["metrics"] = {"cvssMetricV2": [{"source": "nvd@nist.gov", "type": "Primary",
                                                "baseSeverity": "MEDIUM", "cvssData": {"baseScore": 5.0}}]}
    r = nvd.transform(item)
    assert r.cvss_v3_score is None and r.cvss_v4_score is None and r.severity == "MEDIUM"


def test_unparseable_criteria_skipped_not_fatal():
    item = record("CVE-2021-44790")
    node = item["cve"]["configurations"][0]["nodes"][0]
    node["cpeMatch"].append({"vulnerable": True, "criteria": "cpe:2.3:a:broken"})
    r = nvd.transform(item)
    assert len(r.skipped_rules) == 1 and "cpe:2.3:a:broken" in r.skipped_rules[0]
    assert any(m.product == "http_server" for m in rules(r))


def test_missing_operator_defaults_to_or():
    r = nvd.transform(record("CVE-2021-44790"))
    assert {c.operator for c in r.configurations} == {"OR"}
