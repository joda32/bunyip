package build

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

const epssSample = `#model_version:v2025.03.14,score_date:2026-10-10T00:00:00+0000
cve,epss,percentile
CVE-2021-41773,0.94321,0.99012
CVE-2024-6387,0.12345,0.80000
not-a-cve,0.5,0.5
CVE-2021-41773,0.1,0.1
`

func TestParseEPSS(t *testing.T) {
	d, err := parseEPSS(bytes.NewReader([]byte(epssSample)), "sample")
	if err != nil {
		t.Fatal(err)
	}
	if d.ModelVersion != "v2025.03.14" {
		t.Errorf("model = %q", d.ModelVersion)
	}
	if d.ScoreDate != "2026-10-10T00:00:00+0000" { // the colons in the time must survive
		t.Errorf("score_date = %q", d.ScoreDate)
	}
	if len(d.Rows) != 2 { // non-CVE skipped, duplicate skipped
		t.Fatalf("rows = %d (%+v)", len(d.Rows), d.Rows)
	}
	if d.Rows[0].CVEID != "CVE-2021-41773" || d.Rows[0].Score != 0.94321 || d.Rows[0].Percentile != 0.99012 {
		t.Errorf("row0 = %+v", d.Rows[0])
	}
}

func TestLoadEPSSGzip(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "epss_scores-current.csv.gz")
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	w.Write([]byte(epssSample))
	w.Close()
	if err := os.WriteFile(p, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	d, err := LoadEPSS(p)
	if err != nil || len(d.Rows) != 2 {
		t.Fatalf("load gz: %v rows=%d", err, len(d.Rows))
	}
}

func TestLoadEPSSEmptyIsError(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "empty.csv")
	os.WriteFile(p, []byte("#model_version:v1,score_date:x\ncve,epss,percentile\n"), 0o644)
	if _, err := LoadEPSS(p); err == nil {
		t.Error("expected error for no data rows")
	}
}
