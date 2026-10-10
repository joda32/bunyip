package build

import (
	"bufio"
	"compress/gzip"
	"context"
	"database/sql"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
)

// FIRST EPSS (Exploit Prediction Scoring System) snapshot loading. The daily
// file is a gzipped CSV: a leading comment line carries the model version and
// score date, then a `cve,epss,percentile` header, then one row per CVE.
//
//	#model_version:v2025.03.14,score_date:2026-10-10T00:00:00+0000
//	cve,epss,percentile
//	CVE-1999-0001,0.01234,0.54321

// EPSSRow is one CVE's EPSS score and percentile rank (both 0..1).
type EPSSRow struct {
	CVEID      string
	Score      float64
	Percentile float64
}

// EPSSData is a parsed EPSS snapshot.
type EPSSData struct {
	ModelVersion string
	ScoreDate    string
	Rows         []EPSSRow
}

// LoadEPSS parses an EPSS CSV snapshot (gzipped when the path ends in .gz).
func LoadEPSS(path string) (EPSSData, error) {
	f, err := os.Open(path)
	if err != nil {
		return EPSSData{}, err
	}
	defer f.Close()
	var r io.Reader = f
	if strings.HasSuffix(path, ".gz") {
		gz, err := gzip.NewReader(f)
		if err != nil {
			return EPSSData{}, fmt.Errorf("%s: %w", path, err)
		}
		defer gz.Close()
		r = gz
	}
	return parseEPSS(r, path)
}

func parseEPSS(r io.Reader, path string) (EPSSData, error) {
	var data EPSSData
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	seenHeader := false
	seen := map[string]bool{}
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "#") {
			data.ModelVersion, data.ScoreDate = parseEPSSComment(line)
			continue
		}
		if !seenHeader { // the "cve,epss,percentile" header line
			seenHeader = true
			if strings.HasPrefix(strings.ToLower(line), "cve,") {
				continue
			}
			// No header present: fall through and treat this as a data row.
		}
		fields := strings.Split(line, ",")
		if len(fields) < 3 {
			continue
		}
		cve := strings.ToUpper(strings.TrimSpace(fields[0]))
		if !strings.HasPrefix(cve, "CVE-") || seen[cve] {
			continue
		}
		score, err1 := strconv.ParseFloat(strings.TrimSpace(fields[1]), 64)
		pct, err2 := strconv.ParseFloat(strings.TrimSpace(fields[2]), 64)
		if err1 != nil || err2 != nil {
			continue
		}
		seen[cve] = true
		data.Rows = append(data.Rows, EPSSRow{CVEID: cve, Score: score, Percentile: pct})
	}
	if err := sc.Err(); err != nil {
		return EPSSData{}, fmt.Errorf("%s: %w", path, err)
	}
	if len(data.Rows) == 0 {
		return EPSSData{}, fmt.Errorf("%s: no EPSS rows parsed", path)
	}
	return data, nil
}

// parseEPSSComment extracts model_version and score_date from the leading
// "#key:value,key:value" comment. A value may itself contain colons (the date),
// so each field is split on its first colon only.
func parseEPSSComment(line string) (model, date string) {
	for _, field := range strings.Split(strings.TrimPrefix(line, "#"), ",") {
		k, v, ok := strings.Cut(field, ":")
		if !ok {
			continue
		}
		switch strings.TrimSpace(k) {
		case "model_version":
			model = strings.TrimSpace(v)
		case "score_date":
			date = strings.TrimSpace(v)
		}
	}
	return model, date
}

// insertEPSS loads the EPSS snapshot in one transaction.
func insertEPSS(ctx context.Context, db *sql.DB, rows []EPSSRow) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	for _, r := range rows {
		if _, err := tx.ExecContext(ctx,
			"INSERT OR REPLACE INTO epss (cve_id, score, percentile) VALUES (?, ?, ?)",
			r.CVEID, r.Score, r.Percentile); err != nil {
			tx.Rollback()
			return err
		}
	}
	return tx.Commit()
}
