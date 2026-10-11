package matcher

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"

	"bunyip/internal/database"
)

// Scale roughly comparable to NVD: ~100k CVEs and ~500k match rules, plus
// one heavily referenced product (like linux_kernel) with many rules.
const (
	benchCVEs         = 100_000
	benchRulesPerCVE  = 5
	benchProducts     = 5_000
	benchHotProductCV = 8_000
)

// buildBenchDB generates a synthetic large database. Values are arbitrary;
// only the shape matters.
func buildBenchDB(b *testing.B) string {
	b.Helper()
	ctx := context.Background()
	path := filepath.Join(b.TempDir(), "bench.sqlite")
	s, err := database.Create(ctx, path)
	if err != nil {
		b.Fatal(err)
	}
	score := 7.5
	f := &database.Fixture{Metadata: map[string]string{"dataset": "synthetic-benchmark"}}
	for i := range benchCVEs {
		c := database.FixtureCVE{
			CVEID:       fmt.Sprintf("CVE-0000-%07d", i),
			Description: "[SYNTHETIC] benchmark record",
			CVSSv3Score: &score,
			Severity:    "HIGH",
		}
		var matches []database.FixtureMatch
		for j := range benchRulesPerCVE {
			p := (i*benchRulesPerCVE + j) % benchProducts
			matches = append(matches, database.FixtureMatch{
				Criteria:              fmt.Sprintf("cpe:2.3:a:vendor%d:product%d:*:*:*:*:*:*:*:*", p, p),
				Vulnerable:            true,
				VersionStartIncluding: fmt.Sprintf("%d.0", j),
				VersionEndExcluding:   fmt.Sprintf("%d.%d", j+1, i%50),
			})
		}
		if i < benchHotProductCV {
			matches = append(matches, database.FixtureMatch{
				Criteria:            "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
				Vulnerable:          true,
				VersionEndExcluding: fmt.Sprintf("6.%d.%d", i%12, i%200),
			})
		}
		c.Configurations = []database.FixtureConfig{{Nodes: []database.FixtureNode{{CPEMatch: matches}}}}
		f.CVEs = append(f.CVEs, c)
	}
	if err := s.ImportFixture(ctx, f); err != nil {
		b.Fatal(err)
	}
	s.Close()
	return path
}

func BenchmarkQueryLargeDB(b *testing.B) {
	path := buildBenchDB(b)
	store, err := database.Open(context.Background(), path)
	if err != nil {
		b.Fatal(err)
	}
	defer store.Close()
	e, err := New(context.Background(), store)
	if err != nil {
		b.Fatal(err)
	}

	cases := []struct{ name, cpe string }{
		{"typical_product", "cpe:/a:vendor42:product42:2.5"},
		{"hot_product_8k_rules", "cpe:/o:linux:linux_kernel:6.1.50"},
		{"unknown_product", "cpe:/a:nobody:nothing:1.0"},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			for b.Loop() {
				if _, err := e.QueryCPE(context.Background(), c.cpe, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
