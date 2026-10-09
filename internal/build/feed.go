package build

import (
	"bufio"
	"compress/gzip"
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Feed is one NVD JSON 2.0 feed file (a year, or "modified").
type Feed struct {
	Name         string // "2021" ... or "modified"
	GzPath       string // nvdcve-2.0-<name>.json.gz
	LastModified string // from the .meta sidecar, if present
}

// FeedOrder returns yearly feeds in ascending year order, then the modified
// feed as an overlay. Other feed names are ignored (matches the Python
// updater's feed_order).
func FeedOrder(feeds []Feed) []Feed {
	var yearly, modified []Feed
	for _, f := range feeds {
		if f.Name == "modified" {
			modified = append(modified, f)
		} else if isYear(f.Name) {
			yearly = append(yearly, f)
		}
	}
	sort.Slice(yearly, func(i, j int) bool { return yearly[i].Name < yearly[j].Name })
	return append(yearly, modified...)
}

func isYear(s string) bool {
	if len(s) != 4 {
		return false
	}
	for i := 0; i < 4; i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// streamFeed opens a gzipped feed and calls fn for each element of its
// top-level "vulnerabilities" array, as a raw JSON object, keeping memory
// bounded to one record.
func streamFeed(path string, fn func(json.RawMessage) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(bufio.NewReaderSize(f, 1<<20))
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	defer gz.Close()

	dec := json.NewDecoder(bufio.NewReaderSize(gz, 1<<20))
	// Walk tokens to the "vulnerabilities" array.
	for {
		tok, err := dec.Token()
		if err != nil {
			return fmt.Errorf("%s: no vulnerabilities array: %w", path, err)
		}
		if s, ok := tok.(string); ok && s == "vulnerabilities" {
			break
		}
	}
	if tok, err := dec.Token(); err != nil || tok != json.Delim('[') {
		return fmt.Errorf("%s: vulnerabilities is not an array", path)
	}
	for dec.More() {
		var raw json.RawMessage
		if err := dec.Decode(&raw); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		if err := fn(raw); err != nil {
			return err
		}
	}
	return nil
}

// readMeta extracts lastModifiedDate from a .meta sidecar (CRLF key:value
// lines); returns "" when the file is absent or lacks the field.
func ReadMeta(gzPath string) string {
	meta := strings.TrimSuffix(gzPath, ".json.gz") + ".meta"
	data, err := os.ReadFile(meta)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(strings.ReplaceAll(string(data), "\r\n", "\n"), "\n") {
		if k, v, ok := strings.Cut(line, ":"); ok && k == "lastModifiedDate" {
			return strings.TrimSpace(v)
		}
	}
	return ""
}
