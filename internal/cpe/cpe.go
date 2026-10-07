// Package cpe parses and normalises Common Platform Enumeration names.
//
// Two input bindings are accepted:
//
//   - CPE 2.3 formatted strings: cpe:2.3:a:apache:http_server:2.4.49:*:*:*:*:*:*:*
//   - CPE 2.2 URIs (as emitted by Nmap): cpe:/a:apache:http_server:2.4.49
//
// Both are normalised into a CPE value whose attributes are held in canonical
// CPE 2.3 formatted-string form: lower case, with every character other than
// [a-z0-9._-] backslash-escaped. Two names that refer to the same thing
// therefore compare equal attribute-by-attribute regardless of input binding.
//
// All CPE parsing for the project lives in this package.
package cpe

import (
	"errors"
	"fmt"
	"strings"
)

// Special logical attribute values.
const (
	Any = "*" // ANY: the attribute is unspecified / matches anything.
	NA  = "-" // NA: the attribute is "not applicable".
)

// CPE is a parsed, normalised CPE name.
//
// Every attribute holds a canonical CPE 2.3 formatted-string value (see the
// package documentation). Use Unescape to obtain the logical value, e.g. for
// version comparison.
type CPE struct {
	Part      string // "a" (application), "o" (operating system) or "h" (hardware)
	Vendor    string
	Product   string
	Version   string
	Update    string
	Edition   string
	Language  string
	SWEdition string
	TargetSW  string
	TargetHW  string
	Other     string
}

// ErrMalformed is wrapped by every parse error.
var ErrMalformed = errors.New("malformed CPE")

func malformed(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrMalformed, fmt.Sprintf(format, args...))
}

const (
	prefix23 = "cpe:2.3:"
	prefix22 = "cpe:/"
)

// attributeNames lists attributes in CPE 2.3 formatted-string order.
var attributeNames = [...]string{
	"part", "vendor", "product", "version", "update", "edition",
	"language", "sw_edition", "target_sw", "target_hw", "other",
}

// Parse parses a CPE name supplied as a query input (for example from Nmap).
//
// Wildcards embedded inside a value (e.g. "2.4.*") are rejected: a supplied
// name must describe something concrete. Whole-value ANY ("*") and NA ("-")
// are permitted.
func Parse(s string) (CPE, error) {
	return parse(s, false)
}

// ParsePattern parses a CPE match criteria string (for example from NVD
// configuration data). Unlike Parse it permits unescaped '*' and '?'
// wildcards inside values.
func ParsePattern(s string) (CPE, error) {
	return parse(s, true)
}

func parse(s string, allowWildcards bool) (CPE, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return CPE{}, malformed("empty input")
	}
	lower := strings.ToLower(s)
	switch {
	case strings.HasPrefix(lower, prefix23):
		return parse23(s[len(prefix23):], allowWildcards)
	case strings.HasPrefix(lower, prefix22):
		return parse22(s[len(prefix22):])
	default:
		return CPE{}, malformed("%q must start with %q (CPE 2.3) or %q (CPE 2.2)", s, prefix23, prefix22)
	}
}

// parse23 parses the body of a CPE 2.3 formatted string (after "cpe:2.3:").
func parse23(body string, allowWildcards bool) (CPE, error) {
	fields, err := splitEscaped(body)
	if err != nil {
		return CPE{}, err
	}
	if len(fields) != len(attributeNames) {
		return CPE{}, malformed("CPE 2.3 formatted string needs %d attributes after %q, got %d",
			len(attributeNames), prefix23, len(fields))
	}
	for i, f := range fields {
		v, err := canonicalFS(f, allowWildcards)
		if err != nil {
			return CPE{}, malformed("attribute %s: %v", attributeNames[i], err)
		}
		fields[i] = v
	}
	return fromFields(fields)
}

// splitEscaped splits on ':' characters that are not backslash-escaped.
func splitEscaped(s string) ([]string, error) {
	var fields []string
	var cur strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case '\\':
			if i+1 >= len(s) {
				return nil, malformed("trailing backslash")
			}
			cur.WriteByte(c)
			cur.WriteByte(s[i+1])
			i++
		case ':':
			fields = append(fields, cur.String())
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	return append(fields, cur.String()), nil
}

// canonicalFS canonicalises one CPE 2.3 formatted-string attribute value.
func canonicalFS(v string, allowWildcards bool) (string, error) {
	if v == "" {
		return "", errors.New("empty value (use * for ANY)")
	}
	if v == Any || v == NA {
		return v, nil
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case c == '\\':
			// splitEscaped guarantees a following character.
			i++
			writeLiteral(&b, v[i])
		case c == '*' || c == '?':
			if !allowWildcards {
				return "", fmt.Errorf("wildcard %q inside value %q is not allowed in a supplied CPE", c, v)
			}
			b.WriteByte(c)
		case isPlain(c):
			b.WriteByte(toLower(c))
		default:
			return "", fmt.Errorf("character %q in value %q must be escaped", c, v)
		}
	}
	return keepLiteral(b.String()), nil
}

// parse22 parses the body of a CPE 2.2 URI (after "cpe:/").
//
// CPE 2.2 permits trailing components to be omitted and empty components;
// both mean ANY. A packed edition ("~edition~sw_edition~target_sw~target_hw~other")
// is unpacked into the extended CPE 2.3 attributes.
func parse22(body string) (CPE, error) {
	comps := strings.Split(body, ":")
	if len(comps) > 7 {
		return CPE{}, malformed("CPE 2.2 URI has %d components, at most 7 allowed", len(comps))
	}
	fields := make([]string, len(attributeNames))
	for i := range fields {
		fields[i] = Any
	}
	for i, c := range comps {
		if i == 5 && strings.HasPrefix(c, "~") {
			if err := unpackEdition(c, fields); err != nil {
				return CPE{}, err
			}
			continue
		}
		v, err := canonicalURI(c)
		if err != nil {
			return CPE{}, malformed("attribute %s: %v", attributeNames[i], err)
		}
		fields[i] = v
	}
	return fromFields(fields)
}

// unpackEdition expands a CPE 2.2 packed edition component.
func unpackEdition(c string, fields []string) error {
	parts := strings.Split(c[1:], "~")
	if len(parts) != 5 {
		return malformed("packed edition %q must have 5 '~'-separated parts", c)
	}
	targets := []int{5, 7, 8, 9, 10} // edition, sw_edition, target_sw, target_hw, other
	for i, p := range parts {
		v, err := canonicalURI(p)
		if err != nil {
			return malformed("packed edition %q: %v", c, err)
		}
		fields[targets[i]] = v
	}
	return nil
}

// canonicalURI decodes one CPE 2.2 URI component into canonical 2.3 form.
func canonicalURI(c string) (string, error) {
	if c == "" {
		return Any, nil
	}
	if c == NA {
		return NA, nil
	}
	var b strings.Builder
	for i := 0; i < len(c); i++ {
		ch := c[i]
		if ch == '%' {
			if i+2 >= len(c) {
				return "", fmt.Errorf("truncated percent-encoding in %q", c)
			}
			d, ok := unhex(c[i+1], c[i+2])
			if !ok {
				return "", fmt.Errorf("invalid percent-encoding %q in %q", c[i:i+3], c)
			}
			if d == 0x01 || d == 0x02 {
				return "", fmt.Errorf("wildcard encoding in %q is not allowed in a supplied CPE", c)
			}
			ch = d
			i += 2
		}
		if ch <= ' ' || ch >= 0x7f {
			return "", fmt.Errorf("invalid character %q in %q", ch, c)
		}
		writeLiteral(&b, ch)
	}
	return keepLiteral(b.String()), nil
}

// keepLiteral stops a decoded literal hyphen (e.g. "\-" or "%2d") from
// becoming the logical NA value.
func keepLiteral(v string) string {
	if v == NA {
		return `\-`
	}
	return v
}

func fromFields(f []string) (CPE, error) {
	c := CPE{
		Part: f[0], Vendor: f[1], Product: f[2], Version: f[3], Update: f[4],
		Edition: f[5], Language: f[6], SWEdition: f[7], TargetSW: f[8],
		TargetHW: f[9], Other: f[10],
	}
	switch c.Part {
	case "a", "o", "h":
	default:
		return CPE{}, malformed("part must be a, o or h, got %q", c.Part)
	}
	return c, nil
}

// String returns the canonical CPE 2.3 formatted string.
func (c CPE) String() string {
	return prefix23 + strings.Join(c.Attributes(), ":")
}

// Attributes returns all eleven attribute values in formatted-string order.
func (c CPE) Attributes() []string {
	return []string{
		c.Part, c.Vendor, c.Product, c.Version, c.Update, c.Edition,
		c.Language, c.SWEdition, c.TargetSW, c.TargetHW, c.Other,
	}
}

// AttributeName returns the CPE 2.3 name of attribute index i.
func AttributeName(i int) string { return attributeNames[i] }

// IsSpecific reports whether a value is neither ANY nor NA.
func IsSpecific(v string) bool { return v != Any && v != NA }

// Unescape returns the logical value of a canonical attribute value, removing
// formatted-string escaping (e.g. `1.0\(beta\)` -> `1.0(beta)`).
func Unescape(v string) string {
	if !strings.Contains(v, `\`) {
		return v
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		if v[i] == '\\' && i+1 < len(v) {
			i++
		}
		b.WriteByte(v[i])
	}
	return b.String()
}

// writeLiteral writes a literal (non-wildcard) character in canonical
// formatted-string form.
func writeLiteral(b *strings.Builder, c byte) {
	if isPlain(c) {
		b.WriteByte(toLower(c))
		return
	}
	b.WriteByte('\\')
	b.WriteByte(c)
}

// isPlain reports whether c may appear unescaped in a formatted-string value.
func isPlain(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' ||
		c == '_' || c == '.' || c == '-'
}

func toLower(c byte) byte {
	if c >= 'A' && c <= 'Z' {
		return c + ('a' - 'A')
	}
	return c
}

func unhex(a, b byte) (byte, bool) {
	hi, ok1 := hexVal(a)
	lo, ok2 := hexVal(b)
	return hi<<4 | lo, ok1 && ok2
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// EscapeValue returns the canonical formatted-string form of a literal value
// (e.g. a version reported by a scanner): special characters, including
// wildcard characters, are escaped and letters lower-cased. An empty value
// is ANY.
func EscapeValue(v string) string {
	if v == "" {
		return Any
	}
	var b strings.Builder
	for i := 0; i < len(v); i++ {
		writeLiteral(&b, v[i])
	}
	return keepLiteral(b.String())
}
