// Package schema embeds the SQLite schema so the vulndb binary can create a
// database without shipping schema.sql separately.
package schema

import _ "embed"

// SQL is the contents of schema.sql.
//
//go:embed schema.sql
var SQL string
