// Package data embeds the curated first-party JSON that the vulndb builder
// loads, so a single self-contained binary can build a database without the
// repository checkout on disk.
//
// Only first-party source data is embedded. data/http_tech.json is NOT
// embedded: it is derived at build time from the GPL-3.0 webappanalyzer corpus
// (vulndb build --webappanalyzer DIR) and is gitignored.
package data

import _ "embed"

//go:embed aliases.json
var Aliases []byte

//go:embed distro_packages.json
var DistroPackages []byte

//go:embed distro_releases.json
var DistroReleases []byte

//go:embed windows_builds.json
var WindowsBuilds []byte

//go:embed product_names.json
var ProductNames []byte

//go:embed http_apps.json
var HTTPApps []byte

// Files maps each embedded curated file's base name to its contents. The
// builder resolves an "embedded:<name>" source against this map.
var Files = map[string][]byte{
	"aliases.json":         Aliases,
	"distro_packages.json": DistroPackages,
	"distro_releases.json": DistroReleases,
	"windows_builds.json":  WindowsBuilds,
	"product_names.json":   ProductNames,
	"http_apps.json":       HTTPApps,
}
