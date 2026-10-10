#!/usr/bin/env bash
# Build release archives of the bunyip binary for one or more OS/arch targets.
#
#   scripts/release.sh VERSION [GOOS/GOARCH ...]
#
# Each target produces dist/bunyip_<version>_<os>_<arch>.{tar.gz|zip} holding a
# self-contained binary (curated data is embedded; CGO is off) plus the license
# files and README. A dist/SHA256SUMS covers every archive.
set -euo pipefail

version="${1:?usage: scripts/release.sh VERSION [GOOS/GOARCH ...]}"
shift || true
platforms=("$@")
[ "${#platforms[@]}" -eq 0 ] && platforms=(linux/amd64)

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dist="$root/dist"
docs=(LICENSE-MIT LICENSE-APACHE NOTICE README.md)

rm -rf "$dist"
mkdir -p "$dist"

for p in "${platforms[@]}"; do
	os="${p%/*}"
	arch="${p#*/}"
	ext=""
	[ "$os" = windows ] && ext=".exe"
	name="bunyip_${version}_${os}_${arch}"
	staging="$dist/$name"
	mkdir -p "$staging"
	echo "building $p -> $name"
	CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" go build -trimpath \
		-ldflags "-s -w -X main.buildVersion=${version}" \
		-o "$staging/bunyip${ext}" "$root/cmd/bunyip"
	for d in "${docs[@]}"; do
		[ -f "$root/$d" ] && cp "$root/$d" "$staging/"
	done
	if [ "$os" = windows ]; then
		(cd "$dist" && zip -qr "${name}.zip" "$name")
	else
		(cd "$dist" && tar -czf "${name}.tar.gz" "$name")
	fi
	rm -rf "$staging"
done

(cd "$dist" && sha256sum bunyip_*.tar.gz bunyip_*.zip 2>/dev/null >SHA256SUMS || true)
echo
echo "artifacts in $dist:"
ls -1 "$dist"
