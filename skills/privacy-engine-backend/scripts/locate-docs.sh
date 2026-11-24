#!/bin/sh
# locate-docs.sh [MODULE_DIR]
#
# Prints the docs directory of the privacy-engine version that the Go module
# in MODULE_DIR (default: the current directory) actually uses, so that the
# agent reads the specification matching that version. Honors go.work and
# replace directives. Downloads the module if it is not in the cache yet.
set -eu
mod=github.com/ln80/privacy-engine
cd "${1:-.}"

if ! command -v go >/dev/null 2>&1; then
	echo "locate-docs: the go command is not installed" >&2
	exit 1
fi

version=$(go list -m -f '{{.Version}}{{with .Replace}} (replaced by {{.Path}}{{with .Version}}@{{.}}{{end}}){{end}}' "$mod" 2>/dev/null || true)
dir=$(go list -m -f '{{.Dir}}' "$mod" 2>/dev/null || true)
if [ -z "$dir" ] && [ -n "$version" ]; then
	go mod download "$mod" >/dev/null 2>&1 || true
	dir=$(go list -m -f '{{.Dir}}' "$mod" 2>/dev/null || true)
fi
if [ -z "$dir" ]; then
	echo "locate-docs: this module does not require $mod. Add it first:" >&2
	echo "  go get $mod@latest" >&2
	exit 1
fi
if [ ! -d "$dir/docs" ]; then
	echo "locate-docs: $mod ${version:-(local)} at $dir has no docs/ directory; v0.11.0 or later is needed" >&2
	exit 1
fi
echo "version: ${version:-(local)}"
echo "docs:    $dir/docs"
