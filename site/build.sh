#!/usr/bin/env bash
# Builds the site into site/dist/. Needs pandoc and, for the diagrams, mmdc (mermaid-cli).
# Rendered diagrams are cached by content in site/.cache/.
set -euo pipefail
site=$(cd "$(dirname "$0")" && pwd)
repo=$(dirname "$site")
dist=$site/dist
cache=$site/.cache

rm -rf "$dist"
mkdir -p "$dist/diagrams" "$cache"
cp "$site"/{index.html,base.css,docs.css,site.js,logo.svg,logo-mark.svg} "$dist/"

# Pages deploys dist/ as static files, so nothing should treat it as a Jekyll source.
touch "$dist/.nojekyll"

grep -v '^#' "$site/allow.txt" | cut -d'|' -f1 | while read -r src; do
  [ -f "$repo/$src" ] || { echo "allow.txt names a missing file: $src" >&2; exit 1; }
  out=$(printf '%s' "$src" | sed -e 's/README\.md$/index.html/' -e 's/\.md$/.html/')
  mkdir -p "$dist/$(dirname "$out")"
  SRC=$src SITE=$site DIST=$dist CACHE=$cache pandoc -f gfm -t html5 \
    --syntax-highlighting=none --toc --toc-depth=2 --wrap=none \
    --lua-filter="$site/filter.lua" --template="$site/docs.tmpl.html" \
    -o "$dist/$out" "$repo/$src"
  echo "rendered $out"
done

pandoc lua "$site/check.lua" "$site" "$dist"
