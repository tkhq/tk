#!/bin/sh
# Usage: render.sh VERSION DIST_DIR
# Prints the tk formula for release VERSION (without the leading v), filled
# from the .sha256 files in DIST_DIR.
set -eu

version=$1
dist=$2
formula=$(cat "$(dirname "$0")/tk.rb")
for target in aarch64-apple-darwin aarch64-unknown-linux-musl x86_64-unknown-linux-musl; do
  sum=$(cut -d ' ' -f 1 "$dist/tk-$target-v$version.tar.gz.sha256")
  formula=$(printf '%s\n' "$formula" | sed "s/@SHA256_$target@/$sum/g")
done
formula=$(printf '%s\n' "$formula" | sed "s/@VERSION@/$version/g")
case $formula in
*@*@*)
  echo "unfilled placeholder in the rendered formula" >&2
  exit 1
  ;;
esac
printf '%s\n' "$formula"
