#!/usr/bin/env bash
# Build the Splunkbase package dist/mlab-<version>.tgz from mlab/, without dev-stack leftovers.
set -euo pipefail
cd "$(dirname "$0")/.."
version=$(awk -F' *= *' '/^\[id\]/{s=1} s && $1=="version"{print $2; exit}' mlab/default/app.conf)
out="dist/mlab-$version.tgz"
mkdir -p dist
# COPYFILE_DISABLE: no macOS ._* files; --exclude: what Splunk writes into the mounted app
COPYFILE_DISABLE=1 tar -czf "$out" --exclude='mlab/local' --exclude='mlab/metadata/local.meta' \
  --exclude='__pycache__' --exclude='*.pyc' --exclude='.DS_Store' mlab
echo "$out"
