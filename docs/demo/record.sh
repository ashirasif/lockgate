#!/usr/bin/env bash
# Re-record docs/demo.gif. Run from the repository root:
#
#   cargo build --release
#   docs/demo/seed.sh        # once — builds the capture the tape drives
#   docs/demo/record.sh
#
# Needs vhs (brew install vhs). The origin has to be up: the tape replays a
# 401 with a token attached and the response has to come back 200.
set -euo pipefail

[ -d docs/demo/.data.pristine ] || { echo "run docs/demo/seed.sh first"; exit 1; }

python3 docs/demo/serve.py 8000 & origin=$!
trap 'kill $origin 2>/dev/null || true' EXIT
sleep 1

# Start from the seeded capture every time — the tape files a finding, and a
# second run would otherwise show two.
rm -rf docs/demo/.data
cp -R docs/demo/.data.pristine docs/demo/.data

vhs docs/demo/demo.tape
