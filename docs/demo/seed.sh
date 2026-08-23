#!/usr/bin/env bash
# Build the capture the demo GIF is recorded against.
#
# Runs a throwaway origin (docs/demo/serve.py) on 127.0.0.1:8000, points a
# throwaway lockgate at it, and browses it with curl. Every hostname is under
# localtest.me, a public wildcard that resolves to 127.0.0.1 — so the history
# reads like a real host tree without touching /etc/hosts or a real target.
#
# Two api.github.com requests are the exception: they are there so the capture
# shows an HTTPS flow going through the MITM CA. Drop them if you are offline.
#
# Run from the repository root, after `cargo build --release`.
set -euo pipefail

DATA=docs/demo/.data
CA=crates/lockgate-core/src/ca/ca.cer
PROXY=http://127.0.0.1:9080
S=http://shop.localtest.me:8000
A=http://api.shop.localtest.me:8000
UA='Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/141.0 Safari/537.36'
TOK=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOjQ3MTEsInJvbGUiOiJjdXN0b21lciJ9.s1g

[ -f "$CA" ] || { echo "no CA at $CA — see the README"; exit 1; }

rm -rf "$DATA"
python3 docs/demo/serve.py 8000 & origin=$!
# The TUI wants a terminal, so give it one and let it draw into the void.
script -q /dev/null ./target/release/lockgate \
  --project acme -p 9080 --mcp-port 0 --data-dir "$DATA" >/dev/null 2>&1 & proxy=$!
trap 'kill $origin $proxy 2>/dev/null || true' EXIT
sleep 4

q() { curl -s -o /dev/null -w "%{http_code} " -x "$PROXY" --cacert "$CA" -m 15 -A "$UA" "$@"; }

q $S/
q $S/static/app.css
q $S/static/app.js
q $A/api/v1/products
q $A/api/v1/products/103
q $A/api/v1/products/999
q $S/login
q -X POST -H 'Content-Type: application/x-www-form-urlencoded' \
     -d 'email=dana@example.com&password=correct-horse' $A/api/v1/session
q -H 'Cookie: sid=8f2b1c9d4a' $A/api/v1/cart
q -X POST -H 'Content-Type: application/json' -H 'Cookie: sid=8f2b1c9d4a' \
     -d '{"sku":"LG-HUB","qty":1}' $A/api/v1/cart/items
q $A/api/v1/account                                   # 401 — the one the GIF replays
q -H "Authorization: Bearer $TOK" $A/api/v1/account
q -H "Authorization: Bearer $TOK" $A/api/v1/orders/8817
q -H "Authorization: Bearer $TOK" $A/api/v1/orders/8818
q -H "Authorization: Bearer $TOK" $A/api/v1/admin/users
q -H "Authorization: Bearer $TOK" $A/api/v1/reports/export
q -X PUT -H 'Content-Type: application/json' -H "Authorization: Bearer $TOK" \
     -d '{"role":"admin"}' $A/api/v1/account
q $S/health
q https://api.github.com/repos/charmbracelet/vhs
q https://api.github.com/rate_limit
q $A/api/v1/products/101
q $A/api/v1/products/102
q -H "Authorization: Bearer $TOK" $A/api/v1/orders/8819
q $S/static/app.js
q $A/api/v1/products
q -H "Authorization: Bearer $TOK" $A/api/v1/account
echo

# The tape replays the capture from a pristine copy, so a re-record starts from
# the same 26 flows however many findings the last run filed.
kill $proxy; sleep 2
rm -rf docs/demo/.data.pristine
cp -R "$DATA" docs/demo/.data.pristine
echo "seeded $DATA (26 flows)"
