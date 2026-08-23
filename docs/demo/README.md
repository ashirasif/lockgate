# The demo GIF

`docs/demo.gif` in the top-level README. Recorded with
[vhs](https://github.com/charmbracelet/vhs) so it can be regenerated rather than
re-performed.

```sh
cargo build --release
docs/demo/seed.sh      # capture the traffic the tape drives (once)
docs/demo/record.sh    # render docs/demo.gif from demo.tape
```

- `serve.py` — a throwaway shop API. Plain HTTP: lockgate verifies upstream
  certificates, so a self-signed origin would come back 502.
- `seed.sh` — browses that origin through a throwaway lockgate, leaving 26 flows
  in `docs/demo/.data` (gitignored, along with the `.data.pristine` copy the
  tape resets to). Hostnames are `shop.localtest.me` and `api.shop.localtest.me`
  — a public wildcard resolving to 127.0.0.1, so the sitemap reads like a real
  host tree without editing `/etc/hosts`. Two api.github.com requests are the
  only real traffic, there so an HTTPS flow through the MITM CA shows up.
- `demo.tape` — the keystrokes. `Type "15j"` lands on flow #10, the 401 the tape
  replays; if you change the seed, recount.

Nothing here touches `~/.lockgate`, so a real engagement's traffic can never
end up in the recording.
