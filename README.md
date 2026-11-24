# activeban

An **AI-driven active ban system** for home networks: **machine detection bans
a device immediately, an LLM reviews the ban afterwards and releases false
positives, and a human has the final say.**

activeban is the *control layer* only. Detection (what looks dangerous) and
enforcement (how a ban is applied) are both external and pluggable:

- **Detection** feeds events into activeban (`report`). Anything that can call
  a CLI — or pipe one JSON object to `report --json-stdin` — works: a DNS
  monitor, Suricata, Zeek, a log watcher, …
- **Enforcement** is delegated to two external commands you provide
  (`ban_cmd` / `release_cmd`), called with `(MAC, IP, TTL)` / `(MAC, IP)`.
  Example scripts are included for:
  - log-only (default, safe)
  - ASUS routers — SSH + iptables (WAN block)
  - OpenWrt — SSH + nftables (WAN block, TTL also enforced by nft itself)
  - OpenWrt Wi-Fi — SSH + hostapd deny ACL + deauthenticate
    (full network exclusion, lateral traffic included)
  - anything else that can be scripted the same way — e.g. moving a client
    to a quarantine VLAN, or shutting a managed switch port — is just
    another command pair.

> **Status: experimental "utakata" project** — *utakata* (泡沫) is foam on
> water: here today, gone tomorrow. Built for the author's own home,
> published in case it is useful to someone. Maintenance is best-effort
> and may stop at any time. No promotion, no roadmap.

## How it works

```
detector ──report──▶ activeban daemon ──▶ external ban command ──▶ router/AP
                          │  ▲
              LLM review ─┘  └── verdict: release (false positive)
              (separate user)     or keep (with reason, notified)
                          │
                     notifications (Nextcloud Talk, with offline spool)
                          │
                     human can ban / release / override at any time
                     every ban expires by TTL
```

### Authority model

The interesting part is *who is allowed to do what*. Authority is never taken
from a CLI argument (a `--as human` flag would be self-asserted); it is
derived from the **Unix UID of the client connecting to the daemon's socket**
(`SO_PEERCRED`):

| role | who | can |
|---|---|---|
| `machine` | detector account (`qdetect`) | submit events (`report`) only |
| `llm` | verification service account (`qllm`) | release **machine** bans, submit verdicts |
| `human` | root | everything |

Rules:

- **Hierarchy**: human > llm > machine. The LLM can never release a human's
  ban. A release by a higher authority puts the device in **cooldown**
  (default 24 h): the same trigger class cannot re-ban it, and the refusal
  is logged. Only a *heavier* trigger class or a human can break a cooldown.
- **Flap damping**: if releases repeat for one device (default 2), automatic
  response for that device stops and the case is escalated to the human.
  There is deliberately **no global ban cap** — if a vendor cloud is
  compromised, most of your IoT may need banning at once.
- **Do-not-block list**: MACs in `policy.json` (routers, servers, phones, …)
  are refused for *every* role. Judge exclusions by the harm of stopping the
  device, not by device category.
- **TTL**: every ban expires (default 6 h). Expiry is not a "release" and
  carries no cooldown.
- **Fail-closed review**: if the LLM API is unreachable, bans stay in place.

The LLM receives detection data as structured JSON. Device names and DNS
strings are attacker-controlled data: the review prompt treats them strictly
as data, never as instructions.

### Canary probe: test the whole loop without opening a hole

End-to-end testing needs a trigger a device can fire on demand — but a
dedicated test URL would mean a new listening service, i.e. new attack
surface. activeban uses a **DNS canary** instead:

- The probe name is `canary.activeban.invalid` (`.invalid` is reserved by
  RFC 2606: it never resolves and is never registered). No server exists.
- A DNS-observing detector (e.g. a Pi-hole watcher) reports any query for
  that name as `trigger: "canary"`, TTL 300 s. Opening
  `http://canary.activeban.invalid/` in a browser fires the DNS query
  first; the page failing to load is expected.
- The ban runs the full pipeline — enforcement, Talk notification, LLM
  review — and the reviewer is instructed (on the trusted prompt side) to
  release a matching canary as a deliberate test probe.
- `canary` maps to a dedicated `test` class in `policy.json`: releasing a
  test ban sets **no cooldown** and does not count toward flap damping,
  so the probe can be re-run immediately. Protected MACs are still
  refused, as for every trigger.

Details and the staged procedure are in
[`docs/integration.md`](docs/integration.md) §7.

## Layout

- `activeban.py` — daemon + CLI + LLM verification loop (single file, stdlib only)
- `deploy.sh` — idempotent installer (users, files, systemd units; log-only pair)
- `policy.example.json` — copy to `/etc/activeban/policy.json` and edit
- `fw.d/` — example enforcement commands (log / ASUS / OpenWrt / templates)
- `examples/` — integration helpers, including the SSH forced-command
  receiver for a detector on another host
- `systemd/` — `activeban.service` (daemon, unprivileged user) and
  `activeban-verify.service` (LLM loop, separate user)
- `docs/design.md` — design notes and the reasoning behind the authority model
- `docs/integration.md` — the implementation contract: detector CLI/JSON,
  remote-detector SSH bridge, local socket protocol, enforcement-command
  arguments and exit status, configuration, and a staged first-run checklist

## Quick start

1. Create users/groups: a system group `activeban`; a daemon user; `qllm` and
   `qdetect` system users, both in group `activeban`. Map them in `policy.json`
   (`role_users`).
2. Install `activeban.py` to `/usr/local/sbin/`, the log-only command pair as
   `/usr/local/sbin/activeban-ban` and `/usr/local/sbin/activeban-release`.
3. Prepare the configuration in the repository root (real files are
   covered by `.gitignore` and cannot be committed by accident):
   - `policy.json`: copy `policy.example.json` and edit
   - `nextcloud.json`: copy `nextcloud.example.json` (Talk credentials)
   - `llm.json`: copy `llm.example.json`
   - `openai.key`: the API key itself, one line (see `openai.key.example`)
   Then run `deploy.sh` as root: it installs everything, including the
   secret files with owner `root:<reader>` and mode `640`.
4. Install the systemd units, `systemctl enable --now activeban activeban-verify`.
5. Try it (as root = human):
   - `activeban.py ban <a protected MAC>` → refused
   - `activeban.py ban <a test device MAC> --ttl 60` → banned, auto-released in 60 s
   - `activeban.py status`

Before connecting a production detector or router, follow the staged
first-run checklist in [`docs/integration.md`](docs/integration.md). It
defines the detector CLI/JSON event format, the SSH forced-command bridge
for a detector on another host, and the exact enforcement-command contract
(argument order, idempotence, timeout, and exit status).

Then swap the enforcement pair for your router/AP and let your detector call
`activeban.py report <MAC> --ip <IP> --trigger <name> --reason <text>` as the
`qdetect` user — or pipe an event as JSON:

```sh
echo '{"mac":"AA:BB:CC:DD:EE:FF","ip":"192.168.1.50","trigger":"intel",
       "reason":"threat-intel match","evidence":{"domain":"example.org"}}' \
  | activeban.py report --json-stdin
```

## License

MIT — see `LICENSE`.
