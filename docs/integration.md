# activeban integration guide

This document is the implementation contract for connecting three things to
activeban:

1. a **detector**, which submits an event;
2. an **enforcement command pair**, which applies and removes a ban;
3. a detector on **another host**, which reaches activeban through SSH.

The design rationale is in [`design.md`](design.md). This guide is about the
exact interfaces an implementer needs.

## Integration map

```text
same host:
  detector process (qdetect)
      │  activeban.py report ...
      ▼
  CLI ── Unix socket / SO_PEERCRED ──▶ activeban daemon
                                           │
                                           ├─▶ ban_cmd / release_cmd
                                           ├─▶ Nextcloud Talk API (HTTPS)
                                           └─▶ state + append-only log

another host:
  detector ── SSH forced command ──▶ activeban-report-ssh (qdetect)
                                           │
                                           └─▶ same CLI and Unix socket

verification:
  activeban-verify (qllm) ── Unix socket ──▶ daemon
      └──▶ configured LLM API (HTTPS)
```

activeban deliberately has **no TCP listener**. Remote detectors do not
connect to the daemon socket over the network.

---

## 1. Detector integration (same host)

### Supported interface

Use the `activeban.py` CLI on the activeban host. The CLI connects to the
daemon's Unix socket; the daemon determines the caller's role from the CLI
process's UID (`SO_PEERCRED`). A request does **not** carry a role field.

For machine detection, the CLI process must run as the account mapped to
`machine` in `policy.json` (`qdetect` in the example policy).

> Do not run a detector as root and expect it to be treated as a machine
> event. Root is the human role, so its bans become human bans and the LLM
> cannot release them. An unmapped account is rejected as an unknown caller.

The detector account must also be able to connect to the socket: the socket
is mode `0660`, owned by the daemon user and the group named by
`socket_group` in the policy (`activeban` by default).

### CLI form

```sh
activeban.py report AA:BB:CC:DD:EE:FF \
  --ip 192.168.1.50 \
  --trigger behavior \
  --reason "unusual outbound burst" \
  --ttl 21600 \
  --evidence '{"queries": 1200, "window_seconds": 300}'
```

| Item | Meaning |
|---|---|
| positional `MAC` | Required. Colon-separated MAC; case-insensitive on input and normalized to uppercase. |
| `--ip` | Optional but strongly recommended: the IP observed for that MAC at detection time. |
| `--trigger` | Optional event name; default `behavior`. Define its class in `trigger_classes` in the policy. Unknown names fall back to class `normal`. |
| `--reason` | Human-readable detection reason. It is logged and sent to the reviewer and notification channel. |
| `--ttl` | Optional ban lifetime in seconds. If omitted, `default_ttl_seconds` from the policy is used. |
| `--evidence` | Optional JSON text. By contract this should be a JSON object containing detector-specific evidence. |

### JSON-stdin form

A detector or format converter can pipe exactly one JSON object:

```sh
printf '%s\n' '{
  "mac": "AA:BB:CC:DD:EE:FF",
  "ip": "192.168.1.50",
  "trigger": "intel",
  "reason": "threat-intel match",
  "ttl": 21600,
  "evidence": {"domain": "example.org", "feed": "example-feed"}
}' | activeban.py report --json-stdin
```

Fields have the same names and meanings as the CLI options above. `mac` is
required; all other fields are optional. Keep the event compact: the local
socket request is read as one message of at most 65,536 bytes.

### Event semantics

- Send the **MAC observed at detection time**, not only an IP address. If
  DHCP later gives the IP to another device, the MAC is still the identity
  activeban enforces.
- `report` asks for an immediate machine ban. It is not a passive alert API.
- A report for a MAC in `do_not_block` is refused for every role.
- A report for a device in a higher-or-equal-class cooldown, or under a
  human hold, is refused and logged.
- Reporting an already-banned MAC extends its daemon-side expiry to at
  least `now + ttl`; it does not call the ban command again. If the
  enforcement layer has its own independent expiry, account for that in the
  enforcement implementation.
- A detector should submit an event once. It should not retry blindly after
  an ambiguous transport failure without checking `activeban.py status` or
  the daemon log, because a retry can extend a ban.

### Device identification

A detector may know a device by its MAC, by its IP, or by a
human-assigned name — and for LLM inference it is best to send
**everything known at once**, not one chosen identifier. Send a
`device` object with any subset of the three fields (at least one is
required):

```json
{"device": {"mac": "AA:BB:CC:DD:EE:FF", "ip": "192.168.1.50", "name": "Living room bulb"}}
```

When several fields are present they are cross-checked: if the MAC
resolves to one device but the IP's owner at the event time is another,
that disagreement is itself evidence (a stale DHCP mapping or possible
spoofing) — it is logged and notified as a warning, and enforcement
proceeds on the MAC.

Resolution is mechanical and strictly ordered:

1. **MAC** — exact match (normalized to uppercase). Always wins.
2. **IP** — resolved to the MAC that held that IP **at the event time**,
   using timestamped sources (DHCP lease/reservation table, ARP history,
   a monitor's IP↔MAC history). Never resolve an IP through the
   *current* mapping alone: DHCP addresses rot, and yesterday's IP may
   be another device today.
3. **Name** — normalized exact match only. Human-assigned names contain
   typos, and the same name often exists on several devices (a set of
   identical smart bulbs, for example); multiple exact matches are
   *ambiguous*, not a match.

Keep two kinds of identification separate:

- **Enforcement identity**: a ban can only be applied to a MAC. An event
  whose MAC cannot be determined must not be banned on a guessed MAC;
  report it as a notification for human judgement instead.
- **Profile identity** (context for the LLM review): if the enforcement
  MAC is known but no device profile matches, or resolution above was
  ambiguous, pass the candidate rows of the device table to the LLM and
  let it infer the device from the clues available — the OUI vendor
  implied by the MAC prefix, the DHCP hostname, the last IP, the device
  type, the last-seen time, name similarity. An inferred identity is an
  **estimate, not a fact**: notifications and logs must carry a warning
  (for example `identity: inferred, unverified`), the review reason must
  state the basis of the inference, and an inferred profile's "normal
  behaviour" summary is weak evidence — a mismatch against it alone is
  not a reason to keep a ban.

Human-facing output (notifications, status displays) leads with the
device **name** and shows MAC/IP secondarily: people cannot manage a
fleet by MAC address. Internally nothing changes — profiles,
`do_not_block`, cooldowns and enforcement all stay keyed by MAC.

The device table itself is meant to be generated, not hand-maintained
row by row: human-assigned names (authoritative), the operator's device
classification, the router's DHCP reservation/lease table (a useful
MAC↔IP↔hostname clue source, but stale, mistyped and duplicated entries
do occur — a clue, not the truth), IP↔MAC history, and an OUI vendor
table for the MAC prefix.

### Event context: the device table, "normal", and "just now"

The LLM review can only compare. It needs three things, and none of
them works as free prose — an open-ended "describe the behaviour"
field leaves every detector implementer guessing what to write. Use
the fixed fields below and copy the closest worked example.

**1. The device table ("who is this, normally").** One row per device,
keyed by MAC, generated as described above. The free-text field is
`expected`, and it has a fixed three-part shape — (a) normal
destinations, (b) volume and timing, (c) what it never does:

```json
{"mac": "30:30:F9:00:00:01", "name": "Living room bulb", "type": "bulb",
 "vendor": "SwitchBot",
 "expected": "Destinations: vendor cloud (AWS) and NTP only. Volume: a few dozen queries/day, periodic traffic at night too. Never: connects to other LAN devices, long tunnel-like DNS names."}
{"mac": "84:FC:E6:00:00:02", "name": "Entrance hub", "type": "hub",
 "vendor": "SwitchBot",
 "expected": "Destinations: vendor cloud, NTP. Volume: a few hundred queries/day including BLE relay traffic for child devices. Never: LAN scans, direct uploads to unknown hosts."}
{"mac": "10:2C:B1:00:00:03", "name": "Camera base station", "type": "camera",
 "vendor": "Eufy",
 "expected": "Destinations: vendor cloud (video upload, also at night), NTP. Volume: bursty, large uploads on motion events. Never: connects to other LAN devices."}
```

**2. `recent` ("what just happened") — fixed fields, counted, not
narrated.** Put it in `evidence`:

| Field | Meaning |
|---|---|
| `window_seconds` | The observation window the counts cover. |
| `counts` | Per-kind counts (queries, NX responses, connections, alerts…). |
| `top_peers` | Top destinations (domains and/or IPs), at most 10, with counts. |
| `new_peers` | Destinations **not** in the device's baseline. This is the field the review mostly judges by. |
| `first_seen_peer_at` | When the newest destination was first seen, if known. |

**3. `baseline` ("what is usual for this device")** — only a detector
with history can compute this (a DNS monitor can; most others cannot).
If you have none, send `"baseline": null` and say why in `reason`:
an explicit "none" is not the same as a missing field, and the review
treats insufficient context conservatively.

Worked examples — copy the closest one and replace the numbers:

DNS detector (with baseline):

```json
{"device": {"mac": "30:30:F9:00:00:01", "ip": "192.168.1.151", "name": "Living room bulb"},
 "trigger": "behavior", "reason": "NX burst far above baseline",
 "evidence": {
   "recent": {"window_seconds": 1800, "counts": {"queries": 4120, "nx": 3980},
     "top_peers": [{"domain": "a1b2.example-dyndns.net", "count": 3900}],
     "new_peers": ["a1b2.example-dyndns.net"], "first_seen_peer_at": "2026-01-01T02:14:00+09:00"},
   "baseline": {"period_days": 30, "queries_per_day_median": 48,
     "top_domains": ["api.switch-bot.com", "pool.ntp.org"], "nx_rate": 0.01}}}
```

IDS detector (no baseline — stated explicitly):

```json
{"device": {"mac": "10:2C:B1:00:00:03", "ip": "192.168.1.60"},
 "trigger": "behavior", "reason": "IDS signature matched; this detector keeps no per-device history, baseline: none",
 "evidence": {
   "recent": {"window_seconds": 60, "counts": {"alerts": 3},
     "top_peers": [{"ip": "203.0.113.9", "port": 4444, "protocol": "tcp"}],
     "new_peers": ["203.0.113.9"]},
   "baseline": null,
   "signature": "ET MALWARE Possible C2 Heartbeat"}}
```

Minimal event (log watcher, manual-style report — the floor, not the goal):

```json
{"device": {"ip": "192.168.1.77", "name": "garage plug"},
 "trigger": "behavior", "reason": "repeated outbound connection attempts to a single new IP in the firewall log; no baseline available",
 "evidence": {"recent": {"window_seconds": 600, "counts": {"connections": 240},
   "top_peers": [{"ip": "198.51.100.23", "port": 8888, "protocol": "tcp"}],
   "new_peers": ["198.51.100.23"]}, "baseline": null}}
```

A `reason` string alone, with no `recent`, is treated by the review as
insufficient context: the ban stays and the case effectively waits for
a human. Numbers and destination comparisons are what a verdict can
be based on; a calm-sounding sentence is not.

### Reading the result

The CLI prints one JSON object to stdout. **Check `ok`; do not rely only on
the CLI process exit code.** A daemon refusal is a normal JSON response and
the current CLI exits `0` after printing it. A socket connection failure is
different: the CLI raises an error and exits non-zero.

Successful new ban:

```json
{"ok": true, "result": "banned", "expires_at": 1790000000, "req": "0123456789ab"}
```

Duplicate report:

```json
{"ok": true, "result": "extended", "expires_at": 1790000000}
```

Refusal:

```json
{"ok": false, "error": "protected mac (do_not_block)"}
```

Possible refusal errors include `bad mac`, `unknown caller`,
`protected mac (do_not_block)`, `held for human judgement`, and
`cooldown (<class>) until <unix-time>`.

---

## 2. Detector integration (another host)

Use SSH as a narrow, forced-command bridge. This adds no listening service
to activeban.

### Activeban-host side

1. Install the included receiver:

   ```text
   examples/activeban-report-ssh
     → /usr/local/sbin/activeban-report-ssh
   ```

2. Make it owned by root and executable.
3. Add the detector's dedicated public key to `qdetect`'s
   `authorized_keys`, with the requested SSH command ignored and replaced
   by the receiver:

   ```text
   command="/usr/local/sbin/activeban-report-ssh",no-pty,no-port-forwarding,no-agent-forwarding,no-X11-forwarding ssh-ed25519 AAAA... detector-host
   ```

4. The `qdetect` account needs a shell that can execute the forced command
   (for example `/bin/sh`); keep the password locked and rely on the key
   restrictions above. A `nologin` shell prevents the forced command from
   running.

The receiver ignores `SSH_ORIGINAL_COMMAND`, reads one JSON event from
stdin, and executes:

```sh
/usr/bin/python3 /usr/local/sbin/activeban.py report --json-stdin
```

Because the receiver and CLI run as `qdetect`, the daemon sees the machine
role through `SO_PEERCRED`.

### Detector-host side

Send one event on stdin:

```sh
ssh -T \
  -i /path/to/detector_key \
  -o BatchMode=yes \
  -o StrictHostKeyChecking=yes \
  qdetect@activeban-host \
  < event.json
```

The response is the same JSON result described above; check `ok` on the
detector side. Protect the detector's private key as a credential that can
cause bans, even though the forced command cannot obtain a shell or release
a ban.

---

## 3. Local socket protocol (advanced)

The supported public interface is the CLI. The socket protocol below is
documented so operators and alternative local clients can understand what
the CLI does; it is not a network protocol.

| Property | Value |
|---|---|
| Transport | `AF_UNIX`, `SOCK_STREAM` |
| Default path | `/run/activeban/activeban.sock` (override: `ACTIVEBAN_SOCK`) |
| Permissions | Socket mode `0660`; group from policy `socket_group` |
| Framing | Send one UTF-8 JSON object in one write; the daemon performs one read of at most 65,536 bytes |
| Response | One UTF-8 JSON object followed by `\n`, then the daemon closes its side after the client closes |
| Authentication | Peer UID via `SO_PEERCRED`; no role field and no bearer token |

Example request:

```json
{"cmd":"report","mac":"AA:BB:CC:DD:EE:FF","ip":"192.168.1.50","trigger":"behavior","reason":"unusual outbound burst","ttl":21600,"evidence":{}}
```

Commands implemented by the daemon are:

| `cmd` | Allowed roles | Purpose |
|---|---|---|
| `report` | intended for `machine` | Submit a detection event for immediate ban. |
| `ban` | `human` | Manual ban. |
| `release` | `llm`, `human` | Release a ban, subject to origin rules. |
| `verdict` | `llm` | Submit the post-ban LLM verdict. |
| `pending` | `llm`, `human` | List machine bans awaiting verification. |
| `status` | any recognized role | Return bans, cooldowns, and holds. |
| `unhold` | `human` | Clear a hold and cooldowns for a MAC. |

Including `"role":"human"` in a request has no effect. Authority comes only
from the connecting process's UID.

---

## 4. Enforcement command contract

### Configuration

`policy.json` names exactly one executable path for each direction:

```json
{
  "ban_cmd": "/usr/local/sbin/activeban-ban",
  "release_cmd": "/usr/local/sbin/activeban-release"
}
```

These values are executable paths, not shell command lines. activeban does
not append policy-defined arguments and does not invoke a shell. Install
one selected pair from `fw.d/` under those names, or write a custom pair
from the included templates:

```text
fw.d/activeban-ban-template
fw.d/activeban-release-template
```

### Invocation

The daemon runs the commands as its own service user (`quarantine` in the
included systemd unit), captures stdout and stderr, and applies a
30-second timeout.

#### Ban

```text
activeban-ban MAC IP TTL_SECONDS
```

| Argument | Value |
|---|---|
| `$1` | MAC, uppercase `AA:BB:CC:DD:EE:FF` |
| `$2` | IP recorded at detection time, or an empty string |
| `$3` | TTL in decimal seconds |

#### Release

```text
activeban-release MAC IP
```

| Argument | Value |
|---|---|
| `$1` | MAC, uppercase `AA:BB:CC:DD:EE:FF` |
| `$2` | IP recorded for the ban, or an empty string |

### Exit status and state

- Exit `0` means the requested network state is in effect.
- Any non-zero exit, execution error, or timeout means failure.
- If a **ban** command fails, activeban logs `fw_exec` / `ban_failed` and
  does **not** record the device as banned.
- If a **release** command fails, activeban logs `fw_exec` /
  `release_failed` and keeps the ban in its state, so a later release or
  TTL tick can retry.
- stdout is not part of the protocol. stderr is truncated in the daemon log;
  write diagnostics to stderr or to the command's own log, not stdout.

A successful CLI result therefore means both that the daemon accepted the
operation and that the enforcement command reported success. Separately
verify the router/AP state during first installation; an implementation can
always return `0` incorrectly.

### Implementation requirements

An enforcement pair must:

- be executable by the daemon user;
- be idempotent in both directions — banning an already-banned MAC and
  releasing a non-banned MAC should succeed;
- finish within 30 seconds and never wait for interactive input;
- use absolute paths and not depend on the current working directory or a
  login shell environment;
- treat the MAC as the identity and the IP as detection-time context;
- either honour the TTL itself or ensure the daemon's release call can
  remove the state after TTL expiry;
- fail with a non-zero exit when the target cannot be reached or the
  requested change cannot be confirmed;
- keep router/AP credentials outside `policy.json` and preferably outside
  the command body.

Router-based examples read a shell fragment from:

```text
/etc/activeban/fw-target.conf
```

with values such as:

```sh
FW_HOST=192.168.1.1
FW_USER=admin
FW_KEY=/etc/activeban/router_key
# Wi-Fi pair only; space-separated hostapd interface names:
WIFI_IFACES="wlan0 wlan1"
# Webhook pair only; URLs POSTed to on ban / release:
WEBHOOK_BAN_URL="http://homeassistant.local:8123/api/webhook/activeban-ban"
WEBHOOK_RELEASE_URL="http://homeassistant.local:8123/api/webhook/activeban-release"
# WEBHOOK_HEADER="Authorization: Bearer TOKEN"
```

Because the examples source this file as shell, protect it as trusted local
configuration and restrict its permissions. The SSH key it points to should
be dedicated to this enforcement purpose where the target supports that.

### Included enforcement pairs

Install one ban script and its matching release script under the fixed
names `activeban-ban` and `activeban-release`.

| Pair suffix | Target | Behaviour | TTL / persistence notes |
|---|---|---|---|
| `log` | none | Appends the intended action to a log. Safe default for first setup. | No network effect. Log path can be overridden with `ACTIVEBAN_FW_LOG`. |
| `asus` | ASUS router over SSH | Adds/removes an iptables `FORWARD` MAC DROP rule. | Router rules may persist across daemon restarts; TTL and removal are daemon-driven. Verify AiMesh and reboot behaviour on the actual router. |
| `flint` | OpenWrt over SSH | Adds/removes a MAC in the nftables set `inet activeban quarantine`. | Passes TTL to nft as an element timeout as well. The dedicated table/set/chain must be created first and recreated after reboot; see the script header. |
| `wifi` | OpenWrt hostapd over SSH | Adds/removes a MAC in hostapd's deny ACL and deauthenticates on ban. | Runtime-only: hostapd restart clears it. Applies only to clients of that AP. |
| `webhook` | any HTTP endpoint | POSTs a JSON event (`action`, `mac`, `ip`, `ttl_seconds`) to a configured URL. The far end decides what a ban means: a Home Assistant automation switching a smart plug off, a managed switch API, a ticket for a human. | The far end holds the state; TTL and release are daemon-driven. HTTP status ≥ 400 counts as failure. Guard the URL: it holds ban power. |
| `template` | custom | Argument-checked starting point that deliberately exits `1` until implemented. | Replace the placeholder with a real, idempotent action. |

---

## 5. Configuration reference

### `policy.json`

| Key | Meaning |
|---|---|
| `do_not_block` | MAC addresses refused for every role. |
| `cooldown_hours` | Cooldown after an LLM or human release. |
| `default_ttl_seconds` | Ban lifetime when an event/manual ban does not supply one. |
| `min_ttl_seconds`, `max_ttl_seconds` | Clamp applied to every supplied TTL (defaults 60 and 604800). A detector cannot create a near-zero or effectively permanent ban. |
| `flap_threshold` | Number of releases after which a device is held for human judgement. |
| `ban_cmd`, `release_cmd` | Enforcement executable paths. |
| `role_users` | Map of local usernames to `machine` or `llm`. Root is always `human`. |
| `socket_group` | Group allowed to connect to the Unix socket. |
| `trigger_classes` | Map of detector trigger names to severity classes: `test` (canary only), `normal`, `high`, or `manual`. |
| `lang` | Language of human-facing notification texts, and of the `reason` field the LLM returns: `"ja"` or `"en"` (default `"en"`; may also be set in `llm.json`). The review prompt itself is maintained in English only — the configured language is passed to the LLM as the output language for `reason`, instead of translating the instructions. Machine-readable log events and keys stay English either way. |

### Notification and LLM files

`nextcloud.json`:

```json
{"base_url": "https://nextcloud.example", "user": "...", "password": "...", "token": "talk-room-token"}
```

Example files are included under `examples/` (`policy.example.json`,
`nextcloud.example.json`, `llm.example.json`, `openai.key.example`). Copy each to its real name in the repository root, fill it
in, and run `deploy.sh`: real filenames are listed in `.gitignore`, and
the deploy script installs the secret files to `/etc/activeban/` with
owner `root:<reader>` and mode `640` (`nextcloud.json` is read by the
daemon user, the other two by the verification user).

If this file is absent, Talk notification is disabled. If delivery fails,
messages are appended to the spool (`/var/lib/activeban/spool.jsonl` by
default) and retried on a later notification/flush.

`llm.json`:

```json
{"api_key_file": "/etc/activeban/openai.key", "model": "gpt-4o-mini"}
```

The verification service reads the API key from `api_key_file`, polls the
daemon for pending machine bans, and sends its verdict through the socket.
If the LLM call fails, the ban remains in place. Optional keys:
`lang` (overrides the policy language), `profiles_file` (path to the
device profiles file, below).

`device_profiles.json`:

The device table the review compares against (see "Event context"
above). Place the real file next to `deploy.sh` (it is listed in
`.gitignore` — it contains the home's device inventory) and the deploy
script installs it to `/etc/activeban/` for the verification user.
Build a skeleton from an existing MAC→name registry with
`examples/make_device_profiles.py`, then fill in `expected` by hand.
Format: an object keyed by MAC (a list of row objects also works):

```json
{"AA:BB:CC:DD:EE:FF": {"name": "...", "type": "bulb", "vendor": "...",
  "ip": "192.168.1.50", "expected": "Destinations: ... Volume: ... Never: ...",
  "notes": "..."}}
```

For each pending ban the verification loop resolves the profile in
this order — MAC exact match, then registered `ip` match, then
registered `name` normalized exact match — and reports how it matched
as `identity_source`. If nothing matches, it passes up to five
candidate rows (same OUI prefix or similar name) for the LLM to infer
from; the review prompt treats inferred identity as weak evidence.
The loop also attaches the device's ban/release history (kept by the
daemon, most recent 20 events) as counts plus the last few entries.
A verdict may set `"history_based": true` when it releases on the
basis of a repeated human-release pattern; the daemon then marks the
release notification with a warning asking the human to confirm.

Reports may carry the device identifiers as one object
(`"device": {"mac": ..., "ip": ..., "name": ...}` in the JSON-stdin
form, or `--name` on the CLI). A report whose MAC cannot be
determined is **not** banned: the daemon logs `report_unresolved`,
notifies the human, and returns
`{"ok": false, "error": "identity unresolved: no mac to enforce"}`.

### Main environment variables

| Variable | Default |
|---|---|
| `ACTIVEBAN_POLICY` | `/etc/activeban/policy.json` |
| `ACTIVEBAN_STATE` | `/var/lib/activeban/state.json` |
| `ACTIVEBAN_LOG` | `/var/log/activeban.log` |
| `ACTIVEBAN_SOCK` | `/run/activeban/activeban.sock` |
| `ACTIVEBAN_NC_CONF` | `/etc/activeban/nextcloud.json` |
| `ACTIVEBAN_LLM_CONF` | `/etc/activeban/llm.json` |
| `ACTIVEBAN_SPOOL` | `/var/lib/activeban/spool.jsonl` |
| `ACTIVEBAN_PROFILES` | `/etc/activeban/device_profiles.json` |
| `ACTIVEBAN_TARGET_CONF` | `/etc/activeban/fw-target.conf` (enforcement examples) |

---

## 6. First-run checklist

Do not connect a real detector and a real router at the same time on the
first attempt. Stage it:

1. Install the **log** enforcement pair and confirm `policy.json` points to
   it.
2. Put one sacrificial test MAC in the normal blockable set and one router
   or server MAC in `do_not_block`.
3. Start `activeban.service`; the verify service can wait until the basic
   report path works.
4. As root, confirm a protected MAC is refused:

   ```sh
   activeban.py ban <protected-MAC>
   ```

   Check that the printed JSON has `"ok": false`.
5. Submit a test event **as `qdetect`**, not as root:

   ```sh
   sudo -u qdetect activeban.py report <test-MAC> \
     --ip <test-IP> --trigger behavior --reason "install smoke test" \
     --ttl 60
   ```

   Check for `"ok": true`, then inspect `activeban.py status` and the log
   enforcement file (`/var/log/activeban-fw.log` by default).
6. Confirm the test ban is released after the TTL, or release it as root.
7. Replace the log pair with one real enforcement pair. Repeat the same
   test and verify the state on the router/AP itself, not only in
   activeban's status.
8. Test a deliberate enforcement failure (for example, a temporarily wrong
   target host in a staging configuration) and confirm the report returns
   `"ok": false` and no ban is recorded.
9. Only then connect the production detector, preferably through the JSON
   or SSH forced-command interface above.

This sequence separates the four common failure points — account/role,
socket access, daemon policy, and router enforcement — so the first setup
does not have to debug all of them at once.

---

## 7. Canary test probe (end-to-end check without opening a hole)

A dedicated test URL served by a new listener would add attack surface just
to test the pipeline. activeban's canary needs **no server at all**: the
probe is a DNS name under the RFC 2606 `.invalid` TLD, which never
resolves and is never registered anywhere.

### The probe

```text
canary.activeban.invalid
<test-id>.canary.activeban.invalid      (optional label, e.g. a date or run id)
```

From a test device, trigger it in any way that issues a DNS query through
the house resolver — for example opening `http://canary.activeban.invalid/`
in a browser, or:

```sh
nslookup canary.activeban.invalid
```

The lookup fails (NXDOMAIN). That is expected: detection happens at the
DNS query, before any HTTP connection exists.

### Detector rule

Wherever DNS queries are already observed (for example a Pi-hole FTL
reader such as dns_watch), add one exact rule, separate from any
dangerous-signal screening:

- query name is `canary.activeban.invalid` or ends with
  `.canary.activeban.invalid`;
- submit one report with:
  - `trigger`: `"canary"`
  - `ttl`: `300` (short, so even a `keep` verdict self-heals in minutes)
  - `reason`: `"canary test probe"`
  - `evidence`: `{"canary_domain": "<full query name>", "test_id": "<first label, if any>"}`

The `canary_domain` evidence field matters: the verification prompt only
treats a probe as a deliberate test when the structured `trigger` set by
detector code is `canary` **and** this field matches the canary suffix.
A device cannot turn a real detection into a "test" by putting the word
canary in a reason string.

### Semantics of the `test` class

`policy.json` maps the trigger to a dedicated class:

```json
"trigger_classes": {"canary": "test", "...": "..."}
```

- A release (LLM verdict or human) of a `test`-class ban sets **no
  cooldown** and does not count toward the flap threshold, so the probe
  can be re-run immediately — a health check that locks itself out for
  24 hours after one success is not a health check. A canary report is
  likewise not refused by an existing cooldown from another class
  (a human hold still refuses it).
- Everything else is unchanged: protected MACs are still refused, the
  ban still goes through the real enforcement pair, Talk notifications
  still fire, and the LLM still performs the post-ban verification
  (for a matching canary it is instructed, on the trusted system-prompt
  side, to release).

### Procedure and limits

1. Run the first probes with the **log** enforcement pair. Any blockable
   device that can issue a DNS query works as the probe device.
2. Confirm the full loop in order: DNS query → report accepted → ban
   logged → Talk ban notice → LLM verdict release → Talk release notice.
3. Re-run the probe immediately and confirm it is accepted again
   (no cooldown refusal in the response JSON).
4. Repeat once with the real enforcement pair and a sacrificial device,
   and verify the state on the router/AP itself.
5. Limits: the probe device must actually use the observed resolver —
   a client doing DNS-over-HTTPS to an outside resolver bypasses the
   DNS observation point and the probe will not fire. A device that
   cannot issue an arbitrary DNS query (most IoT appliances) cannot
   probe by itself; probe from a general-purpose device instead.
