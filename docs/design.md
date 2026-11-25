# activeban design notes

## Why this exists

Home networks are full of IoT devices whose firmware is rarely updated and
whose vendor clouds are attractive mass targets. A homeowner cannot staff a
SOC. The design goal is therefore: **machines respond at machine speed, an
LLM cleans up false positives, and the human judges last** — the same shape
as "build the harness first, then automate" applied to home defense.

Detection alone (alerts) does not scale for one person: alerts that require
immediate manual action at 3 a.m. are alerts that get ignored. Response has
to be automatic, which means the safety engineering has to live in the
*authority structure*, not in hoping the detector is accurate.

## Layers

1. **Detection** (external, read-only): watches DNS / traffic / logs and
   submits *events*. It can never order a ban directly; an event is a claim,
   not a command. Events carry a MAC snapshot — if the IP's owner changed
   between detection and execution, the ban must not fire on the new owner.
2. **Controller** (activeban daemon): owns the policy, the ban state, the TTLs,
   and every authority decision. It is the only component that talks to the
   enforcement commands.
3. **Enforcement** (external commands): applies/removes the actual block on
   a router or AP (iptables, nftables, hostapd deny lists, …). Deliberately
   dumb: it receives (MAC, IP, TTL) and returns an exit code.
4. **LLM verification**: a separate process running as its own user. After
   each machine ban it reviews the evidence and either releases the ban
   (false positive) or keeps it with a stated reason. Both outcomes are
   notified to the human.
5. **Human**: can ban, release, and clear holds at any time, from anywhere
   they can reach the CLI. The human is the only role that can release a
   human ban.

## The authority model in detail

The daemon accepts commands on a Unix socket and maps the peer UID
(`SO_PEERCRED`) to a role. Authority therefore comes from the OS account,
never from request parameters: a compromised detector can spam events but
cannot release anything; a prompt-injected LLM can at worst release machine
bans, never human bans, and every release it makes starts a cooldown that
prevents the detector from immediately re-banning the same device for the
same reason.

### Mandate

The daemon reads a policy file it cannot write (root-owned): the
do-not-block list, allowed trigger classes, cooldown and TTL parameters.
Neither the detector nor the LLM can widen the mandate; policy changes are
human work from a maintenance machine.

### Provenance

Every ban records its origin (detection rule, LLM verdict, human CLI), its
reason, and a request ID, in an append-only log. Anonymous or stale orders
are refused.

### Flap damping, not global caps

A tempting safety measure is capping simultaneous or hourly bans. It is the
wrong one: in a real mass-compromise (e.g. a vendor cloud breach), most of
the house may need banning at once, and a cap would disarm the system
exactly when it matters. The realistic failure mode is per-device
oscillation (machine bans → LLM releases → machine bans …), so damping is
per-device: cooldowns scoped by trigger class, and escalation to the human
when releases repeat.

### Kill authority

The daemon runs unprivileged and holds no network credentials beyond what
its enforcement commands need. Stopping it (or the host it runs on) stops
new bans; existing bans expire by TTL or by the enforcement layer's own
timeout if it has one (the OpenWrt example passes the TTL to nftables as an
element timeout, so expiry does not depend on the daemon being alive).

## Enforcement choices

- **Gateway firewall (iptables / nftables)**: stops WAN traffic completely.
  On a flat L2 network it cannot stop device-to-device traffic, which does
  not cross the gateway. Acceptable when the priority is "stop it talking
  to the internet".
- **Wi-Fi association refusal (hostapd deny + deauthenticate)**: the
  strongest option for wireless IoT — the device leaves the network
  entirely, lateral traffic included. Only works for clients of APs you
  control (e.g. OpenWrt); clients that roam to a vendor mesh node escape it.
- Rules persist on a router while a daemon may not; always pair persistent
  rules with an expiry mechanism (daemon TTL, nft element timeout, or a
  reconciler that re-asserts desired state).

## What activeban is not

- Not an IDS. Bring your own detection (DNS baselines, Suricata, Zeek,
  threat-intel matching, …). Garbage events in, garbage bans out — the LLM
  review and cooldowns limit the blast radius, they do not fix a bad
  detector.
- Not a WAF, and not an inbound IPS. A WAF inspects HTTP requests at a
  reverse proxy and rejects malicious requests one by one; an inbound
  IPS pattern (Suricata sees an attack from the internet → the
  perimeter firewall blocks the attacker's source IP) is the
  fail2ban / CrowdSec-bouncer shape. That problem is **IP-keyed**, and
  its failure modes are different from banning a LAN device: source
  IPs can be spoofed (UDP), shared (CGNAT, CDN and cloud egress —
  blocking one address can block many legitimate users), and ephemeral
  (per-IP history and cooldowns are worth little; the false-positive
  unit is signature × endpoint, not a device). activeban's identity,
  state and enforcement contract are MAC-keyed for devices you own.
  The *control pattern* (report → immediate block → post-review →
  TTL/cooldown) could be re-implemented for IP blocking, but that is a
  sibling system, not a configuration of this one — and where a
  CrowdSec-style stack already guards the public face, it already
  fills that role.
- Not a guarantee. A determined attacker already inside the LAN is out of
  scope; this is a first-response system for commodity IoT compromise.
