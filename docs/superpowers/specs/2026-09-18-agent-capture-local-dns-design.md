# Agent endpoint capture, blacklist, and local DNS design

## Authoritative routing semantics (2026-09-18)

The policy is LAN-allowlist/WLAN-default. A configured IP or CIDR is allowed
through the LAN interface for all ports and protocols. A configured URL/domain
is resolved through an explicitly configured LAN DNS server on the LAN link;
each returned A/AAAA address receives an exact, TTL-bound LAN host route and
destination allow rule. Any destination without a LAN authorization uses the
WLAN default and must not fall through to LAN. Blacklisted AI/agent addresses
take precedence over all LAN rules, are routed via WLAN, and are dropped on
LAN. The numeric WLAN route metric is lower than the LAN metric.

`LAN_DOMAINS` and `LAN_DNS_SERVER(S)` are required for dynamic LAN-domain
resolution. If LAN split-DNS cannot be configured, that domain resolution
fails closed; it never silently uses WLAN DNS. Manual mode does not infer new
LAN targets.

## Goal

Prevent AI-agent traffic from ever leaving through the configured target/server
interface while retaining normal WAN access, and allow manually configured
server domains to resolve from a local map without an upstream DNS lookup.

## Scope

The change covers:

1. Metadata-only observation of Agy, Codex CLI, and OpenCode connections.
2. A static blacklist of captured IPv4/IPv6 addresses and CIDRs.
3. Target-interface egress drops for blacklist entries.
4. A local authoritative domain-to-address map used by reverse-tool policy and
   probing.

Agent processes must be run with an explicit timeout. Capture output stores
process/hostname/address/port/interface/timestamp metadata only; packet payloads,
headers, cookies, and tokens are never persisted.

## Configuration model

Add a global blacklist collection to the configuration, populated from manual
CIDR/IP entries and from a capture report only after validation. Entries retain
hostname and capture timestamp as provenance in the report, but firewall rules
use only parsed IP networks.

Add static local DNS records with A and AAAA values. A configured record is
authoritative for the tool: a matching domain is resolved locally and is never
sent to an upstream resolver. Unknown domains retain the existing behavior and
are not implicitly added to the blacklist.

## Data flow

1. Capture runner starts an explicitly configured agent command under a timeout.
2. A metadata collector observes outbound connect events and, where available,
   DNS/TLS hostname metadata. It emits a redacted JSON report.
3. A promotion step validates addresses and writes selected entries to the
   blacklist configuration; capture never silently broadens a CIDR.
4. Reconciliation builds target-interface firewall chains. Blacklist DROP rules
   precede established/related and allow rules. IPv4 uses `iptables`, IPv6 uses
   `ip6tables`.
5. Policy and path probing consult local DNS records before any system resolver.

## Safety and fallback semantics

Blacklist enforcement is limited to `TARGET_INTERFACE`; it prevents fallback
through the server path without disabling AI access over the normal WAN. A
blacklisted address that is reached through a target route is dropped even when
the connection is already established. Existing `FALLBACK=drop` behavior remains
the rule for configured server targets.

The local DNS map is static/manual. It does not infer records from arbitrary
traffic, and an unresolved domain is not treated as a server target merely
because its name resembles one.

## Verification

Tests must cover configuration parsing, local DNS hit/miss and case handling,
IPv4/IPv6 blacklist rule generation and ordering, capture timeout/redaction, and
the invariant that a failed target path cannot select WAN for a configured drop
rule. A dry-run inspection must show the resulting blacklist and DNS records
without applying kernel state.
