# Agent Capture, Blacklist, and Local DNS Implementation Plan

## Revision 2026-09-18 — LAN allowlist / WLAN default semantics

This revision supersedes any conflicting wording below. The authoritative
behavior is:

- A configured IP or CIDR is allowed through the LAN interface for every
  destination port and protocol; a port in legacy `TargetConfig` is metadata
  only and must not restrict firewall authorization.
- A configured URL/domain is resolved through the configured LAN DNS server on
  the LAN interface. Each returned A/AAAA address is granted an exact host
  route and destination allow rule on LAN for its TTL; no broader subnet is
  inferred.
- An IP/domain not authorized by the LAN config uses the lower-metric WLAN
  default and must not fall through to LAN.
- Blacklisted AI/agent addresses have highest precedence: they use WLAN and
  are dropped if they attempt LAN, even when an overlapping LAN rule exists.
- Manual mode never discovers or adds LAN targets automatically. If LAN DNS
  transport cannot be configured, configured LAN domains fail closed instead
  of falling back to WLAN DNS.

Implementation deltas to the original tasks:

1. Add `LAN_DOMAINS` and `LAN_DNS_SERVER(S)` configuration and validate them.
2. Change firewall target entries to destination-only all-port allows.
3. Add explicit LAN DNS-server routes and split-DNS routing on the LAN link.
4. Make route/firewall precedence `blacklist > LAN IP/domain answer > WLAN
   default` and add tests for `connect(10.0.0.1, 8000)` with no configured
   port.

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Capture agent connection metadata, enforce an IPv4/IPv6 target-interface blacklist, and resolve configured server domains from a local authoritative map.

**Architecture:** Extend the existing core configuration and desired-state model with parsed blacklist networks and local DNS records. Reconciliation passes blacklist entries to an interface-scoped firewall controller whose DROP rules precede connection-state and allow rules; the local resolver is consulted by policy/probing without changing the host resolver. Add a bounded capture command that launches a supplied agent command under `strace`, records only connect metadata, and can emit validated blacklist entries.

**Tech Stack:** Rust workspace, Tokio process management, serde/TOML, `ipnet`, Linux `iptables`/`ip6tables`, `strace` for metadata-only observation.

**Spec:** `docs/superpowers/specs/2026-09-18-agent-capture-local-dns-design.md`

## Global Constraints

- Capture stores process/hostname/address/port/interface/timestamp metadata only; never persist payloads, headers, cookies, or tokens.
- Blacklist enforcement is limited to `TARGET_INTERFACE` and must cover both IPv4 and IPv6.
- Blacklist DROP rules precede established/related and allow rules.
- Local DNS records are authoritative for configured domains and do not fall back to an upstream resolver.
- Unknown domains retain existing behavior.
- Existing `FALLBACK=drop` semantics remain unchanged.

### Task 1: Extend configuration with blacklist and local DNS records

**Files:**
- Modify: `crates/reverse-core/src/config.rs`
- Modify: `crates/reverse-core/src/lib.rs`
- Test: `crates/reverse-core/src/config.rs` tests
- Modify: `.env.example`
- Modify: `config/example.toml`

**Interfaces:**
- Add `Config.blacklist: Vec<ipnet::IpNet>` and `Config.local_dns: BTreeMap<String, Vec<IpAddr>>`.
- Add `Config::resolve_local_domain(&self, name: &str) -> Option<&[IpAddr]>` with lowercase/trailing-dot canonicalization.
- Parse `BLACKLIST_IPS` as comma-separated IP/CIDR values; bare IPv4/IPv6 become `/32` or `/128`.
- Parse `LOCAL_DNS_RECORDS` as semicolon-separated `domain=ip[,ip...]` records; malformed records are ignored consistently with existing `.env` parsing.

- [ ] Write parser and resolver tests for IPv4, IPv6, CIDR, duplicate records, case-insensitivity, and trailing dots.
- [ ] Run `cargo test -p reverse-core config` and verify new tests fail before implementation.
- [ ] Implement fields, parsers, canonicalization, and serde defaults.
- [ ] Update both example config files with safe syntax and comments.
- [ ] Run `cargo test -p reverse-core` and verify all pass.

### Task 2: Make policy and desired state consume local DNS and blacklist data

**Files:**
- Modify: `crates/reverse-core/src/model.rs`
- Modify: `crates/reverse-core/src/policy.rs`
- Modify: `crates/reverse-core/src/planner.rs`
- Modify: `crates/reverse-app/src/daemon.rs`
- Test: `crates/reverse-core/src/policy.rs` and `crates/reverse-app/tests/integration_tests.rs`

**Interfaces:**
- Add `DesiredState.blacklist: Vec<IpNet>` with a serde default.
- `PolicyEngine::from_config` stores the local DNS map.
- `PolicyEngine::decide` resolves configured domains locally and fills `Decision.resolved_ip` without calling libc/system DNS.
- `PolicyEngine::generate_desired_routes` emits host routes for local-DNS-resolved domain records using the existing candidate-interface/fallback logic.

- [ ] Add failing tests proving a mapped domain gets a resolved IP and no system lookup is attempted.
- [ ] Add failing tests proving mapped A/AAAA records create routes and unmapped domains preserve WAN behavior.
- [ ] Implement resolver-aware matching and route generation.
- [ ] Populate `DesiredState.blacklist` from `Config` in daemon apply flow.
- [ ] Run core and integration tests.

### Task 3: Enforce blacklist on target interfaces for IPv4 and IPv6

**Files:**
- Modify: `crates/reverse-linux/src/firewall.rs`
- Modify: `crates/reverse-app/src/reconcile.rs`
- Modify: `crates/reverse-app/src/daemon.rs`
- Test: `crates/reverse-linux/src/firewall.rs` and integration tests

**Interfaces:**
- Add `FirewallController::apply_egress_policy(interface, allowed_targets, blocked_targets)`.
- `blocked_targets` is `&[IpNet]`; IPv4 entries are sent to `iptables`, IPv6 entries to `ip6tables`.
- Dedicated chain ordering is: blacklist DROP, established/related ACCEPT, DHCP/DNS/ICMP allowances, explicit whitelist ACCEPT, final DROP.
- `cleanup_all` removes both IPv4 and IPv6 RT chains.

- [ ] Add pure rule-plan helpers so tests can assert family selection and ordering without mutating kernel state.
- [ ] Add failing tests for IPv4/IPv6 drop-before-established ordering and final-drop behavior.
- [ ] Implement command execution for both firewall families and make reconcile pass blacklist entries only to configured target interfaces.
- [ ] Ensure an interface with a blacklist but no current route still receives a chain when it is a configured target interface.
- [ ] Run firewall/unit/integration tests and a dry-run reconciliation.

### Task 4: Add metadata-only agent capture and promotion output

**Files:**
- Create: `crates/reverse-app/src/commands/capture.rs`
- Modify: `crates/reverse-app/src/commands/mod.rs`
- Modify: `crates/reverse-app/src/bin/reverse-tool.rs`
- Create: `scripts/capture-agents.sh` only if the CLI wrapper needs a shell entry point
- Test: `crates/reverse-app/src/commands/capture.rs`

**Interfaces:**
- Add `reverse-tool capture --label <agent> --duration <seconds> -- <program> <args...>`.
- Run the supplied command through `strace -f -e trace=connect` under a hard timeout; never pass shell text to `sh -c`.
- Parse only numeric destination address/port and process label into a redacted JSON report with timestamp and optional interface lookup.
- Add `--promote-blacklist <path>` to write validated `/32` or `/128` entries to a separate capture output file; promotion never expands to a broader CIDR automatically.

- [ ] Add parser tests with IPv4/IPv6 `connect()` fixtures and assertions that payload-like lines are ignored.
- [ ] Add timeout/error tests for missing `strace` and non-zero agent exit.
- [ ] Implement bounded process capture and JSON serialization.
- [ ] Run the command against harmless `true`/`sleep` fixtures first; only then capture configured agents with explicit timeouts.

### Task 5: Record the current agent/AI endpoint snapshot and verify end-to-end behavior

**Files:**
- Create: `config/agent-endpoints.blacklist.example`
- Modify: `.env.example`
- Test: `crates/reverse-app/tests/integration_tests.rs`

**Interfaces:**
- Snapshot entries include Agy (`cloudcode-pa.googleapis.com`, `daily-cloudcode-pa.googleapis.com`), Codex (`chatgpt.com`, `auth.openai.com`), OpenCode bridge/Zen (`api.cline.bot`, `opencode.ai`), Gemini, and Claude endpoints.
- Snapshot records hostname, address, address family, capture time, and a warning that CDN addresses rotate.

- [ ] Capture each agent with a short timeout and inspect reports for destination metadata only.
- [ ] Promote only observed addresses into the example blacklist file; do not print credentials.
- [ ] Add integration assertions that a failed configured target still yields DROP and that blacklist rules cannot select the target interface.
- [ ] Run `cargo fmt --check`, `cargo build --release`, and `cargo test --workspace`.
- [ ] Perform a dry-run apply and inspect IPv4/IPv6 chain plans before any live firewall mutation.
