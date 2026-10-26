# Stage 7 Deployment Evidence Record

**Status:** NOT RUN — complete this record only from an authorized isolated lab or intended deployment network.  
**Normative candidate:** NetOS `3b461036147027b5cec5bfdc7f43d3af410e6505`  
**Core candidate:** `d29c3a71bc07a28365186df4994d85ca048e41bc`

Do not fill PASS from source inspection or hosted CI. Attach raw command output and PCAPs to a restricted evidence location; do not commit secrets, private keys, customer addresses, or unredacted sensitive captures to a public repository.

## 1. Run identity

| Field | Value |
|---|---|
| Operator / reviewer | TODO |
| UTC start / end | TODO |
| NetOS commit actually tested | TODO |
| Core commit actually tested | TODO |
| OS / kernel / FRR versions per router | TODO |
| Router identities (non-secret IDs) | TODO |
| Topology and WAN interfaces | TODO |
| Authenticated primary WAN locator and UDP port per peer | TODO |
| NAT / firewall / uRPF / routing mode | TODO |
| Evidence bundle location and access control | TODO |

## 2. Gate results

Use only **PASS**, **FAIL**, **BLOCKED**, or **NOT APPLICABLE**. Every PASS/FAIL must cite evidence IDs, timestamps, and a reviewer.

| Gate | Required evidence | Result | Evidence IDs / observations | Defect or exception |
|---|---|---|---|---|
| A — M1–M4 outer locator/port correctness | WAN PCAPs; decoded outer IPv6 source/destination and UDP ports for each message | NOT RUN | TODO | TODO |
| B — no derived-vIP interface/FIB/policy route | Before/during/after address, route, and rule snapshots | NOT RUN | TODO | TODO |
| C — OSPFv3 invariance | Before/during/after neighbor, LSDB, OSPFv3 route, and kernel route snapshots | NOT RUN | TODO | TODO |
| D — PMTU/fragmentation | Bidirectional boundary-size matrix, captures on both ends, ICMPv6 Packet Too Big behavior, loss/recovery result | NOT RUN | TODO | TODO |
| E1 — stateful firewall/ACL | Ingress/egress captures, effective rules, counters, new and established session results | NOT RUN | TODO | TODO |
| E2 — NAT/NAT66 (if present) | Redacted topology/config, captures on both sides, mapping lifetime and handshake result | NOT RUN | TODO | TODO |
| E3 — uRPF | Strict/loose/disabled modes where supported; counters and path outcomes | NOT RUN | TODO | TODO |
| E4 — asymmetric return path | Route/path evidence both directions, captures and session result | NOT RUN | TODO | TODO |
| E5 — firewall/ACL reload | Timestamped reload, counters, existing-session and fresh-handshake outcomes | NOT RUN | TODO | TODO |
| F1 — primary endpoint change | Before/after peer details, session/token invalidation and fresh handshake evidence | NOT RUN | TODO | TODO |
| F2 — daemon restart | Service logs, old-session handling, fresh handshake, OSPFv3 snapshots | NOT RUN | TODO | TODO |
| F3 — router reboot | Boot/service logs, recovery timing, stale-state checks, OSPFv3 snapshots | NOT RUN | TODO | TODO |

## 3. Evidence capture commands

Run on each relevant router, adapting interface names and filenames. Keep UTC timestamps with each artifact.

```sh
date -u --iso-8601=seconds
uname -a
ip -Version
sudo vtysh -c 'show version'
sudo tcpdump -ni <wan-interface> -s 0 -w <restricted-evidence-dir>/stage7-wan.pcap 'ip6 and udp'
```

Capture route/address state immediately before, during, and after the handshake/session:

```sh
ip -j -6 address show > <restricted-evidence-dir>/ipv6-addresses.json
ip -j -6 route show table all > <restricted-evidence-dir>/ipv6-routes.json
ip -j -6 rule show > <restricted-evidence-dir>/ipv6-rules.txt
sudo vtysh -c 'show ipv6 ospf6 neighbor' > <restricted-evidence-dir>/ospf6-neighbor.txt
sudo vtysh -c 'show ipv6 ospf6 database' > <restricted-evidence-dir>/ospf6-database.txt
sudo vtysh -c 'show ipv6 route ospf6' > <restricted-evidence-dir>/ospf6-routes.txt
sha256sum <restricted-evidence-dir>/*
```

Do not run disruptive NAT/firewall/uRPF changes or reboot tests on a production network without a written change window and rollback plan. Do not infer exact NLS CLI commands; use the commands supported by the exact installed candidate and record them verbatim.

## 4. PMTU matrix

Record both directions separately. Test the documented supported MTU plus boundary and oversize cases; do not assume a universal MTU.

| Direction | Inner packet size / MTU | Probe or workload | Capture evidence | Result / loss | PTB observed? | Silent black hole? |
|---|---:|---|---|---|---|---|
| A → B | TODO | TODO | TODO | NOT RUN | TODO | TODO |
| B → A | TODO | TODO | TODO | NOT RUN | TODO | TODO |
| A → B | TODO (boundary/oversize) | TODO | TODO | NOT RUN | TODO | TODO |
| B → A | TODO (boundary/oversize) | TODO | TODO | NOT RUN | TODO | TODO |

## 5. Failures and disposition

For each failure, record a minimal reproduction, exact candidate commits, expected vs observed behavior, relevant sanitized logs/PCAP packet numbers, severity, issue link, owner, and retest evidence.

| ID | Gate | Reproduction | Expected | Observed | Severity | Issue / disposition |
|---|---|---|---|---|---|---|
| TODO | TODO | TODO | TODO | TODO | TODO | TODO |

## 6. Independent review and release decision

- [ ] Reviewer is independent of the implementation and has reviewed both normative specs and candidate diffs.
- [ ] All gates A–F are PASS, or each unsupported combination is explicitly excluded from the deployment support matrix with rationale.
- [ ] Every failure has an accepted disposition and tracked follow-up.
- [ ] Evidence is tied to the exact NetOS/Core commits above (or the actual tested SHAs recorded in section 1).
- [ ] No private keys, credentials, or sensitive unredacted traffic are in public artifacts.
- [ ] Release owner records the final decision and date.

**Decision:** NOT ACCEPTED — pending evidence and independent review.  
**Reviewer / date / rationale:** TODO
