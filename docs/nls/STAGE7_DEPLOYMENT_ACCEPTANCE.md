# Stage 7 Deployment Acceptance Checklist

Status: **OPEN — requires execution on the intended deployment network**

This checklist is for collecting evidence that hosted CI cannot provide. Do not mark a gate PASS from configuration inspection alone. Attach command output, packet captures, timestamps, router identities, software versions, and the exact candidate commit used.

## Test record

For every run record:

- NetOS commit and Core commit
- OS/kernel/FRR versions on each router
- Topology and WAN interfaces
- Router identities and authenticated primary WAN locators (redact private keys and credentials)
- UTC start/end times and test operator
- Exact commands and unedited output
- PCAP hashes and relevant packet numbers
- Expected result, observed result, PASS/FAIL, and defect references

## Gate A — M1–M4 outer locator correctness

1. Confirm each peer's authenticated primary WAN locator and advertised UDP port from the signed peer-details/RDR data.
2. Capture handshake traffic on each WAN interface:
   ```sh
   sudo tcpdump -ni <wan-interface> -s 0 -w stage7-handshake.pcap 'ip6 and udp'
   ```
3. Trigger a fresh handshake between the two routers and stop the capture.
4. Decode the capture and record outer IPv6 source, destination, UDP source port, and destination port for M1, M2, M3, and M4.
5. Verify each outer endpoint follows the normative authenticated WAN-locator rule; verify no derived `vip` is used as a routable outer source/destination.
6. Retain the capture securely; redact or restrict distribution of sensitive metadata before attaching it to a public issue.

**PASS criteria:** all four messages use the expected authenticated WAN locators and ports; no outer endpoint is the derived vIP; no unexpected legacy handshake format is accepted.

## Gate B — no derived-vIP interface or route

Before, during, and after a handshake/session, collect:

```sh
ip -j -6 address show > ipv6-addresses.json
ip -j -6 route show table all > ipv6-routes.json
ip -j -6 rule show > ipv6-rules.txt
```

Compare snapshots and identify every address/route delta. Confirm the derived vIP is not installed as an interface address, route, policy-routing selector, or next-hop. Do not treat an ordinary unrelated route change as a failure without attribution; retain the evidence and explain each delta.

**PASS criteria:** no derived-vIP interface address, FIB route, or policy-routing entry appears during the handshake/session lifecycle.

## Gate C — OSPFv3 invariance

On each relevant router, capture before, during, and after session activation/teardown:

```sh
sudo vtysh -c 'show ipv6 ospf6 neighbor'
sudo vtysh -c 'show ipv6 ospf6 database'
sudo vtysh -c 'show ipv6 route ospf6'
ip -j -6 route show table all
```

Compare the OSPFv3 adjacency state, LSDB, and route set. Attribute any change to an expected topology event or investigate it as a failure. Verify the derived vIP is not originated or redistributed into OSPFv3.

**PASS criteria:** no NLS-induced adjacency reset, no unintended LSDB advertisement for the derived vIP, and no NLS-induced route leak.

## Gate D — PMTU and fragmentation

Test the supported path MTU and representative inner packet sizes in both directions. Capture on both sides of the NLS path. Record whether packets are fragmented, dropped, or trigger Packet Too Big handling. Verify no silent black hole occurs at the documented supported MTU and confirm behavior at the configured boundary.

**PASS criteria:** documented MTU behavior is repeatable in both directions; oversize packets fail or recover according to the protocol's specified behavior, without silent persistent black holes.

## Gate E — NAT, firewall, uRPF, and asymmetric routing

Test separately with each production-relevant condition:

- Stateful firewall rules permitting only the intended transport/protocol traffic
- NAT or NAT66, if present in the actual deployment
- Strict and loose uRPF modes where applicable
- Symmetric and asymmetric forward/return paths
- ACL reloads and router firewall reloads during an established and a new session

Capture both ingress and egress traffic and record conntrack/firewall counters where available.

**PASS criteria:** behavior matches the documented deployment support matrix; no unauthorized bypass, unintended route leak, or unexplained session black hole occurs. Explicitly mark unsupported combinations rather than assuming they work.

## Gate F — endpoint change and restart recovery

Test a controlled primary WAN endpoint change, a daemon-only restart, and a router restart as separate cases. For each case record whether peer details are refreshed, old session/token state is invalidated or expires as specified, fresh handshakes succeed, and ordinary OSPFv3 adjacencies/routes remain stable.

**PASS criteria:** recovery follows the specified state machine and timing bounds, stale session state is not reused, and routing remains stable.

## Final acceptance

Do not mark Stage 3 frozen until:

- The cross-repository normative spec review is accepted.
- Gates A–F have evidence attached from the intended network, or each unsupported scenario is explicitly excluded from the deployment support matrix.
- All failures have tracked defects and a documented disposition.
- The evidence identifies the exact NetOS and Core commits tested.

Hosted CI and the FRR startup/shutdown invariance job are necessary evidence, but they do not by themselves satisfy these deployment gates.
