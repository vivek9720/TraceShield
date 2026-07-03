# TraceShield

TraceShield is a local defensive cybersecurity toolkit for inspecting packet captures, indicator lists, detection rules, and firewall policy exports. It is designed for security engineers and administrators who need deterministic command-line analysis without sending artifacts to external services.

## Use Cases

- Summarize Ethernet, IPv4, TCP, UDP, and DNS activity from local PCAP files.
- Normalize IOC lists containing IP addresses, CIDR ranges, domains, URLs, and hashes.
- Match local packet metadata against allowlists and blocklists.
- Inspect Snort/Suricata-style rule subsets for consistency before deployment.
- Audit iptables, nftables, and key-value policy exports for duplicate or shadowed rules.

## Supported Inputs

- PCAP files with Ethernet link type, plus raw Ethernet frames.
- IOC text, CSV, or semicolon-delimited lists.
- IDS rules with action, protocol, endpoints, ports, direction, and common options such as `msg`, `content`, `sid`, `rev`, and `classtype`.
- Firewall exports using common iptables flags, nftables-style expressions, or simple key-value records.

## Architecture

- `core`: byte views, endian helpers, diagnostics, checksums, string utilities, time helpers, and IPv4/CIDR logic.
- `packet`: PCAP, Ethernet, IPv4, TCP, UDP, DNS parsing, metadata extraction, and summaries.
- `ioc`: IOC detection, normalization, duplicate detection, and packet metadata matching.
- `rules`: IDS-style parser, normalizer, validator, and metadata matching helpers.
- `policy`: firewall and policy parsers, ordering analysis, duplicate detection, and summaries.
- `tools`: small CLI front ends that call the reusable library.

## Build

```sh
cmake -S . -B build
cmake --build build
```

The project uses C++17 and the C++ standard library only.

## Tests

```sh
ctest --test-dir build --output-on-failure
```

## CLI

```sh
packetscan sample.pcap
iocmatch indicators.txt sample.pcap
rulecheck local.rules
policyaudit firewall.txt
```

All tools read local files only and produce deterministic text output.

## Developer QA

Robustness harnesses live under `fuzz/` and exercise the packet, IOC, IDS rule, and policy parsing paths. Seed inputs under `fuzz/corpus/` cover valid and near-valid examples so parser changes can be tested against realistic structures.

Example local Clang invocation:

```sh
CXX=clang++ CXXFLAGS="-g -O1 -fsanitize=fuzzer,address,undefined" OUT=out .clusterfuzzlite/build.sh
```

## Seed Corpus

- `packet_fuzzer`: compact PCAP examples for TCP, UDP/DNS, and malformed capture framing.
- `ioc_fuzzer`: IP, domain, URL, hash, CIDR, and malformed IOC lists.
- `rules_fuzzer`: simple, content, TCP, UDP, multi-rule, and malformed IDS inputs.
- `policy_fuzzer`: iptables allow/deny, nftables, multi-rule, and malformed policy inputs.

## Manual Review Checklist

- Confirm command output matches operational expectations for representative artifacts.
- Review parser boundary handling for every length-prefixed structure.
- Check normalization rules before using output in automated enforcement.
- Confirm local policy semantics match the target firewall environment.
- Keep new dependencies out unless they are essential and reproducible.
