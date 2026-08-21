# Network Traffic Analyzer

A packet-capture and inspection tool built in C++, structured as the foundation
for a microservices-based traffic analysis pipeline (C++ capture/DPI service →
gRPC → Java/Spring Boot storage & query service, containerized with Docker,
deployed via Kubernetes/Helm).

Built to close specific skill gaps for Cyber Software Engineer roles: low-level
networking, C++, async I/O, deep packet inspection, service-to-service
communication, and container orchestration.

## Status: Phase 1 complete

- [x] **Phase 1** — Read a `.pcap` file, manually parse Ethernet / IPv4 / TCP / UDP headers
- [ ] Phase 2 — Live capture off a real interface (pcap++)
- [ ] Phase 3 — Async capture pipeline (Boost Asio)
- [ ] Phase 4 — Basic DPI: flag suspicious patterns
- [ ] Phase 5 — gRPC service contract, stream parsed data to a stub server
- [ ] Phase 6 — Java/Spring Boot gRPC server, persists to PostgreSQL
- [ ] Phase 7 — REST query API on the Java service
- [ ] Phase 8 — Dockerize both services
- [ ] Phase 9 — Helm chart, deploy to local Kubernetes cluster

## Why hand-parse headers instead of using a high-level library from day one?

Phase 1 deliberately parses Ethernet/IP/TCP/UDP headers by hand using raw
`libpcap`, rather than reaching for pcap++'s convenience layer immediately.
This is the part of a technical interview where "explain how a TCP header is
laid out on the wire" becomes something you can actually answer, because
you've done it byte-by-byte. Phase 2 introduces pcap++ for live-capture
ergonomics, but the header-parsing understanding carries forward.

## Building

Requires `cmake`, a C++17 compiler, and `libpcap-dev`.

```bash
# Debian/Ubuntu
sudo apt-get install cmake build-essential libpcap-dev

# macOS
brew install cmake libpcap
```

```bash
mkdir build && cd build
cmake ..
make
```

## Running

```bash
./build/pcap_reader data/sample.pcap
```

A sample `.pcap` file is included at `data/sample.pcap` — it contains a TCP
handshake (SYN/SYN-ACK/ACK) to port 443, a UDP/DNS-style packet, and one
packet to an unusual high port (31337) that Phase 4's DPI logic will later
flag as suspicious.

### Generating your own test pcap

If you have Python + scapy installed:

```python
from scapy.all import *
pkt = Ether()/IP(dst="8.8.8.8")/TCP(dport=443, flags="S")
wrpcap("data/custom.pcap", [pkt])
```

Or capture real traffic with `tcpdump` (requires root):

```bash
sudo tcpdump -i eth0 -w data/live_capture.pcap -c 50
```

## Project structure

```
network-traffic-analyzer/
├── CMakeLists.txt
├── src/
│   └── pcap_reader.cpp    # Phase 1: offline pcap file parser
├── data/
│   └── sample.pcap        # test fixture
├── include/                # (future: shared headers as project grows)
└── build/                  # cmake build output (gitignored)
```

## Roadmap detail

**Phase 2 (next):** swap `pcap_open_offline` for `pcap_open_live` (or migrate
to pcap++'s `PcapLiveDevice` for a cleaner live-capture API) to sniff a real
interface instead of reading a static file.

**Phase 4 (DPI):** flag patterns like unusual destination ports, malformed
header lengths, and high-frequency connection attempts from a single source
IP within a time window — the beginning of anomaly detection.

**Phase 5–6 (microservices split):** the C++ side becomes the capture/DPI
service; a Java/Spring Boot service receives parsed+flagged records over gRPC
and persists them to PostgreSQL, exposing a REST query API on top.
