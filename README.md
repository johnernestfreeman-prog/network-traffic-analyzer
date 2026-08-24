# Network Traffic Analyzer

A packet capture and inspection pipeline built in C++ and Java, streaming parsed traffic events from raw NIC capture through gRPC into a persisted, queryable REST API — containerized with Docker and orchestrated with Kubernetes/Helm.

**Live showcase:** https://johnernestfreeman-prog.github.io/network-traffic-analyzer/
**Companion server repo:** https://github.com/johnernestfreeman-prog/traffic-analyzer-server

Built to close specific skill gaps for Cyber Software Engineer roles: low-level networking, C++, async I/O, deep packet inspection, service-to-service communication via gRPC, and container orchestration.

## Status: all 9 phases complete

- [x] Phase 1 — Parse a `.pcap` file, manually decode Ethernet / IPv4 / TCP / UDP headers
- [x] Phase 2 — Live capture off a real interface (Npcap)
- [x] Phase 3 — Async capture pipeline (Boost.Asio)
- [x] Phase 4 — Deep packet inspection: flag suspicious patterns
- [x] Phase 5 — gRPC client, stream parsed events to the server
- [x] Phase 6 — Java/Spring Boot gRPC server, persists to PostgreSQL
- [x] Phase 7 — REST query API on the Java service
- [x] Phase 8 — Dockerize both services
- [x] Phase 9 — Helm chart, deploy the full pipeline to Kubernetes

## Architecture

```
 .pcap / live NIC
        |
        v
  [ Capture ]  libpcap / Npcap, hand-parsed headers
        |
        v
  [ Inspect ]  DPI - rule-based alerting (e.g. known-bad ports)
        |
        v
  [ Stream  ]  gRPC client, async via Boost.Asio  ---->  gRPC server (Java/Spring Boot)
                                                                |
                                                                v
                                                        [ Persist ]  PostgreSQL via Spring Data JPA
                                                                |
                                                                v
                                                        [ REST API ]  query stored packet events
```

Both services run identically across three environments — native, Docker (`--network host`), and Kubernetes (via Service DNS) — controlled by a `GRPC_SERVER_ADDR` environment variable that defaults to `localhost:50051` when unset.

## Tech stack

| Layer | Tools |
|---|---|
| Capture & networking | C++17, Boost.Asio, libpcap, Npcap, CMake |
| Transport | gRPC, Protocol Buffers |
| Server & persistence | Java 21, Spring Boot 4, Hibernate/JPA, PostgreSQL, Maven |
| Containers | Docker, multi-stage builds, Debian bookworm-slim |
| Orchestration | Kubernetes, Helm (Deployments, Services, Jobs, ConfigMaps, Secrets, PVCs) |

## Building and running

### Native (Windows, MinGW)

Requires `cmake`, a C++17 compiler, and `libpcap-dev` (or the Npcap SDK on Windows).

```
cmake -B build -S . -DCMAKE_BUILD_TYPE=Release
mingw32-make.exe -C build async_capture
./build/async_capture.exe --file data/sample.pcap --grpc
```

### Docker

```
docker build -f Dockerfile.async_capture -t async-capture .
docker run --rm --network host async-capture
```

The image regenerates its protobuf/gRPC C++ bindings inside the container at build time, using the container's own `protoc`/`grpc_cpp_plugin`, rather than shipping pre-generated bindings, to avoid protobuf version drift between host and container.

### Kubernetes (Helm)

```
cd helm-chart
helm install traffic-analyzer .
kubectl get pods
kubectl logs job/async-capture
```

The chart deploys PostgreSQL, the Java gRPC server, and the C++ capture client (as a one-shot Kubernetes Job) together, with the client reaching the server via its Kubernetes Service DNS name rather than localhost.

## Repo structure

```
src/                  C++ capture client, DPI engine, gRPC client
proto/                packet_event.proto - shared gRPC contract
data/                 sample.pcap for replay/testing
Dockerfile.async_capture
helm-chart/           Helm chart: postgres, server, async-capture Job
index.html            GitHub Pages showcase site
```

## Author

John Freeman — [GitHub](https://github.com/johnernestfreeman-prog) · [LinkedIn](https://linkedin.com/in/john-ernest-freeman-jr)
