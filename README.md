# quicvpn

**quicvpn** is a high-performance, low-latency, cross-platform VPN tunnel powered by QUIC and HTTP/3 camouflage. It is specifically designed to eliminate traffic signatures against Deep Packet Inspection (DPI) and Machine Learning (AI) traffic classifiers while maximizing network throughput.

---

## Key Features

* **Anti-DPI & Traffic Obfuscation**
  * **HTTP/3 Camouflage**: Disguises VPN traffic as standard HTTP/3 / QUIC HTTPS connections (`h3` ALPN).
  * **Multi-Mode Packet Padding**: Eliminates packet length distribution signatures via `block` (step alignment), `mtu` (fixed length), or `random` padding modes.
  * **Poisson Timing Shaping**: Introduces microsecond Poisson timing jitter to obfuscate packet inter-arrival distributions against AI/ML traffic classifiers.

* **Extreme Performance & Zero Allocation**
  * **Zero-Allocation Forwarding Engine**: Optimized `VSwitch` using `[6]byte` MAC table indexing and `RLock` double-checking for 0-allocation packet forwarding.
  * **O(1) Framing Scanner**: Zero-copy cursor sliding scanner to parse frames without redundant buffer moves.
  * **8MB UDP Socket Tuning**: Pre-tuned `SO_RCVBUF` / `SO_SNDBUF` (8MB) to eliminate kernel-level packet drops during 10Gbps+ bursty traffic.
  * **Ring-Batching AsyncPort**: Flush up to 64 frames in a single batch to reduce CPU context switches and syscall overhead.

* **Low Latency & High Reliability**
  * **QUIC Datagram Mode**: Transmits IP/Ethernet frames via QUIC Datagrams to eliminate Head-of-Line (HOL) blocking.
  * **Reed-Solomon FEC**: Forward Error Correction (e.g. 10:2 FEC) for instant **0ms loss recovery** over bad Wi-Fi / 5G / cross-border links.
  * **Multi-Connection Bonding**: Establishes multiple parallel QUIC connections to bypass single-UDP-socket ISP QoS rate limits and load balance throughput.

* **Cross-Platform Support**
  * Fully supports **Linux**, **Windows**, and **macOS** (Intel & Apple Silicon M1/M2/M3/M4).

---

## Installation & Quick Start

### 1. Download Pre-built Binaries
Download binaries for your OS/architecture from the [GitHub Releases](https://github.com/your-repo/quicvpn/releases) page.

### 2. Running the Server
Start a VPN server listening on port `4000` with 10:2 FEC and block padding:

```bash
./quicvpn_linux_amd64 -mode server -addr 0.0.0.0:4000 -psk "your_secret_key" -padding-mode block -fec-data 10 -fec-parity 2
```

### 3. Running the Client
Connect a client to the server using 4 parallel bonding connections and FEC:

```bash
# On Linux / macOS (Requires root / sudo for TAP interface):
sudo ./quicvpn_linux_amd64 -mode client -addr 1.2.3.4:4000 -psk "your_secret_key" -conns 4 -fec-data 10 -fec-parity 2 -padding-mode block

# On Windows (Run as Administrator):
quicvpn_windows_amd64.exe -mode client -addr 1.2.3.4:4000 -psk "your_secret_key" -conns 4 -fec-data 10 -fec-parity 2
```

---

## Command Line Flags Reference

| Flag | Default | Description |
| :--- | :--- | :--- |
| `-mode` | `""` | Mode of operation: `server` or `client` |
| `-addr` | `0.0.0.0:4000` | Server listen address or target server address |
| `-psk` | `quic_secret` | Pre-shared key for authentication |
| `-tap` | `tap0` | Name of the virtual TAP device |
| `-padding-mode` | `block` | Packet padding strategy: `block`, `mtu`, `random`, or `off` |
| `-padding-step` | `128` | Step size in bytes for `block` padding mode |
| `-mtu` | `1420` | Tunnel MTU payload size |
| `-datagram` | `true` | Enable QUIC Datagram mode for low-latency transmission |
| `-conns` | `1` | Number of parallel QUIC connections for load balancing (Client) |
| `-fec-data` | `0` | Number of FEC data shards (e.g. `10`, `0` to disable) |
| `-fec-parity` | `0` | Number of FEC parity shards (e.g. `2`, `0` to disable) |
| `-so-buf` | `8388608` | UDP Socket SO_RCVBUF / SO_SNDBUF size in bytes (8MB) |
| `-timing-shaping` | `true` | Enable microsecond Poisson timing shaping |
| `-version` | `false` | Show program version information and exit |

---

## Building from Source

Requires Go 1.22+.

### Build for Host OS:
```bash
go build -o quicvpn .
```

### Cross-Compile All 10 Target Binaries:
Run the provided build script:

```bash
chmod +x scripts/build.sh
./scripts/build.sh
```

Compiled binaries will be generated inside the `bin/` directory.

---

## License

Distributed under the [GPL-3.0 License](LICENSE).