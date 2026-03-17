# ft_nmap

A network port scanner written in C, inspired by Nmap. It discovers open, closed, and filtered ports on target hosts using multiple TCP/UDP scanning techniques with multi-threaded performance.

## Features

- **6 scan types**: SYN, NULL, FIN, XMAS, ACK, UDP
- **Host discovery** via ICMP ping before scanning
- **Multi-threaded scanning** with up to 250 parallel threads
- **Batch scanning** from a file of IP addresses
- **Customizable port ranges** (up to 1024 ports per scan)
- **Detailed output** with service name resolution and per-scan-type results

## Port States

| State | Description |
|-------|-------------|
| Open | Service actively accepting connections |
| Closed | Port responds but no service listening |
| Filtered | Blocked by firewall or packet filter |
| Unfiltered | Accessible but state undetermined (ACK scan) |
| Open\|Filtered | No response received, ambiguous state |

## Build

Requires `libpcap`, `pthread`, and `gcc`.

```bash
make        # build
make clean  # remove object files
make fclean # remove object files and executable
make re     # full rebuild
```

## Usage

```
sudo ./ft_nmap --ip <ADDRESS> [OPTIONS]
sudo ./ft_nmap --file <FILE> [OPTIONS]
```

Root privileges are required for raw socket operations.

### Options

| Option | Description |
|--------|-------------|
| `--ip <addr>` | Target IPv4 address or hostname |
| `--file <path>` | File containing target IPs (one per line) |
| `--ports <spec>` | Ports to scan (default: 1-1024). Range (`1-100`), list (`22,80,443`), or both |
| `--speedup <n>` | Number of threads (0-250, default: 0 = single-threaded) |
| `--scan <types>` | Scan types separated by `/` (default: all). Example: `SYN/UDP` |
| `--help` | Display usage information |

### Examples

```bash
# Default scan (all types, ports 1-1024)
sudo ./ft_nmap --ip 192.168.1.1

# Specific ports with threading
sudo ./ft_nmap --ip 192.168.1.1 --ports 22,80,443 --speedup 10

# SYN and UDP scans on a port range
sudo ./ft_nmap --ip 10.0.0.5 --ports 1-100 --scan SYN/UDP --speedup 5

# Batch scan from file
sudo ./ft_nmap --file ips-file --ports 80,443 --speedup 250
```

## Project Structure

```
├── main.c               # Entry point and argument parsing
├── ft_nmap.h            # Data structures and declarations
├── parser/              # Input parsing (IPs, ports, scan types, file reading)
├── network_mapper/      # Host discovery, threading, main scan loop
├── scanner/             # Raw packet crafting, TCP/UDP scans, response handling
├── output/              # Formatted result tables and statistics
└── Makefile
```

## How It Works

1. **Parse** command-line arguments and validate input
2. **Discover** if the target host is alive (ICMP Echo Request)
3. **Distribute** ports across worker threads
4. **Craft** raw IP/TCP/UDP packets with appropriate flags per scan type
5. **Capture** responses using libpcap with BPF filters
6. **Analyze** responses to determine port state per scan type
7. **Conclude** the most likely port state using a voting mechanism across scan results
8. **Display** results in a formatted table with service names

## Dependencies

- **libpcap** — packet capture and BPF filtering
- **pthread** — POSIX threads
- **Standard POSIX** — raw sockets, ICMP, network headers
