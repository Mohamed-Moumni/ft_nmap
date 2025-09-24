# README — ft_nmap

> **ft_nmap** — a small re-implementation of parts of the `nmap` port scanner.  
> (Repository: Mohamed-Moumni/ft_nmap).

---

## Project overview
`ft_nmap` is a small project that re-implements parts of an `nmap`-style port scanner in C. The goal is educational: to understand how a port scanner works (socket usage, scan strategies, parallelism, parsing IP lists, etc.) and to produce a compact, self-contained scanner executable.

---

## Features (likely / intended)
- TCP port scanning over a range of ports.
- Processing multiple IPs (an `ips-file` is present in the repo).
- A small CLI binary (`ft_nmap`) implemented in C.
- Modular layout with `scanner`, `parser`, and `network_mapper` components.

> Note: This README is written from the repository structure and file names. For feature-level accuracy (available flags, scanning techniques implemented, threading model), inspect the source files (e.g. `main.c`, `ft_nmap.h`, and the `scanner/` folder).

---

## Repository structure (high level)
```
ft_nmap/                  # main sources
main.c
ft_nmap.h
Makefile
scanner/                  # scanning logic
parser/                   # argument / input parsing
network_mapper/           # mapping & output helpers
output/                   # example outputs
ips-file                  # example targets
.vscode/
```

---

## Requirements
- A POSIX environment (Linux, macOS).
- A C compiler (gcc / clang) supporting standard C.
- `make` (the repo contains a `Makefile`).
- Root privileges may be required for certain low-level scanning techniques (for raw sockets / SYN scans). If the implementation only uses regular TCP connects, root is not required. Check the source to confirm which methods are used.

---

## Build & install
A common build flow (typical for small C projects with a `Makefile`):

```bash
# clone repo
git clone https://github.com/Mohamed-Moumni/ft_nmap.git
cd ft_nmap

# build
make

# (optional) install to /usr/local/bin
# sudo make install
```

If `make` isn't present or the Makefile uses targets you want to inspect, open the `Makefile` to see the exact compile flags and targets.

---

## Usage
The exact CLI options depend on how the author implemented `main.c` and the parser. Common usage patterns for nmap-style clones:

```
./ft_nmap <target>                # scan a single host
./ft_nmap -p 1-1024 <target>      # scan port range
./ft_nmap -i ips-file             # read targets from a file
./ft_nmap -o output.txt           # save results to a file
```

Open `main.c` / `parser/` in the repo to see the exact options and examples.

---

## Examples
Example invocations (adjust to the actual flags implemented by the project):

```bash
# scan local machine common ports
./ft_nmap 127.0.0.1

# scan a list of hosts from ips-file
./ft_nmap -i ips-file

# scan a host for a port range
./ft_nmap -p 20-443 example.com
```

---

## Testing / Output
There is an `output/` folder in the repository which likely contains sample outputs produced by the scanner. Inspect it to see output format and sample runs.

---

## License
I couldn't find an explicit license file listed in the repository. If you intend to reuse or republish the code, please check the repo for a `LICENSE` file or ask the author for permission. If you want, I can scan the repo for a license file and add the appropriate badge & notice to this README.


