# My-project-1
#!/usr/bin/env python3
"""
Port scanner - a component of the audit tool.

The old scanner.py / syn_scanner.py / multi_scanner.py merged into one module.
They were three MODES of one scanner, not three tools:

  mode="connect"  - OS sockets (connect_ex). No root, works anywhere. Default.
  mode="syn"      - raw half-open SYN via Scapy. Needs root + Linux (the VM);
                    reads reply flags off the wire. scapy is imported lazily so
                    connect mode on the PC never drags it in.

Multi-target is built in: pass one host or many, it flattens every (ip, port)
into ONE thread pool. Open ports get a banner grab for service ID.

Callable as a library (for audit.py):   from scanner import scan
Or run standalone:                       python scanner.py   (asks target/ports/mode)

Targets rule: your own boxes or an authorized (bug-bounty scope) target only.
"""
import socket
import errno
import time
from concurrent.futures import ThreadPoolExecutor
from collections import defaultdict, Counter


# ---------- resolution ----------
def resolve(targets):
    """List of hostnames/IPs -> list of IPs. gethostbyname passes IPs through;
    unresolvable names are skipped with a note rather than crashing the run."""
    ips = []
    for t in targets:
        try:
            ips.append(socket.gethostbyname(t))
        except socket.gaierror:
            print(f"skip {t!r}: cannot resolve")
    return ips


# ---------- connect scan (no root) ----------
def scan_port(ip, port, timeout=3.0):
    """connect() scan of one port. Return 'open' | 'closed' | 'filtered'."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    result = s.connect_ex((ip, port))
    s.close()
    if result == 0:
        return "open"
    elif result == errno.ECONNREFUSED:
        return "closed"
    else:
        return "filtered"


# ---------- SYN scan (root + Linux; scapy imported lazily) ----------
def syn_scan(ip, port, timeout=2.0):
    """Half-open SYN scan of one port via Scapy. Needs root.
    Reply flags decide: 0x12 SYN/ACK=open (then RST), 0x14 RST/ACK=closed."""
    from scapy.all import IP, TCP, sr1, send, conf   # lazy - connect mode never pays for this
    conf.verb = 0
    reply = sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=timeout)
    if reply is None:
        return "filtered"
    if reply.haslayer(TCP):
        if reply[TCP].flags == 0x12:                       # SYN/ACK -> open
            send(IP(dst=ip) / TCP(dport=port, flags="R"), verbose=0)   # tear down half-open
            return "open"
        if reply[TCP].flags == 0x14:                       # RST/ACK -> closed
            return "closed"
    return "filtered"


# ---------- banner grab (service identification) ----------
def grab_banner(ip, port, timeout=3.0):
    """Connect, listen for a greeting; if silent, send an HTTP probe.
    Return the banner string, or None."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.settimeout(1.0)
        try:
            data = s.recv(1024)                    # phase 1: does it speak first? (SSH, FTP...)
        except socket.timeout:
            s.settimeout(timeout)
            s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")  # phase 2: silent -> ask (HTTP)
            data = s.recv(1024)
        return data.decode("utf-8", errors="replace").strip() if data else None
    except Exception:
        return None
    finally:
        s.close()


# ---------- orchestrator: flatten + one thread pool ----------
def scan(targets, ports, mode="connect", workers=200, timeout=3.0):
    """Scan every (ip, port) across all targets in one flat pool.
    Returns (open_by_host dict, Counter of states, resolved ip list)."""
    ips = resolve(targets)
    scan_fn = syn_scan if mode == "syn" else scan_port
    jobs = [(ip, port) for ip in ips for port in ports]

    def do(pair):
        ip, port = pair
        return ip, port, scan_fn(ip, port, timeout)

    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(do, jobs))

    open_by_host = defaultdict(list)
    states = []
    for ip, port, state in results:
        states.append(state)
        if state == "open":
            open_by_host[ip].append(port)
    return open_by_host, Counter(states), ips


# ---------- CLI (only runs when launched directly, not on import) ----------
if __name__ == "__main__":
    raw = input("Target(s) - host/IP, comma-separated: ").strip()
    targets = [t.strip() for t in raw.split(",") if t.strip()]
    if not targets:
        print("No target given.")
        raise SystemExit(1)

    ports_in = input("Ports (e.g. 1-100 or 80) [default 1-1024]: ").strip() or "1-1024"
    try:
        a, b = ports_in.split("-") if "-" in ports_in else (ports_in, ports_in)
        PORTS = range(int(a), int(b) + 1)          # +1 so the end port IS scanned
    except ValueError:
        print(f"Bad port range {ports_in!r} - use like 1-100 or 80.")
        raise SystemExit(1)

    mode = input("Mode - connect / syn [default connect]: ").strip().lower() or "connect"
    if mode not in ("connect", "syn"):
        print(f"Unknown mode {mode!r}; use 'connect' or 'syn'.")
        raise SystemExit(1)

    print(f"\nscanning {len(targets)} target(s) x {len(PORTS)} ports  [mode={mode}]")
    t0 = time.time()
    open_by_host, counts, ips = scan(targets, PORTS, mode=mode)
    dt = time.time() - t0

    for ip in ips:
        opens = sorted(open_by_host[ip])
        print(f"\n{ip}: {opens or 'none open'}")
        for port in opens:                          # banner-grab every open port
            print(f"    {port:<6} {ascii(grab_banner(ip, port))}")

    print(f"\ndone in {dt:.1f}s  {dict(counts)}")
