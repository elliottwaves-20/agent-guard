"""Network egress capture for the MCP sandbox (Stage 2).

The sandbox holds nothing worth stealing -- no mounts, no scanner keys -- so
its value is detection: does the server phone home when it starts or when its
tools are listed? A small capture container owns the network namespace and
runs tcpdump; the target joins it with `--network container:<capture>`, so
every packet the target sends passes the capture and nothing is attributed to
another container.

Afterwards the text output is evaluated without extra dependencies:

  * every DNS lookup must name an allowed host (a lookup alone can leak data,
    even when it fails),
  * every TCP connection (SYN) and every other UDP datagram must go to an
    address that an allowed name resolved to, on the allowed port, or to an
    allowed literal IP,
  * outgoing ICMP and anything unrecognised is reported.

The allow list defaults to the package registries the launch commands need
(PyPI, npm) on port 443. A capture that did not start, lost packets or was cut
short gives no verdict -- the sandbox fails closed.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
import os
import subprocess
import sys
import time
import uuid
from dataclasses import dataclass, field

# Alpine 3.24.2, tcpdump 4.99.6 -- pinned by digest and package version.
CAPTURE_DOCKERFILE = (
    "FROM alpine@sha256:294b683cb724975bec92580e1e685676bd4b50bda910ddb8c51d4cabeaec77e6\n"
    "RUN apk add --no-cache tcpdump=4.99.6-r1\n"
)
# DNS both ways, connection attempts (SYN without ACK, IPv4 and IPv6 without
# extension headers), every other UDP datagram and ICMP. Established TCP
# payload is not captured: the SYN already names the destination.
CAPTURE_FILTER = ("port 53"
                  " or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn)"
                  " or (ip6 and ip6[6] == 6 and ip6[53] & 0x12 == 0x02)"
                  " or (udp and not port 53) or icmp or icmp6")
DEFAULT_ALLOW = ("pypi.org", "files.pythonhosted.org", "registry.npmjs.org")
START_TIMEOUT = 20.0
DOCKER_TIMEOUT = 60
# Shared by every sandbox container. A named constant, not two argv items:
# SkillSpector 2.12.0 misreads the flag and its value inside a long argv list
# as an obfuscated text directive and then inspects the file only partially.
NO_CAPABILITIES = "--cap-drop=ALL"

_HOST = re.compile(r"^(?=.{1,253}$)[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)*$")
_PACKET = re.compile(r"^\d{2}:\d{2}:\d{2}\.\d+ (IP6?) (\S+) > (\S+?): (.*)$")
_QUERY = re.compile(r"^(\d+)\S*\s(?:\[[^\]]*\]\s)?(\w+)\? (\S+) \(")
_ANSWER = re.compile(r"(?:^|\s)(?:A|AAAA) ([0-9A-Fa-f:.]+?)(?=,|\s|$)")
_DROPPED = re.compile(r"^(\d+) packets? dropped by kernel")
# IPv6 housekeeping the kernel sends on its own.
_NDP = ("neighbor solicitation", "neighbor advertisement",
        "router solicitation", "router advertisement", "multicast listener")


class CaptureError(RuntimeError):
    """The capture container could not be started."""


def parse_allow(entries) -> set:
    """HOST or HOST:PORT (default 443) -> {(host, port)}; hosts are lower-cased."""
    allowed = set()
    for entry in entries:
        text = str(entry).strip().lower()
        host, sep, port = text.rpartition(":") if text.count(":") == 1 else (text, "", "")
        if not sep:
            host, port = text, "443"
        if not port.isdigit() or not 0 < int(port) < 65536:
            raise ValueError(f"--allow-host {entry!r}: port must be 1-65535")
        if not _HOST.match(host):
            raise ValueError(f"--allow-host {entry!r}: expected HOST or HOST:PORT "
                             "(a plain name or IPv4 address, no scheme or wildcard)")
        allowed.add((host, int(port)))
    return allowed


def private_address(address: str) -> bool:
    """True for loopback, RFC 1918 and other private addresses; False if not an address."""
    try:
        return ipaddress.ip_address(address).is_private
    except ValueError:
        return False


def dns_resolvers() -> set:
    """Extra resolver addresses from AGENT_GUARD_DNS_RESOLVERS (comma-separated IPs).

    On Linux the Docker bridge copies the host's DNS servers into the container,
    so the resolver may be a public address. Invalid entries are ignored."""
    found = set()
    for entry in os.environ.get("AGENT_GUARD_DNS_RESOLVERS", "").split(","):
        entry = entry.strip()
        if not entry:
            continue
        try:
            found.add(str(ipaddress.ip_address(entry)))
        except ValueError:
            print(f"[WARN] AGENT_GUARD_DNS_RESOLVERS: ignoring invalid address {entry!r}",
                  file=sys.stderr)
    return found


def resolver_address(address: str, resolvers: set) -> bool:
    """The sandbox's own resolver: a private address or one named in `resolvers`."""
    try:
        normal = str(ipaddress.ip_address(address))
    except ValueError:
        return False
    return private_address(address) or normal in resolvers


def _endpoint(text: str, v6: bool) -> tuple:
    if v6:
        host, dot, port = text.rpartition(".")
        return (host, int(port)) if dot and port.isdigit() else (text, None)
    parts = text.split(".")
    if len(parts) == 5 and parts[4].isdigit():
        return ".".join(parts[:4]), int(parts[4])
    return text, None


@dataclass
class Report:
    findings: list = field(default_factory=list)
    names: list = field(default_factory=list)
    complete: bool = True
    problem: str = ""


def analyse(lines, local_ips, allow: set) -> Report:
    """`local_ips`: the target's own address(es) -- one string or a collection."""
    local = {local_ips} if isinstance(local_ips, str) else set(local_ips)
    report = Report()
    allowed_hosts = {host for host, _port in allow}
    queries = {}    # (client port, DNS id) -> name
    resolved = {}   # address -> {names}
    started = False
    dropped = None

    def finding(text):
        if text not in report.findings:
            report.findings.append(text)

    def destination(kind, ip, port):
        names = resolved.get(ip, set())
        if (ip, port) in allow or any((name, port) in allow for name in names):
            return
        via = ", ".join(sorted(names)) or "no DNS lookup"
        finding(f"{kind} {ip}:{port} ({via})")

    resolvers = dns_resolvers()
    for raw in lines:
        line = raw.strip()
        if line.startswith("listening on"):
            started = True
            continue
        match = _DROPPED.match(line)
        if match:
            dropped = int(match.group(1))
            continue
        match = _PACKET.match(line)
        if not match:
            continue
        v6 = match.group(1) == "IP6"
        (src, sport), (dst, dport) = _endpoint(match.group(2), v6), _endpoint(match.group(3), v6)
        payload = match.group(4)

        if dst in local and sport == 53:
            answer = _QUERY.match(payload) or re.match(r"^(\d+)", payload)
            name = queries.get((dport, answer.group(1))) if answer else None
            if name:
                for address in _ANSWER.findall(payload):
                    resolved.setdefault(address, set()).add(name)
            continue
        if src not in local:
            continue  # replies and anything addressed to the target

        if dport == 53:
            exempt = resolver_address(dst, resolvers)  # only the sandbox's own resolver
            if not exempt:
                finding(f"DNS traffic to a public address: {dst}")
            query = _QUERY.match(payload)
            if query:
                name = query.group(3).rstrip(".").lower()
                queries[(sport, query.group(1))] = name
                if name not in report.names:
                    report.names.append(name)
                if name not in allowed_hosts:
                    finding(f"DNS lookup of a host that is not allowed: {name}")
            elif "Flags [" not in payload:
                finding(f"unrecognised traffic: {line}")
            elif exempt and not private_address(dst):
                # A configured public resolver is exempt for UDP queries, whose names
                # are judged above; DNS over TCP is not parsed, so it stays a finding.
                finding(f"TCP traffic to port 53 of a configured resolver: {dst}")
            continue
        if payload.startswith("Flags [S]"):
            destination("TCP connection to", dst, dport)
        elif payload.startswith("UDP,") and dport is not None:
            destination("UDP to", dst, dport)
        elif payload.startswith("ICMP6"):
            if not any(kind in payload for kind in _NDP):
                finding(f"ICMP6 to {dst} ({payload.split(',')[1].strip()})")
        elif payload.startswith("ICMP "):
            finding(f"ICMP to {dst} ({payload[5:].split(',')[0].strip()})")
        else:
            finding(f"unrecognised traffic: {line}")

    if not started:
        report.complete, report.problem = False, "the capture did not start"
    elif dropped is None:
        report.complete, report.problem = False, ("the capture summary is missing "
                                                  "(capture may have been cut short)")
    elif dropped:
        report.complete, report.problem = False, f"{dropped} packet(s) dropped by the capture"
    return report


def verdict(report: Report) -> int:
    print("\n" + "=" * 60)
    print("Network egress of the sandboxed target:")
    print(f"  DNS lookups: {', '.join(report.names) or 'none'}")
    if not report.complete:
        print(f"[BLOCK] NO VERDICT -- network capture incomplete: {report.problem}. "
              "Do NOT install. Re-run the scan.")
        return 2
    if report.findings:
        for item in report.findings:
            print(f"  - {item}")
        print(f"[BLOCK] {len(report.findings)} network destination(s) outside the allow "
              "list. A server that phones home on start is a red flag. If a destination "
              "is expected (the server's own API), review it and re-run with "
              "--allow-host HOST[:PORT].")
        return 1
    print("[OK] network: only allowed destinations were contacted.")
    return 0


# -- capture container ----------------------------------------------------------

def capture_image() -> str:
    digest = hashlib.sha256(CAPTURE_DOCKERFILE.encode("utf-8")).hexdigest()[:12]
    return f"agent-guard-net-capture:{digest}"


def ensure_capture_image() -> str:
    tag = capture_image()
    have = subprocess.run(["docker", "image", "inspect", tag],
                          capture_output=True, text=True, timeout=DOCKER_TIMEOUT)
    if have.returncode == 0:
        return tag
    print("  building network capture image (one-time)...")
    built = subprocess.run(["docker", "build", "-t", tag, "-"], input=CAPTURE_DOCKERFILE,
                           capture_output=True, text=True, timeout=600)
    if built.returncode != 0:
        raise CaptureError(f"capture image build failed: {built.stderr.strip()[-500:]}")
    return tag


def capture_run_argv(name: str, image: str) -> list:
    return ["docker", "run", "-d", "--name", name, "--network", "bridge",
            NO_CAPABILITIES, "--cap-add", "NET_RAW", "--read-only",
            "--security-opt", "no-new-privileges", "--pids-limit", "64",
            image, "tcpdump", "-i", "eth0", "-n", "-l", "-p", CAPTURE_FILTER]


def _is_address(text: str) -> bool:
    try:
        ipaddress.ip_address(text)
    except ValueError:
        return False
    return True


def _docker(*args, timeout=DOCKER_TIMEOUT) -> subprocess.CompletedProcess:
    return subprocess.run(["docker", *args], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=timeout)


class Capture:
    def __init__(self, name: str, local_ips):
        self.name = name
        self.local_ips = [local_ips] if isinstance(local_ips, str) else list(local_ips)

    @classmethod
    def start(cls) -> "Capture":
        image = ensure_capture_image()
        name = "agent-guard-net-" + uuid.uuid4().hex
        started = _docker(*capture_run_argv(name, image)[1:])
        if started.returncode != 0:
            raise CaptureError(f"capture container did not start: {started.stderr.strip()}")
        try:
            deadline = time.monotonic() + START_TIMEOUT
            while True:
                logs = _docker("logs", name)
                if "listening on" in (logs.stdout or "") + (logs.stderr or ""):
                    break
                if time.monotonic() > deadline:
                    raise CaptureError("tcpdump did not report 'listening' in time: "
                                       f"{(logs.stderr or '').strip()[-300:]}")
                time.sleep(0.2)
            ips = _docker("inspect", "-f",
                          "{{range .NetworkSettings.Networks}}"
                          "{{.IPAddress}} {{.GlobalIPv6Address}} {{end}}",
                          name).stdout.split()
            # Docker 29 renders an unset IPv6 address as the words "invalid IP".
            ips = [ip for ip in ips if _is_address(ip)]
            if not ips:
                raise CaptureError("capture container has no network address")
            return cls(name, ips)
        except BaseException:
            _docker("rm", "--force", name)
            raise

    def finish(self, allow: set) -> Report:
        """Stop tcpdump (it prints its summary on SIGTERM), evaluate, remove."""
        try:
            _docker("stop", "-t", "5", self.name)
            logs = _docker("logs", self.name)
        finally:
            self.remove()
        lines = (logs.stdout or "").splitlines() + (logs.stderr or "").splitlines()
        return analyse(lines, self.local_ips, allow)

    def remove(self):
        _docker("rm", "--force", self.name)
