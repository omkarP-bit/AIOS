"""Network observer — ``/proc/net/tcp{,6},udp{,6},unix``.

Socket tables give local endpoints and state. Remote peers come from
``/proc/net/route`` (no gateway) and the TCP/UDP tables. Nothing here opens a
socket or touches iptables.
"""

from __future__ import annotations

import socket
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from aios.observers.paths import read_text, resolve_under

# /proc/net/tcp st column, hex.
TCP_STATES = {
    "01": "ESTABLISHED",
    "02": "SYN_SENT",
    "03": "SYN_RECV",
    "04": "FIN_WAIT1",
    "05": "FIN_WAIT2",
    "06": "TIME_WAIT",
    "07": "CLOSE",
    "08": "CLOSE_WAIT",
    "09": "LAST_ACK",
    "0A": "LISTEN",
    "0B": "CLOSING",
}

SOCKET_FAMILIES = ("tcp", "tcp6", "udp", "udp6")

#: Inode -> pid map built from /proc/*/fd. Used to attribute a socket to a
#: process, which is the whole point of showing connections to a user.
# "unix" is a transport in its own right. It was previously reported as "tcp",
# which put local sockets into the TCP row of by_transport and made a machine
# with many unix sockets look like it had hundreds of TCP connections.
NetworkTransport = Literal["tcp", "tcp6", "udp", "udp6", "unix"]


class NetworkConnection(BaseModel):
    model_config = ConfigDict(extra="forbid")

    family: NetworkTransport
    local_address: str
    local_port: int
    remote_address: str | None = None
    remote_port: int | None = None
    state: str | None = None
    inode: int | None = None
    uid: int | None = None
    pids: list[int] = Field(default_factory=list)
    process_names: list[str] = Field(default_factory=list)
    tx_queue: str | None = None
    rx_queue: str | None = None
    retransmit_count: str | None = None


class NetworkSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    total: int
    by_state: dict[str, int] = Field(default_factory=dict)
    by_transport: dict[str, int] = Field(default_factory=dict)
    attributed: int = Field(default=0, description="Sockets mapped to a PID")
    unattributed: int = Field(default=0)
    truncated: bool = False


class NetworkConnections(BaseModel):
    model_config = ConfigDict(extra="forbid")

    connections: list[NetworkConnection]
    summary: NetworkSummary
    skipped_files: list[str] = Field(default_factory=list)


def _hex_to_ip_v4(hex_addr: str) -> str:
    """/proc stores IPv4 as little-endian hex per 32-bit word."""
    if len(hex_addr) != 8:
        return "0.0.0.0"
    return socket.inet_ntoa(bytes.fromhex(hex_addr)[::-1])


def _hex_to_ip_v6(hex_addr: str) -> str:
    """/proc stores IPv6 as four little-endian 32-bit words.

    Note the word order: each 32-bit word is byte-swapped individually, which
    is why ::1 appears as ...01000000 rather than ...00000001.
    """
    if len(hex_addr) != 32:
        return "::"
    words = [hex_addr[i : i + 8] for i in range(0, 32, 8)]
    raw = b"".join(bytes.fromhex(w)[::-1] for w in words)
    return socket.inet_ntop(socket.AF_INET6, raw)


def parse_addr(spec: str, family: str) -> tuple[str, int]:
    """Parse ``0100007F:1F90`` into ``('127.0.0.1', 8080)``."""
    hex_addr, _, hex_port = spec.partition(":")
    try:
        port = int(hex_port, 16)
    except ValueError:
        port = 0
    if family.endswith("6"):
        return _hex_to_ip_v6(hex_addr), port
    return _hex_to_ip_v4(hex_addr), port


def parse_socket_table(text: str, family: str) -> list[NetworkConnection]:
    """Parse a /proc/net/{tcp,udp} table body (header line excluded)."""
    out: list[NetworkConnection] = []
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 10:
            continue
        # Column layout: 0=sl 1=local 2=remote 3=st 4=tx:rx 5=tr:when
        #                6=retrnsmt 7=uid 8=timeout 9=inode
        try:
            local_addr, local_port = parse_addr(parts[1], family)
            remote_addr, remote_port = parse_addr(parts[2], family)
        except (ValueError, OSError):
            continue
        if parts[2].partition(":")[0] == "00000000":
            remote_addr, remote_port = None, None
        try:
            inode = int(parts[9])
        except (ValueError, IndexError):
            inode = None
        try:
            uid = int(parts[7])
        except (ValueError, IndexError):
            uid = None
        tx_rx = parts[4] if len(parts) > 4 else None
        tr_when = parts[5] if len(parts) > 5 else None
        out.append(
            NetworkConnection(
                family=family,  # type: ignore[arg-type]
                local_address=local_addr,
                local_port=local_port,
                remote_address=remote_addr,
                remote_port=remote_port,
                state=TCP_STATES.get(parts[3].upper(), parts[3])
                if family.startswith("tcp")
                else None,
                inode=inode,
                uid=uid,
                tx_queue=tx_rx.partition(":")[0] if tx_rx else None,
                rx_queue=tx_rx.partition(":")[2] if tx_rx else None,
                retransmit_count=tr_when.partition(":")[0] if tr_when else None,
            )
        )
    return out


def parse_unix_table(text: str) -> list[dict[str, object]]:
    """Parse /proc/net/unix. Names are attacker-controllable; we keep them as
    data and never interpret them."""
    out: list[dict[str, object]] = []
    # Columns: 0=Num 1=RefCount 2=Protocol 3=Flags 4=Type 5=St 6=Inode 7=Path
    for line in text.splitlines()[1:]:
        parts = line.split()
        if len(parts) < 7:
            continue
        out.append(
            {
                "num": parts[0].rstrip(":"),
                "ref_count": parts[1],
                "protocol": parts[2],
                "flags": parts[3],
                "type": parts[4],
                "state": parts[5],
                "inode": parts[6],
                # An abstract socket has an @-prefixed name and no filesystem
                # path; it is not a readable file and must not be treated as one.
                "path": parts[7] if len(parts) > 7 else None,
            }
        )
    return out


def build_inode_map(proc_root: Path) -> dict[int, tuple[list[int], list[str]]]:
    """Map socket inode -> (pids, comms) by scanning /proc/*/fd.

    This is the expensive part (one readlink per fd), so callers can skip it.
    """
    mapping: dict[int, tuple[list[int], list[str]]] = {}
    root = resolve_under(proc_root)
    try:
        pids = [entry for entry in root.iterdir() if entry.name.isdigit()]
    except OSError:
        return mapping

    for pid_dir in pids:
        try:
            pid = int(pid_dir.name)
        except ValueError:
            continue
        fd_dir = pid_dir / "fd"
        try:
            fds = list(fd_dir.iterdir())
        except OSError:
            continue
        for fd in fds:
            try:
                target = fd.resolve()
            except (OSError, ValueError):
                continue
            if not target.name.startswith("socket:["):
                continue
            try:
                inode = int(target.name[len("socket:[") : -1])
            except ValueError:
                continue
            pids_list, names = mapping.get(inode, ([], []))
            if pid not in pids_list:
                pids_list.append(pid)
            if len(names) < 1:
                try:
                    comm = read_text(pid_dir / "comm", 256).strip()
                except OSError:
                    comm = ""
                if comm:
                    names.append(comm)
            mapping[inode] = (pids_list, names)
    return mapping


class NetworkObserver:
    def __init__(self, proc_root: Path) -> None:
        self.proc_root = Path(proc_root)

    def _read_table(self, name: str) -> tuple[str | None, str]:
        try:
            return read_text(resolve_under(self.proc_root, "net", name)), ""
        except OSError:
            return None, name

    def collect(
        self,
        include_unix: bool = False,
        attribute_pids: bool = True,
        limit: int = 200,
        states: list[str] | None = None,
        listening_only: bool = False,
    ) -> NetworkConnections:
        connections: list[NetworkConnection] = []
        skipped: list[str] = []

        for family in SOCKET_FAMILIES:
            text, missing = self._read_table(family)
            if text is None:
                skipped.append(missing)
                continue
            connections.extend(parse_socket_table(text, family))

        if include_unix:
            text, missing = self._read_table("unix")
            if text is None:
                skipped.append(missing)
            else:
                for entry in parse_unix_table(text):
                    connections.append(
                        NetworkConnection(
                            family="unix",
                            local_address=str(entry.get("path") or "unix"),
                            local_port=0,
                            state=str(entry.get("state")),
                        )
                    )

        if states:
            wanted = {s.upper() for s in states}
            connections = [c for c in connections if (c.state or "").upper() in wanted]
        if listening_only:
            connections = [c for c in connections if c.state == "LISTEN"]

        attributed = 0
        if attribute_pids and connections:
            inode_map = build_inode_map(self.proc_root)
            for conn in connections:
                if conn.inode is None:
                    continue
                found = inode_map.get(conn.inode)
                if found:
                    conn.pids, conn.process_names = found[0], found[1]
                    attributed += 1

        by_state: dict[str, int] = {}
        by_transport: dict[str, int] = {}
        for conn in connections:
            by_transport[conn.family] = by_transport.get(conn.family, 0) + 1
            key = conn.state or "NONE"
            by_state[key] = by_state.get(key, 0) + 1

        truncated = len(connections) > limit
        summary = NetworkSummary(
            total=len(connections),
            by_state=by_state,
            by_transport=by_transport,
            attributed=attributed,
            unattributed=len(connections) - attributed,
            truncated=truncated,
        )
        return NetworkConnections(
            connections=connections[:limit], summary=summary, skipped_files=skipped
        )
