"""Generate the synthetic benign canary capture (PRD Goal 5, §10 fixture strategy).

The benign canary is *synthesized* rather than sourced so that "zero labels" is a
known-correct expectation. A real-world capture believed benign may legitimately trip
an admitted rule, which would make the canary flaky and its failures ambiguous.

Contains no real hosts, addresses, or payloads — only RFC 1918 addresses and trivial
HTTP. Output is byte-deterministic: timestamps, IP IDs, and sequence numbers are all
fixed, so the fixture can be regenerated and byte-compared.

Verified against Zeek 8.0.4 (`zeek -C -D -r benign.pcap`): parses cleanly and reports
two connections in conn.log.

Usage:
    python tests/fixtures/make_canary.py [output.pcap]
"""

import struct
import sys

# TCP flags
SYN = 0x02
ACK = 0x10
PSH = 0x08
FIN = 0x01

LINKTYPE_ETHERNET = 1
PCAP_MAGIC = 0xA1B2C3D4
SNAPLEN = 65535
BASE_TS = 1700000000.0

SRC_MAC = b"\x02\x00\x00\x00\x00\x01"
DST_MAC = b"\x02\x00\x00\x00\x00\x02"

# (client port, server port, client IP, server IP)
FLOWS = [
    (49152, 80, "10.0.0.5", "10.0.0.200"),
    (49153, 443, "10.0.0.6", "10.0.0.201"),
]


def checksum(data: bytes) -> int:
    """Internet checksum (RFC 1071)."""
    if len(data) % 2:
        data += b"\x00"
    total = 0
    for i in range(0, len(data), 2):
        total += (data[i] << 8) | data[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return (~total) & 0xFFFF


def _packed_ip(addr: str) -> bytes:
    return bytes(int(octet) for octet in addr.split("."))


def ipv4(src: str, dst: str, payload: bytes, proto: int = 6, ident: int = 0) -> bytes:
    """IPv4 header with a correct checksum, plus payload."""
    fields = (0x45, 0, 20 + len(payload), ident, 0, 64, proto)
    src_b, dst_b = _packed_ip(src), _packed_ip(dst)
    without_cksum = struct.pack("!BBHHHBBH4s4s", *fields, 0, src_b, dst_b)
    header = struct.pack("!BBHHHBBH4s4s", *fields, checksum(without_cksum), src_b, dst_b)
    return header + payload


def tcp(
    sport: int,
    dport: int,
    seq: int,
    ack: int,
    flags: int,
    src: str,
    dst: str,
    payload: bytes = b"",
) -> bytes:
    """TCP header with a correct checksum, plus payload."""
    offset_flags = (5 << 12) | flags
    base = (sport, dport, seq, ack, offset_flags, 8192)
    without_cksum = struct.pack("!HHIIHHHH", *base, 0, 0)
    pseudo = (
        _packed_ip(src)
        + _packed_ip(dst)
        + struct.pack("!BBH", 0, 6, len(without_cksum) + len(payload))
    )
    cksum = checksum(pseudo + without_cksum + payload)
    return struct.pack("!HHIIHHHH", *base, cksum, 0) + payload


def ethernet(payload: bytes) -> bytes:
    return SRC_MAC + DST_MAC + b"\x08\x00" + payload


def build_packets() -> list[tuple[float, bytes]]:
    """One complete, unremarkable HTTP exchange per flow: handshake, data, teardown."""
    packets: list[tuple[float, bytes]] = []
    request = b"GET / HTTP/1.0\r\n\r\n"
    response = b"HTTP/1.0 200 OK\r\n\r\nhi"

    for flow_index, (sport, dport, client, server) in enumerate(FLOWS):
        cseq = 1000 + flow_index
        sseq = 5000 + flow_index
        steps = [
            (client, server, sport, dport, cseq, 0, SYN, b""),
            (server, client, dport, sport, sseq, cseq + 1, SYN | ACK, b""),
            (client, server, sport, dport, cseq + 1, sseq + 1, ACK, b""),
            (client, server, sport, dport, cseq + 1, sseq + 1, PSH | ACK, request),
            (server, client, dport, sport, sseq + 1, cseq + 19, PSH | ACK, response),
            (client, server, sport, dport, cseq + 19, sseq + 22, FIN | ACK, b""),
            (server, client, dport, sport, sseq + 22, cseq + 20, FIN | ACK, b""),
        ]
        for step_index, step in enumerate(steps):
            src, dst, sp, dp, seq, ack, flags, payload = step
            segment = tcp(sp, dp, seq, ack, flags, src, dst, payload)
            ident = flow_index * 100 + step_index
            frame = ethernet(ipv4(src, dst, segment, ident=ident))
            packets.append((BASE_TS + flow_index * 10 + step_index * 0.01, frame))

    return packets


def write_pcap(path: str, packets: list[tuple[float, bytes]]) -> None:
    header = struct.pack("<IHHiIII", PCAP_MAGIC, 2, 4, 0, 0, SNAPLEN, LINKTYPE_ETHERNET)
    with open(path, "wb") as handle:
        handle.write(header)
        for timestamp, frame in packets:
            seconds = int(timestamp)
            micros = int(round((timestamp - seconds) * 1_000_000))
            handle.write(struct.pack("<IIII", seconds, micros, len(frame), len(frame)))
            handle.write(frame)


def main() -> int:
    out = sys.argv[1] if len(sys.argv) > 1 else "benign.pcap"
    packets = build_packets()
    write_pcap(out, packets)
    print(f"wrote {out}: {len(packets)} packets, {len(FLOWS)} flows")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
