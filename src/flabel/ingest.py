"""Capture ingest: sniff, decompress, validate, convert (spec §8 "Ingest").

Every consumer downstream reads one normalized pcap, so Zeek and Suricata cannot disagree
about the input (spec §2.4). Getting there means answering three questions about a file an
operator handed us, in this order and no other:

1. **What is it?** Answered by magic bytes, never by extension. A `.pcap` holding a pcapng is
   ordinary; so is a `.pcap` that is really gzip. Trusting the name would misroute both.
2. **Is all of it there?** Answered by walking the record headers ourselves. No tool in the
   dependency set reports *where* a capture was cut off, and the offset is the difference
   between "partial input, here is what was lost" and an unexplained short packet count.
3. **Can the toolchain read it?** pcapng becomes pcap via `editcap`, and a pcapng mixing link
   types has to lose the minority types because pcap cannot express more than one.

The asymmetry between a truncated pcap and a truncated pcapng is deliberate (spec §8 steps
5-6). A pcap record is self-delimiting, so dropping an incomplete tail record leaves a
correct file. A pcapng block is not: a partial block can leave `editcap` guessing at the
structure of what follows, and a guess about the input is exactly what this module must never
make. So pcap proceeds as partial and pcapng fails with repair instructions.

This module is impure by design (`subprocess` for `editcap`) and performs no network I/O.
"""

from __future__ import annotations

import contextlib
import gzip
import hashlib
import shutil
import struct
import subprocess
from dataclasses import dataclass
from pathlib import Path

from flabel.errors import CaptureError, ToolError
from flabel.models import CaptureFormat, NormalizedCapture, ToolFailure

#: Magic bytes, as they appear on disk. gzip is two bytes (RFC 1952); pcap's magic doubles as
#: a byte-order and timestamp-precision marker; pcapng's block type is palindromic so it reads
#: the same either way, and the endianness comes from the byte-order magic inside the SHB.
GZIP_MAGIC = b"\x1f\x8b"

#: pcap magic -> (struct byte-order prefix, nanosecond timestamps). The precision is recorded
#: for completeness of the walk; both variants convert and copy identically.
PCAP_MAGICS: dict[bytes, tuple[str, bool]] = {
    b"\xa1\xb2\xc3\xd4": (">", False),
    b"\xd4\xc3\xb2\xa1": ("<", False),
    b"\xa1\xb2\x3c\x4d": (">", True),
    b"\x4d\x3c\xb2\xa1": ("<", True),
}
PCAPNG_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAPNG_BYTE_ORDER_MAGIC = 0x1A2B3C4D

PCAP_FILE_HEADER_BYTES = 24
PCAP_RECORD_HEADER_BYTES = 16
PCAPNG_BLOCK_HEADER_BYTES = 8
PCAPNG_MIN_BLOCK_BYTES = 12

#: pcapng block types this module needs to recognise. Everything else is skipped by length,
#: which is what the format's block structure is for.
BLOCK_SECTION_HEADER = 0x0A0D0D0A
BLOCK_INTERFACE_DESCRIPTION = 0x00000001
BLOCK_PACKET_OBSOLETE = 0x00000002
BLOCK_SIMPLE_PACKET = 0x00000003
BLOCK_ENHANCED_PACKET = 0x00000006

#: A record or block longer than this is not a large packet, it is a header we misread. 16 MiB
#: is three orders of magnitude above a jumbo frame, so the bound only fires on corruption.
#: Checked *before* the end-of-file bound so corruption is reported as corruption rather than
#: as truncation, which would tell the operator to look in the wrong place.
MAX_RECORD_BYTES = 16 * 1024 * 1024

#: libpcap link type -> (name recorded in provenance, `editcap -T` name). The names on the
#: right are `editcap`'s own, verified against `editcap -T` on Wireshark 4.6; the ones on the
#: left are the libpcap DLT names, which is what a reader of `labels.json` will recognise.
#:
#: Only the *dominant* type of a mixed capture needs an `editcap -T` name, and a type absent
#: from this table fails loudly (see `_editcap_encapsulation`) rather than being guessed at.
LINK_TYPES: dict[int, tuple[str, str]] = {
    0: ("NULL", "null"),
    1: ("EN10MB", "ether"),
    9: ("PPP", "ppp"),
    101: ("RAW", "rawip"),
    105: ("IEEE802_11", "ieee-802-11"),
    113: ("LINUX_SLL", "linux-sll"),
    127: ("IEEE802_11_RADIOTAP", "ieee-802-11-radiotap"),
    228: ("IPV4", "rawip4"),
    229: ("IPV6", "rawip6"),
    276: ("LINUX_SLL2", "linux-sll2"),
}

#: Name of the single file every downstream stage reads.
NORMALIZED_NAME = "normalized.pcap"

#: `editcap`'s packet selection is passed as command-line arguments, so a capture whose link
#: types interleave into a pathological number of runs would overflow the argument list. The
#: bound is generous — real mixed captures come from a handful of interfaces in long runs —
#: and failing with an explanation beats an `OSError` from the kernel.
MAX_SELECTION_RUNS = 20_000

#: Read size for hashing and copying. Captures are routinely gigabytes; nothing here loads a
#: whole file into memory.
CHUNK_BYTES = 1024 * 1024


class EditcapError(ToolError):
    """`editcap` failed, carrying the structured record for the run block.

    Spec §11 wants a tool failure in `tool_failures[]` *and* a hard failure. `ToolError`
    alone carries only a message, and `NormalizedCapture` has no field for a failure because
    a normalize that fails returns nothing at all — so the record travels on the exception.
    `cli.py` (step 9) reads `.failure` to populate the run block; anything catching plain
    `ToolError` still gets the right exit code.
    """

    def __init__(self, failure: ToolFailure) -> None:
        super().__init__(failure.message)
        self.failure = failure


@dataclass(frozen=True)
class _Walk:
    """What reading every record header told us about a capture.

    Private: `NormalizedCapture` is the module's public answer. This is the intermediate that
    both the pcap and pcapng paths produce so `normalize` can branch on facts rather than on
    format-specific state.
    """

    packets: int
    truncated_at_offset: int | None
    #: Packet count per link type, in ascending link-type order. Single-entry for pcap.
    packets_by_link_type: tuple[tuple[int, int], ...] = ()

    @property
    def link_types(self) -> tuple[int, ...]:
        return tuple(link_type for link_type, _ in self.packets_by_link_type)


# --- sniffing ------------------------------------------------------------------------------


def sniff(path: Path) -> str:
    """Container format of `path` by magic bytes: `gzip`, `pcap` or `pcapng`.

    Raises `CaptureError` for anything else, which is spec §8 step 4's unreadable header: we
    will not hand an unidentified file to a tool to find out what happens.
    """
    with path.open("rb") as handle:
        magic = handle.read(4)

    if magic[:2] == GZIP_MAGIC:
        return "gzip"
    if magic in PCAP_MAGICS:
        return "pcap"
    if magic == PCAPNG_MAGIC:
        return "pcapng"
    raise CaptureError(
        f"{path}: unrecognised capture format — first bytes are {magic.hex(' ') or '(empty)'}. "
        f"Expected gzip (1f 8b), pcap (a1 b2 c3 d4 or its byte-swapped and nanosecond "
        f"variants) or pcapng (0a 0d 0d 0a). The file extension is never consulted."
    )


# --- validation: the record-header walk ----------------------------------------------------


def _walk_pcap(path: Path) -> _Walk:
    """Count records and locate the first short one.

    Driven by seeks and 16-byte header reads rather than by reading payloads, so the cost is
    proportional to the packet count, not to the capture size.
    """
    size = path.stat().st_size
    with path.open("rb") as handle:
        header = handle.read(PCAP_FILE_HEADER_BYTES)
        if len(header) < PCAP_FILE_HEADER_BYTES:
            raise CaptureError(
                f"{path}: pcap file header is {len(header)} bytes, needs "
                f"{PCAP_FILE_HEADER_BYTES}. The header itself is incomplete, so there is no "
                f"capture to read — this is not recoverable truncation."
            )
        order, _nanosecond = PCAP_MAGICS[header[:4]]
        _, version_major, _version_minor, _, _, _snaplen, link_type = struct.unpack(
            order + "IHHiIII", header
        )
        if version_major != 2:
            raise CaptureError(
                f"{path}: pcap version {version_major} is not 2 — the header does not "
                f"describe a readable pcap file."
            )

        packets = 0
        offset = PCAP_FILE_HEADER_BYTES
        while offset < size:
            record_header = handle.read(PCAP_RECORD_HEADER_BYTES)
            if len(record_header) < PCAP_RECORD_HEADER_BYTES:
                return _Walk(packets, offset, ((link_type, packets),))
            _, _, captured_length, _ = struct.unpack(order + "IIII", record_header)
            if captured_length > MAX_RECORD_BYTES:
                raise CaptureError(
                    f"{path}: record header at offset {offset} claims {captured_length} "
                    f"captured bytes, above the {MAX_RECORD_BYTES}-byte sanity bound. The "
                    f"header is not readable — the file is corrupt rather than truncated."
                )
            if offset + PCAP_RECORD_HEADER_BYTES + captured_length > size:
                return _Walk(packets, offset, ((link_type, packets),))
            offset += PCAP_RECORD_HEADER_BYTES + captured_length
            handle.seek(offset)
            packets += 1

    return _Walk(packets, None, ((link_type, packets),))


def _walk_pcapng(path: Path) -> _Walk:
    """Count packet blocks per interface link type and locate the first short block.

    Interface link types are collected as well as counted because pcap cannot express more
    than one, so `normalize` has to choose — and because the count per type is the only
    defensible basis for that choice.
    """
    size = path.stat().st_size
    order = "<"
    link_type_of_interface: list[int] = []
    counts: dict[int, int] = {}
    packets = 0
    offset = 0

    with path.open("rb") as handle:
        while offset < size:
            head = handle.read(PCAPNG_BLOCK_HEADER_BYTES)
            if len(head) < PCAPNG_BLOCK_HEADER_BYTES:
                if offset == 0:
                    raise CaptureError(
                        f"{path}: file is {size} bytes — too short to hold a pcapng section "
                        f"header block."
                    )
                return _Walk(packets, offset, _by_link_type(counts))

            block_type = struct.unpack(order + "I", head[:4])[0]
            if offset == 0 or block_type == BLOCK_SECTION_HEADER:
                order = _section_byte_order(handle, path, offset)
                block_type = BLOCK_SECTION_HEADER
                # A new section redefines the interfaces; carrying the old ones over would
                # attribute packets to link types from a different section.
                link_type_of_interface = []

            total_length = struct.unpack(order + "I", head[4:8])[0]
            if (
                total_length < PCAPNG_MIN_BLOCK_BYTES
                or total_length % 4
                or total_length > MAX_RECORD_BYTES
            ):
                raise CaptureError(
                    f"{path}: block at offset {offset} declares a total length of "
                    f"{total_length}, which is not a valid pcapng block length. The file is "
                    f"corrupt rather than truncated."
                )
            if offset + total_length > size:
                return _Walk(packets, offset, _by_link_type(counts))

            body = handle.read(total_length - PCAPNG_MIN_BLOCK_BYTES)
            trailer = struct.unpack(order + "I", handle.read(4))[0]
            if trailer != total_length:
                raise CaptureError(
                    f"{path}: block at offset {offset} declares length {total_length} but "
                    f"its trailing length is {trailer}. pcapng writes the length twice so a "
                    f"reader can detect exactly this; the file is corrupt."
                )

            if block_type == BLOCK_INTERFACE_DESCRIPTION:
                link_type_of_interface.append(struct.unpack(order + "H", body[:2])[0])
            elif block_type in (BLOCK_ENHANCED_PACKET, BLOCK_PACKET_OBSOLETE, BLOCK_SIMPLE_PACKET):
                interface = _packet_interface(block_type, body, order)
                if interface >= len(link_type_of_interface):
                    raise CaptureError(
                        f"{path}: packet block at offset {offset} references interface "
                        f"{interface}, which no interface description block defines. Its link "
                        f"type is unknowable, and guessing one would misdescribe the capture."
                    )
                counts[link_type_of_interface[interface]] = (
                    counts.get(link_type_of_interface[interface], 0) + 1
                )
                packets += 1

            offset += total_length

    return _Walk(packets, None, _by_link_type(counts))


def _section_byte_order(handle, path: Path, offset: int) -> str:
    """Byte order declared by the section header block whose header was just read.

    The SHB's own `total_length` field cannot be read until this is known, so the byte-order
    magic four bytes further in is peeked at and the handle put back where it was.
    """
    magic = handle.read(4)
    handle.seek(offset + PCAPNG_BLOCK_HEADER_BYTES)
    if len(magic) < 4:
        raise CaptureError(
            f"{path}: pcapng section header block at offset {offset} is incomplete — its "
            f"byte-order magic is missing, so the file cannot be read at all."
        )
    for order in ("<", ">"):
        if struct.unpack(order + "I", magic)[0] == PCAPNG_BYTE_ORDER_MAGIC:
            return order
    raise CaptureError(
        f"{path}: pcapng section header block at offset {offset} has byte-order magic "
        f"{magic.hex(' ')}, expected 1a 2b 3c 4d in either order."
    )


def _packet_interface(block_type: int, body: bytes, order: str) -> int:
    """Interface index a packet block belongs to.

    A simple packet block carries no interface field: the format defines it as belonging to
    the first interface, which is the only reading that is not a guess.
    """
    if block_type == BLOCK_ENHANCED_PACKET:
        return struct.unpack(order + "I", body[:4])[0]
    if block_type == BLOCK_PACKET_OBSOLETE:
        return struct.unpack(order + "H", body[:2])[0]
    return 0


def _by_link_type(counts: dict[int, int]) -> tuple[tuple[int, int], ...]:
    """Counts as a tuple sorted by link type — a stable order for a reproducible run."""
    return tuple(sorted(counts.items()))


def walk(path: Path, container: str) -> _Walk:
    """Validate `path` by reading every record header. `container` comes from `sniff`."""
    return _walk_pcap(path) if container == "pcap" else _walk_pcapng(path)


# --- link types ----------------------------------------------------------------------------


def link_type_name(link_type: int) -> str:
    """libpcap DLT name for provenance, or `LINKTYPE_<n>` when we have no name for it."""
    known = LINK_TYPES.get(link_type)
    return known[0] if known else f"LINKTYPE_{link_type}"


def _editcap_encapsulation(link_type: int, path: Path) -> str:
    """`editcap -T` name for `link_type`, or a `CaptureError` explaining the dead end.

    `-T` is unavoidable when discarding link types: `editcap` decides the output
    encapsulation from the *interface description blocks*, not from the packets that survive
    selection, so a pcapng that ever declared two link types still refuses to become a pcap
    even once the minority packets are dropped. Verified on Wireshark 4.6.7.

    That makes `-T` a claim about the kept packets, so it is only ever passed with a name for
    the type those packets actually carry. Without one, the operator gets an explanation
    rather than a mislabelled capture.
    """
    known = LINK_TYPES.get(link_type)
    if known is None:
        raise CaptureError(
            f"{path}: the dominant link type is {link_type_name(link_type)}, which flabel has "
            f"no `editcap -T` name for, and the capture mixes link types so a plain "
            f"conversion is impossible. Split it by link type manually (see `editcap -T` for "
            f"the available names) and pass the resulting single-link-type capture instead."
        )
    return known[1]


# --- editcap -------------------------------------------------------------------------------


def _run_editcap(argv: list[str]) -> None:
    """Invoke `editcap`, turning any failure into `EditcapError`.

    A missing binary and a non-zero exit are the same event to a caller — the conversion did
    not happen — so both arrive as one exception type with `exit_code` distinguishing them.
    """
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=False)
    except OSError as error:
        raise EditcapError(
            ToolFailure(
                tool="editcap",
                argv=tuple(argv),
                exit_code=None,
                message=f"editcap could not be run: {error}",
            )
        ) from error

    if result.returncode != 0:
        raise EditcapError(
            ToolFailure(
                tool="editcap",
                argv=tuple(argv),
                exit_code=result.returncode,
                message=(
                    f"editcap exited {result.returncode}: "
                    f"{(result.stderr or result.stdout).strip()}"
                ),
            )
        )


def _selection_ranges(path: Path, keep_link_type: int, walked: _Walk) -> list[str]:
    """1-based packet-number ranges for every packet on `keep_link_type`.

    A second walk rather than a per-packet list from the first: the ranges compress runs, so
    memory stays proportional to the number of interleavings instead of to the packet count,
    which matters on the multi-gigabyte captures this is aimed at.
    """
    runs: list[tuple[int, int]] = []
    for number in _packet_numbers(path, keep_link_type):
        if runs and runs[-1][1] == number - 1:
            runs[-1] = (runs[-1][0], number)
        else:
            runs.append((number, number))
        if len(runs) > MAX_SELECTION_RUNS:
            raise CaptureError(
                f"{path}: packets of the kept link type fall into more than "
                f"{MAX_SELECTION_RUNS} separate runs. flabel selects them by passing ranges "
                f"to `editcap`, and a list this long exceeds what a command line can carry. "
                f"Split the capture by link type before running flabel."
            )
    if not runs:
        raise CaptureError(
            f"{path}: no packets carry link type {link_type_name(keep_link_type)}, though the "
            f"header walk counted {walked.packets}. This is a flabel bug, not a bad file."
        )
    return [f"{first}-{last}" if first != last else str(first) for first, last in runs]


def _packet_numbers(path: Path, keep_link_type: int):
    """1-based numbers of the packet blocks whose interface carries `keep_link_type`.

    Yields rather than collects. Only reached for a capture already known to be a
    structurally valid pcapng, so the error paths of `_walk_pcapng` are not repeated here.
    """
    size = path.stat().st_size
    order = "<"
    link_type_of_interface: list[int] = []
    number = 0
    offset = 0

    with path.open("rb") as handle:
        while offset < size:
            head = handle.read(PCAPNG_BLOCK_HEADER_BYTES)
            if len(head) < PCAPNG_BLOCK_HEADER_BYTES:
                return
            block_type = struct.unpack(order + "I", head[:4])[0]
            if offset == 0 or block_type == BLOCK_SECTION_HEADER:
                order = _section_byte_order(handle, path, offset)
                block_type = BLOCK_SECTION_HEADER
                link_type_of_interface = []
            total_length = struct.unpack(order + "I", head[4:8])[0]
            if offset + total_length > size:
                return
            body = handle.read(total_length - PCAPNG_MIN_BLOCK_BYTES)

            if block_type == BLOCK_INTERFACE_DESCRIPTION:
                link_type_of_interface.append(struct.unpack(order + "H", body[:2])[0])
            elif block_type in (BLOCK_ENHANCED_PACKET, BLOCK_PACKET_OBSOLETE, BLOCK_SIMPLE_PACKET):
                number += 1
                interface = _packet_interface(block_type, body, order)
                if link_type_of_interface[interface] == keep_link_type:
                    yield number

            offset += total_length
            handle.seek(offset)


# --- output --------------------------------------------------------------------------------


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _copy_prefix(source: Path, destination: Path, length: int) -> None:
    """Copy the first `length` bytes of `source` — the complete records of a truncated pcap."""
    remaining = length
    with source.open("rb") as reader, destination.open("wb") as writer:
        while remaining:
            chunk = reader.read(min(CHUNK_BYTES, remaining))
            if not chunk:
                break
            writer.write(chunk)
            remaining -= len(chunk)


def _verify_converted(path: Path, expected_packets: int) -> None:
    """Re-walk `editcap`'s output and check the packet count is the one we asked for.

    `editcap` exiting zero is not evidence that it wrote what was requested, and a silently
    short conversion would show up downstream as flows that never existed rather than as an
    ingest failure. The walk already exists, so the check is nearly free.
    """
    produced = _walk_pcap(path)
    if produced.packets != expected_packets or produced.truncated_at_offset is not None:
        raise EditcapError(
            ToolFailure(
                tool="editcap",
                argv=(),
                exit_code=0,
                message=(
                    f"editcap exited 0 but its output holds {produced.packets} packets where "
                    f"{expected_packets} were expected"
                    + (
                        f", and is itself truncated at offset {produced.truncated_at_offset}"
                        if produced.truncated_at_offset is not None
                        else ""
                    )
                ),
            )
        )


# --- the entry point -----------------------------------------------------------------------


def normalize(capture: Path, workdir: Path) -> NormalizedCapture:
    """Produce the single normalized capture every downstream stage reads.

    `workdir` receives exactly one file on success, `normalized.pcap`. On failure it receives
    none, and is not created if it did not already exist: spec §13 forbids a partial run
    directory, so a capture that cannot be normalized must leave nothing resembling output.

    `sha256` and `bytes_total` describe `capture` **as it was handed to us** — a compressed
    input hashes as the compressed file. They identify the operator's input, which is what
    `capture_format` also describes; the normalized file is identified by being derived from
    them through the recorded `normalization` steps.

    Offsets in `truncated_at_offset` are offsets into the *uncompressed* capture, since that
    is the only place a record boundary exists.
    """
    capture = Path(capture)
    if not capture.is_file():
        raise CaptureError(f"{capture}: not a readable file")

    container = sniff(capture)
    compressed = container == "gzip"
    created_workdir = not workdir.exists()
    intermediates: list[Path] = []
    normalization: list[str] = []

    try:
        workdir.mkdir(parents=True, exist_ok=True)
        source = capture
        if compressed:
            source = workdir / "decompressed.capture"
            intermediates.append(source)
            _decompress(capture, source)
            normalization.append("decompress: gzip")
            # Sniffed again: gzip says nothing about what it wraps, and the name says nothing
            # about anything. A `.pcap.gz` holding a pcapng is the reason this is a second
            # sniff rather than an assumption.
            container = sniff(source)
        capture_format: CaptureFormat = _format_name(container, compressed)

        walked = walk(source, container)
        output = workdir / NORMALIZED_NAME
        if container == "pcap":
            discarded_link_types: tuple[str, ...] = ()
            discarded_packets = 0
            _emit_pcap(source, output, walked, normalization, intermediates)
        else:
            discarded_link_types, discarded_packets = _emit_pcapng(
                source, output, walked, normalization
            )
    except BaseException:
        _discard_output(workdir, created_workdir, intermediates)
        raise

    for intermediate in intermediates:
        intermediate.unlink(missing_ok=True)

    partial = walked.truncated_at_offset is not None or discarded_packets > 0
    return NormalizedCapture(
        path=output,
        original_path=capture,
        sha256=_sha256(capture),
        capture_format=capture_format,
        bytes_total=capture.stat().st_size,
        input_status="partial" if partial else "complete",
        packets_read=walked.packets,
        truncated_at_offset=walked.truncated_at_offset,
        discarded_link_types=discarded_link_types,
        discarded_packets=discarded_packets,
        normalization=tuple(normalization),
    )


def _decompress(capture: Path, destination: Path) -> None:
    """Stream `capture` out of gzip. Streamed, because captures do not fit in memory."""
    try:
        with gzip.open(capture, "rb") as compressed, destination.open("wb") as writer:
            shutil.copyfileobj(compressed, writer, CHUNK_BYTES)
    except (OSError, EOFError, gzip.BadGzipFile) as error:
        raise CaptureError(f"{capture}: gzip decompression failed: {error}") from error


def _format_name(container: str, compressed: bool) -> CaptureFormat:
    """The `CaptureFormat` literal for what was sniffed, not for what the file was called."""
    name = f"{container}.gz" if compressed else container
    if name not in ("pcap", "pcapng", "pcap.gz", "pcapng.gz"):  # pragma: no cover - defensive
        raise CaptureError(f"unsupported capture format: {name}")
    return name  # type: ignore[return-value]


def _emit_pcap(
    source: Path,
    output: Path,
    walked: _Walk,
    normalization: list[str],
    intermediates: list[Path],
) -> None:
    """Write the normalized pcap for a pcap input: a copy, minus any incomplete tail record.

    Dropping the incomplete record is what makes "proceed as partial" (spec §8 step 5)
    possible at all. Verified on the pinned toolchain: given a pcap cut mid-record, Zeek 8.0.9
    exits 1 with `fatal error: failed to read a packet ... truncated dump file`, and Suricata
    8.0.6 logs `pcap: error code -1 truncated dump file`. Passing the file through untouched
    would turn a loss condition the spec says to *report* into a tool failure that ends the
    run. `packets_read` and `truncated_at_offset` say exactly what was dropped and where, so
    the trim removes bytes, not information.
    """
    if walked.truncated_at_offset is not None:
        _copy_prefix(source, output, walked.truncated_at_offset)
        normalization.append(
            f"trim: dropped incomplete final record at offset {walked.truncated_at_offset}"
        )
        return

    if source in intermediates:
        # The decompressed file is already exactly the bytes we want; renaming it avoids a
        # second full-size copy of the capture on disk.
        source.replace(output)
        intermediates.remove(source)
    else:
        shutil.copyfile(source, output)


def _emit_pcapng(
    source: Path,
    output: Path,
    walked: _Walk,
    normalization: list[str],
) -> tuple[tuple[str, ...], int]:
    """Convert a pcapng to pcap, discarding minority link types if there is more than one.

    Returns the discarded link-type names and packet count for provenance.
    """
    if walked.truncated_at_offset is not None:
        raise CaptureError(
            f"{source}: pcapng is truncated at offset {walked.truncated_at_offset} after "
            f"{walked.packets} packets. Unlike a pcap record, a partial pcapng block cannot "
            f"be dropped safely, so flabel will not convert it. Repair it first — "
            f"`editcap -F pcapng {source} repaired.pcapng` rewrites the readable blocks — "
            f"then re-run flabel against the repaired file."
        )

    if len(walked.link_types) <= 1:
        _run_editcap(["editcap", "-F", "pcap", str(source), str(output)])
        normalization.append("convert: editcap -F pcap")
        _verify_converted(output, walked.packets)
        return (), 0

    # Dominant by packet count, ties broken by the lowest link type. A tie has no meaningful
    # winner, so the rule is chosen to be *stable* — reproducibility (Goal 2) needs two runs
    # over one capture to keep the same packets, which a dict-order or first-seen rule would
    # not guarantee.
    kept_link_type, kept_packets = max(
        walked.packets_by_link_type, key=lambda item: (item[1], -item[0])
    )
    encapsulation = _editcap_encapsulation(kept_link_type, source)
    ranges = _selection_ranges(source, kept_link_type, walked)

    _run_editcap(
        ["editcap", "-F", "pcap", "-T", encapsulation, "-r", str(source), str(output), *ranges]
    )
    _verify_converted(output, kept_packets)

    discarded = tuple(
        link_type_name(link_type)
        for link_type, _ in walked.packets_by_link_type
        if link_type != kept_link_type
    )
    discarded_packets = walked.packets - kept_packets
    normalization.append("convert: editcap -F pcap")
    normalization.append(
        f"split: kept link type {link_type_name(kept_link_type)} ({kept_packets} packets); "
        f"discarded {discarded_packets} packets of link type(s) {', '.join(discarded)}"
    )
    return discarded, discarded_packets


def _discard_output(workdir: Path, created_workdir: bool, intermediates: list[Path]) -> None:
    """Leave nothing behind after a failure — spec §13: no partial run directory.

    The normalized file is removed too: a caller that catches the error and carries on must
    not find a half-written capture waiting for it. An existing `workdir` is left in place
    (it was not ours to delete) but emptied of what this call put there.

    Every removal is best-effort. This runs while an exception is in flight, and a cleanup
    that raised — an unwritable directory, an output path that turned out to be something
    else — would replace the real diagnosis with an incidental one.
    """
    for path in [*intermediates, workdir / NORMALIZED_NAME]:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
    if created_workdir and workdir.is_dir():
        # Only if something else wrote here meanwhile — in which case the directory is not
        # ours to remove after all.
        with contextlib.suppress(OSError):
            workdir.rmdir()
