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

Three properties hold throughout, because a capture is the largest and least trustworthy
thing flabel touches:

* **Nothing is read into memory whole.** Hashing, copying and decompression stream; the walks
  seek past payloads and large blocks instead of reading them.
* **A malformed file is a `CaptureError`, never a traceback.** Header fields are bounds-checked
  before they are unpacked, and the walk has an outer guard for anything that slips through.
* **A failure leaves no output.** Spec §13 allows a complete run directory or none, so every
  path that has already written something cleans up before the exception escapes — including
  any directory this call created.

This module is impure by design (`subprocess`) and performs no network I/O.
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

PACKET_BLOCKS = frozenset({BLOCK_ENHANCED_PACKET, BLOCK_PACKET_OBSOLETE, BLOCK_SIMPLE_PACKET})

BLOCK_NAMES = {
    BLOCK_SECTION_HEADER: "section header",
    BLOCK_INTERFACE_DESCRIPTION: "interface description",
    BLOCK_PACKET_OBSOLETE: "packet",
    BLOCK_SIMPLE_PACKET: "simple packet",
    BLOCK_ENHANCED_PACKET: "enhanced packet",
}

#: Smallest body (block length minus the 12 bytes of framing) that can hold the mandatory
#: fields of each block type this module reads fields from. Checked before unpacking: a block
#: whose declared length is structurally valid can still be too short for its own contents,
#: and unpacking that raises `struct.error` — not a `FlabelError`, so it would reach the
#: operator as a traceback instead of "this file is corrupt".
MIN_BODY_BYTES = {
    BLOCK_SECTION_HEADER: 16,
    BLOCK_INTERFACE_DESCRIPTION: 8,
    BLOCK_ENHANCED_PACKET: 20,
    BLOCK_PACKET_OBSOLETE: 20,
    BLOCK_SIMPLE_PACKET: 4,
}

#: How much of a block body to read. Every field this module needs is in the first few bytes,
#: and a pcapng may legitimately carry a very large block — Wireshark embeds TLS key logs in
#: decryption secrets blocks, and name resolution blocks grow with the capture — so bodies are
#: peeked at and skipped rather than read.
PCAPNG_PEEK_BYTES = 32

#: A *packet* longer than this is not a large frame, it is a header we misread. 16 MiB is three
#: orders of magnitude above a jumbo frame, so the bound only fires on corruption. It is
#: deliberately **not** applied to other block types, where large is normal and legal — a
#: capture carrying a decryption secrets block is not a corrupt capture. Checked before the
#: end-of-file bound so corruption is reported as corruption rather than as truncation, which
#: would send the operator looking in the wrong place.
MAX_PACKET_BYTES = 16 * 1024 * 1024

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

#: Intermediates, deleted before `normalize` returns. Named rather than randomised so a crashed
#: process leaves something recognisable behind instead of a mystery temp file.
DECOMPRESSED_NAME = "decompressed.capture"
SELECTED_NAME = "selected.pcapng"

#: Read size for hashing and copying. Captures are routinely gigabytes; nothing here loads a
#: whole file into memory.
CHUNK_BYTES = 1024 * 1024


class ConversionError(ToolError):
    """`editcap` or `tshark` failed, carrying the structured record for the run block.

    Spec §11 wants a tool failure in `tool_failures[]` *and* a hard failure. `ToolError` alone
    carries only a message, and `NormalizedCapture` has no field for a failure because a
    normalize that fails returns nothing at all — so the record travels on the exception.
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
    #: Link type of each interface, in the order the interfaces appear in the file — the
    #: numbering `tshark`'s `frame.interface_id` uses, so it is what a selection filter is
    #: built from. Several interfaces may share one link type.
    interface_link_types: tuple[int, ...] = ()

    @property
    def link_types(self) -> tuple[int, ...]:
        return tuple(link_type for link_type, _ in self.packets_by_link_type)


# --- sniffing ------------------------------------------------------------------------------


def sniff(path: Path, subject: str | None = None) -> str:
    """Container format of `path` by magic bytes: `gzip`, `pcap` or `pcapng`.

    Raises `CaptureError` for anything else, which is spec §8 step 4's unreadable header: we
    will not hand an unidentified file to a tool to find out what happens.

    `subject` is what an error message should name. It differs from `path` once a temporary
    decompressed file is what is being read — naming that file would point the operator at
    something cleanup has already deleted.
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
        f"{subject or path}: unrecognised capture format — first bytes are "
        f"{magic.hex(' ') or '(empty)'}. Expected gzip (1f 8b), pcap (a1 b2 c3 d4 or its "
        f"byte-swapped and nanosecond variants) or pcapng (0a 0d 0d 0a). The file extension "
        f"is never consulted."
    )


# --- validation: the record-header walk ----------------------------------------------------


def walk(path: Path, container: str, subject: str | None = None) -> _Walk:
    """Validate `path` by reading every record header. `container` comes from `sniff`.

    The `struct.error` guard is the outer net for the whole walk. The bounds checks below aim
    to catch every malformed field before it is unpacked; this makes sure a case they miss
    still reaches the operator as `CaptureError` — a diagnosis and an exit code — rather than
    as a traceback from the middle of a struct call.
    """
    subject = subject or str(path)
    try:
        if container == "pcap":
            return _walk_pcap(path, subject)
        return _walk_pcapng(path, subject)
    except struct.error as error:
        raise CaptureError(
            f"{subject}: a header field could not be read ({error}). The file is corrupt: "
            f"flabel walks record headers itself, so a malformed one surfaces here."
        ) from error


def _walk_pcap(path: Path, subject: str) -> _Walk:
    """Count records and locate the first short one.

    Driven by seeks and 16-byte header reads rather than by reading payloads, so the cost is
    proportional to the packet count, not to the capture size.
    """
    size = path.stat().st_size
    with path.open("rb") as handle:
        header = handle.read(PCAP_FILE_HEADER_BYTES)
        if len(header) < PCAP_FILE_HEADER_BYTES:
            raise CaptureError(
                f"{subject}: pcap file header is {len(header)} bytes, needs "
                f"{PCAP_FILE_HEADER_BYTES}. The header itself is incomplete, so there is no "
                f"capture to read — this is not recoverable truncation."
            )
        order, _nanosecond = PCAP_MAGICS[header[:4]]
        _, version_major, _version_minor, _, _, _snaplen, link_type = struct.unpack(
            order + "IHHiIII", header
        )
        if version_major != 2:
            raise CaptureError(
                f"{subject}: pcap version {version_major} is not 2 — the header does not "
                f"describe a readable pcap file."
            )

        packets = 0
        offset = PCAP_FILE_HEADER_BYTES
        while offset < size:
            record_header = handle.read(PCAP_RECORD_HEADER_BYTES)
            if len(record_header) < PCAP_RECORD_HEADER_BYTES:
                return _Walk(packets, offset, ((link_type, packets),), (link_type,))
            _, _, captured_length, _ = struct.unpack(order + "IIII", record_header)
            if captured_length > MAX_PACKET_BYTES:
                raise CaptureError(
                    f"{subject}: record header at offset {offset} claims {captured_length} "
                    f"captured bytes, above the {MAX_PACKET_BYTES}-byte sanity bound. The "
                    f"header is not readable — the file is corrupt rather than truncated."
                )
            if offset + PCAP_RECORD_HEADER_BYTES + captured_length > size:
                return _Walk(packets, offset, ((link_type, packets),), (link_type,))
            offset += PCAP_RECORD_HEADER_BYTES + captured_length
            handle.seek(offset)
            packets += 1

    return _Walk(packets, None, ((link_type, packets),), (link_type,))


def _walk_pcapng(path: Path, subject: str) -> _Walk:
    """Count packet blocks per interface link type and locate the first short block.

    Interface link types are collected as well as counted because pcap cannot express more
    than one, so `normalize` has to choose — and because the count per type is the only
    defensible basis for that choice.
    """
    size = path.stat().st_size
    order = "<"
    interface_link_types: list[int] = []
    section_base = 0
    counts: dict[int, int] = {}
    packets = 0
    offset = 0

    with path.open("rb") as handle:
        while offset < size:
            head = handle.read(PCAPNG_BLOCK_HEADER_BYTES)
            if len(head) < PCAPNG_BLOCK_HEADER_BYTES:
                if offset == 0:
                    raise CaptureError(
                        f"{subject}: file is {size} bytes — too short to hold a pcapng "
                        f"section header block."
                    )
                return _Walk(packets, offset, _by_link_type(counts), tuple(interface_link_types))

            block_type = struct.unpack(order + "I", head[:4])[0]
            if offset == 0 or block_type == BLOCK_SECTION_HEADER:
                order = _section_byte_order(handle, subject, offset)
                block_type = BLOCK_SECTION_HEADER
                # A new section restarts interface *numbering*, but Wireshark — and therefore
                # `frame.interface_id` — numbers interfaces continuously across the whole
                # file. One list plus a per-section base preserves both readings.
                section_base = len(interface_link_types)

            total_length = struct.unpack(order + "I", head[4:8])[0]
            body_length = total_length - PCAPNG_MIN_BLOCK_BYTES
            is_packet = block_type in PACKET_BLOCKS
            name = BLOCK_NAMES.get(block_type, f"type 0x{block_type:08x}")

            if total_length < PCAPNG_MIN_BLOCK_BYTES or total_length % 4:
                raise CaptureError(
                    f"{subject}: {name} block at offset {offset} declares a total length of "
                    f"{total_length}, which is not a valid pcapng block length (at least "
                    f"{PCAPNG_MIN_BLOCK_BYTES} bytes, and a multiple of 4). The file is "
                    f"corrupt rather than truncated."
                )
            if is_packet and total_length > MAX_PACKET_BYTES:
                raise CaptureError(
                    f"{subject}: {name} block at offset {offset} declares {total_length} "
                    f"bytes, above the {MAX_PACKET_BYTES}-byte sanity bound for a packet. The "
                    f"header is not readable — the file is corrupt rather than truncated."
                )
            if offset + total_length > size:
                return _Walk(packets, offset, _by_link_type(counts), tuple(interface_link_types))
            if body_length < MIN_BODY_BYTES.get(block_type, 0):
                raise CaptureError(
                    f"{subject}: {name} block at offset {offset} has a {body_length}-byte "
                    f"body, too short for the {MIN_BODY_BYTES[block_type]} bytes of fields "
                    f"its type defines. The file is corrupt."
                )

            body = handle.read(min(body_length, PCAPNG_PEEK_BYTES))
            handle.seek(offset + total_length - 4)
            trailer = struct.unpack(order + "I", handle.read(4))[0]
            if trailer != total_length:
                raise CaptureError(
                    f"{subject}: {name} block at offset {offset} declares length "
                    f"{total_length} but its trailing length is {trailer}. pcapng writes the "
                    f"length twice so a reader can detect exactly this; the file is corrupt."
                )

            if block_type == BLOCK_INTERFACE_DESCRIPTION:
                interface_link_types.append(struct.unpack(order + "H", body[:2])[0])
            elif is_packet:
                index = section_base + _packet_interface(block_type, body, order)
                if index >= len(interface_link_types):
                    raise CaptureError(
                        f"{subject}: {name} block at offset {offset} references interface "
                        f"{index}, which no interface description block defines. Its link "
                        f"type is unknowable, and guessing one would misdescribe the capture."
                    )
                counts[interface_link_types[index]] = counts.get(interface_link_types[index], 0) + 1
                packets += 1

            offset += total_length
            handle.seek(offset)

    return _Walk(packets, None, _by_link_type(counts), tuple(interface_link_types))


def _section_byte_order(handle, subject: str, offset: int) -> str:
    """Byte order declared by the section header block whose header was just read.

    The SHB's own `total_length` field cannot be read until this is known, so the byte-order
    magic four bytes further in is peeked at and the handle put back where it was.
    """
    magic = handle.read(4)
    handle.seek(offset + PCAPNG_BLOCK_HEADER_BYTES)
    if len(magic) < 4:
        raise CaptureError(
            f"{subject}: pcapng section header block at offset {offset} is incomplete — its "
            f"byte-order magic is missing, so the file cannot be read at all."
        )
    for order in ("<", ">"):
        if struct.unpack(order + "I", magic)[0] == PCAPNG_BYTE_ORDER_MAGIC:
            return order
    raise CaptureError(
        f"{subject}: pcapng section header block at offset {offset} has byte-order magic "
        f"{magic.hex(' ')}, expected 1a 2b 3c 4d in either order."
    )


def _packet_interface(block_type: int, body: bytes, order: str) -> int:
    """Interface index a packet block belongs to, relative to its section.

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


# --- link types ----------------------------------------------------------------------------


def link_type_name(link_type: int) -> str:
    """libpcap DLT name for provenance, or `LINKTYPE_<n>` when we have no name for it."""
    known = LINK_TYPES.get(link_type)
    return known[0] if known else f"LINKTYPE_{link_type}"


def _editcap_encapsulation(link_type: int, subject: str) -> str:
    """`editcap -T` name for `link_type`, or a `CaptureError` explaining the dead end.

    `-T` is unavoidable when discarding link types: `editcap` decides the output
    encapsulation from the *interface description blocks*, not from the packets that survive
    filtering, so a pcapng that ever declared two link types still refuses to become a pcap
    even once the minority packets are gone. Verified on Wireshark 4.6.7 — for `tshark` as
    well as `editcap`, and whether the filtering happens in one step or two.

    That makes `-T` a claim about the kept packets, so it is only ever passed with a name for
    the type those packets actually carry. Without one, the operator gets an explanation
    rather than a mislabelled capture.
    """
    known = LINK_TYPES.get(link_type)
    if known is None:
        raise CaptureError(
            f"{subject}: the dominant link type is {link_type_name(link_type)}, which flabel "
            f"has no `editcap -T` name for, and the capture mixes link types so a plain "
            f"conversion is impossible. Split it by link type manually (see `editcap -T` for "
            f"the available names) and pass the resulting single-link-type capture instead."
        )
    return known[1]


# --- running the tools ---------------------------------------------------------------------


def _run_tool(tool: str, argv: list[str]) -> None:
    """Invoke a conversion tool, turning any failure into `ConversionError`.

    A missing binary and a non-zero exit are the same event to a caller — the conversion did
    not happen — so both arrive as one exception type, with `exit_code` (`None` for "could not
    be run at all") telling them apart in the run block.
    """
    try:
        result = subprocess.run(argv, capture_output=True, text=True, check=False)
    except OSError as error:
        raise ConversionError(
            ToolFailure(
                tool=tool,
                argv=tuple(argv),
                exit_code=None,
                message=f"{tool} could not be run: {error}",
            )
        ) from error

    if result.returncode != 0:
        raise ConversionError(
            ToolFailure(
                tool=tool,
                argv=tuple(argv),
                exit_code=result.returncode,
                message=(
                    f"{tool} exited {result.returncode}: {(result.stderr or result.stdout).strip()}"
                ),
            )
        )


def _verify_converted(path: Path, expected_packets: int, tool: str, argv: list[str]) -> None:
    """Re-walk the conversion output and check the packet count is the one we asked for.

    Exiting zero is not evidence that a tool wrote what was requested, and a silently short
    conversion would surface downstream as flows that never existed rather than as an ingest
    failure. The walk already exists, so the check is nearly free.

    Reported as a tool failure rather than a capture error: the input was fine — we walked it —
    so what went wrong is the tool, which is what `tool_failures[]` is for. `exit_code` is
    `None` because the process did exit zero; the message carries the contradiction.
    """
    try:
        produced = _walk_pcap(path, f"the pcap {tool} produced")
    except CaptureError as error:
        raise ConversionError(
            ToolFailure(
                tool=tool,
                argv=tuple(argv),
                exit_code=None,
                message=f"{tool} exited 0 but its output is not a readable pcap: {error}",
            )
        ) from error

    if produced.packets != expected_packets or produced.truncated_at_offset is not None:
        raise ConversionError(
            ToolFailure(
                tool=tool,
                argv=tuple(argv),
                exit_code=None,
                message=(
                    f"{tool} exited 0 but its output holds {produced.packets} packets where "
                    f"{expected_packets} were expected"
                    + (
                        f", and is itself truncated at offset {produced.truncated_at_offset}"
                        if produced.truncated_at_offset is not None
                        else ""
                    )
                ),
            )
        )


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


# --- the entry point -----------------------------------------------------------------------


def normalize(capture: Path, workdir: Path) -> NormalizedCapture:
    """Produce the single normalized capture every downstream stage reads.

    `workdir` receives exactly one file on success, `normalized.pcap`. On failure it receives
    none, and neither it nor any parent directory this call created survives: spec §13 allows
    a complete run directory or none, with nothing in between.

    `sha256` and `bytes_total` describe `capture` **as it was handed to us** — a compressed
    input hashes as the compressed file. They identify the operator's input, which is what
    `capture_format` also describes; the normalized file is identified by being derived from
    them through the recorded `normalization` steps.

    Two counting conventions, reported to the run block exactly as stated here:

    * `packets_read` counts the **complete** records in the input. An incomplete tail record
      is not counted and is *not* in `discarded_packets` either — `truncated_at_offset` is
      what reports it. `discarded_packets` counts link-type discards only, so the normalized
      file holds `packets_read - discarded_packets` packets.
    * `truncated_at_offset` is an offset into the **uncompressed** capture, since a gzip
      member has no record boundaries for an offset to refer to.
    """
    capture = Path(capture)
    if not capture.is_file():
        raise CaptureError(f"{capture}: not a readable file")

    container = sniff(capture)
    compressed = container == "gzip"
    subject = str(capture)
    created_dirs = _missing_directories(workdir)
    intermediates: list[Path] = []
    normalization: list[str] = []

    try:
        workdir.mkdir(parents=True, exist_ok=True)
        source = capture
        if compressed:
            source = workdir / DECOMPRESSED_NAME
            intermediates.append(source)
            _decompress(capture, source)
            normalization.append("decompress: gzip")
            # Sniffed again, and renamed for reporting: gzip says nothing about what it wraps,
            # and from here on the file being read is a temporary one that cleanup deletes, so
            # every message must still name the operator's file.
            subject = f"{capture} (decompressed)"
            container = sniff(source, subject)
        capture_format: CaptureFormat = _format_name(container, compressed)

        walked = walk(source, container, subject)
        output = workdir / NORMALIZED_NAME
        if container == "pcap":
            discarded_link_types: tuple[str, ...] = ()
            discarded_packets = 0
            _emit_pcap(source, output, walked, normalization, intermediates)
        else:
            discarded_link_types, discarded_packets = _emit_pcapng(
                source, output, walked, normalization, workdir, subject, capture, intermediates
            )

        for intermediate in intermediates:
            intermediate.unlink(missing_ok=True)
        intermediates.clear()

        # Hashing and sizing are inside the try on purpose: `capture` is a file on someone
        # else's filesystem, and if it vanishes or turns unreadable in this window the failure
        # must take `normalized.pcap` with it rather than leave output behind for a failed run.
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
    except BaseException:
        _discard_output(workdir, created_dirs, intermediates)
        raise


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
    workdir: Path,
    subject: str,
    origin: Path,
    intermediates: list[Path],
) -> tuple[tuple[str, ...], int]:
    """Convert a pcapng to pcap, discarding minority link types if there is more than one.

    Returns the discarded link-type names and packet count for provenance.
    """
    if walked.truncated_at_offset is not None:
        raise CaptureError(
            f"{subject}: pcapng is truncated at offset {walked.truncated_at_offset} after "
            f"{walked.packets} packets. Unlike a pcap record, a partial pcapng block cannot "
            f"be dropped safely, so flabel will not convert it. Repair it first — "
            f"`editcap -F pcapng {origin} repaired.pcapng` rewrites the readable blocks, and "
            f"reads a gzipped capture directly — then re-run flabel on the repaired file."
        )

    if len(walked.link_types) <= 1:
        argv = ["editcap", "-F", "pcap", str(source), str(output)]
        _run_tool("editcap", argv)
        normalization.append("convert: editcap -F pcap")
        _verify_converted(output, walked.packets, "editcap", argv)
        return (), 0

    # Dominant by packet count, ties broken by the lowest link type. A tie has no meaningful
    # winner, so the rule is chosen to be *stable*: reproducibility (Goal 2) needs two runs
    # over one capture to keep the same packets, which a dict-order or first-seen rule would
    # not guarantee.
    kept_link_type, kept_packets = max(
        walked.packets_by_link_type, key=lambda item: (item[1], -item[0])
    )
    encapsulation = _editcap_encapsulation(kept_link_type, subject)
    kept_interfaces = [
        index
        for index, link_type in enumerate(walked.interface_link_types)
        if link_type == kept_link_type
    ]

    # Selection by *interface*, with a display filter. The obvious alternative — passing the
    # kept packet numbers to `editcap` as ranges — only stays small while link types arrive in
    # long runs, and a real `dumpcap -i eth0 -i lo` capture interleaves them per packet, so
    # the argument list would grow with the capture until it exceeded what a command line can
    # carry. A filter is one argument whatever the interleaving. Several interfaces can share
    # the kept link type, hence the disjunction.
    selected = workdir / SELECTED_NAME
    intermediates.append(selected)
    expression = " || ".join(f"frame.interface_id=={index}" for index in kept_interfaces)
    select_argv = [
        "tshark",
        "-r",
        str(source),
        "-Y",
        expression,
        "-F",
        "pcapng",
        "-w",
        str(selected),
    ]
    _run_tool("tshark", select_argv)

    convert_argv = ["editcap", "-F", "pcap", "-T", encapsulation, str(selected), str(output)]
    _run_tool("editcap", convert_argv)
    _verify_converted(output, kept_packets, "editcap", convert_argv)

    discarded = tuple(
        link_type_name(link_type)
        for link_type, _ in walked.packets_by_link_type
        if link_type != kept_link_type
    )
    discarded_packets = walked.packets - kept_packets
    normalization.append(
        f"select: tshark kept interface(s) "
        f"{', '.join(str(index) for index in kept_interfaces)} carrying link type "
        f"{link_type_name(kept_link_type)} ({kept_packets} packets)"
    )
    normalization.append(f"convert: editcap -F pcap -T {encapsulation}")
    normalization.append(
        f"split: discarded {discarded_packets} packets of link type(s) {', '.join(discarded)}"
    )
    return discarded, discarded_packets


# --- cleanup -------------------------------------------------------------------------------


def _missing_directories(workdir: Path) -> list[Path]:
    """`workdir` and every ancestor of it that does not exist yet, deepest first.

    `mkdir(parents=True)` can create a whole chain of directories, and a cleanup that removed
    only the leaf would leave the rest behind as debris from a run that produced nothing.
    """
    missing: list[Path] = []
    current = workdir
    while not current.exists():
        missing.append(current)
        if current.parent == current:
            break
        current = current.parent
    return missing


def _discard_output(workdir: Path, created_dirs: list[Path], intermediates: list[Path]) -> None:
    """Leave nothing behind after a failure — spec §13: no partial run directory.

    The normalized file is removed too: a caller that catches the error and carries on must
    not find a half-written capture waiting for it. Directories go only if this call created
    them, so a pre-existing `workdir` survives — it was not ours to delete — emptied of
    whatever this call put in it.

    Every removal is best-effort. This runs while an exception is in flight, and a cleanup
    that raised — an unwritable directory, an output path that turned out to be something
    else — would replace the real diagnosis with an incidental one.
    """
    for path in [*intermediates, workdir / NORMALIZED_NAME]:
        with contextlib.suppress(OSError):
            path.unlink(missing_ok=True)
    for directory in created_dirs:
        # `rmdir` refuses a non-empty directory, which is the behaviour we want: if something
        # else wrote here meanwhile, the directory is not ours to remove after all.
        with contextlib.suppress(OSError):
            directory.rmdir()
