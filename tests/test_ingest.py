"""Ingest and normalization (spec §8 "Ingest", PLAN.md step 3).

Every awkward input gets the outcome spec §8 names, and the two loss conditions ingest owns
(spec §11: input truncated, multi-datalink discard) get their fault injection here.

Fixtures are **generated, never committed**: `tests/fixtures/make_awkward.py` writes them into
`tmp_path`. Committed capture bytes cannot be reviewed, and this repository is public.

`editcap` and `capinfos` run for real (spec §2, "tools real, network stubbed"), and `capinfos`
is deliberately used as an *independent* oracle for packet counts and encapsulation: flabel's
own record-header walk is the thing under test, so checking it against flabel's own reader
would prove only that the code agrees with itself. Nothing here touches the network.
"""

from __future__ import annotations

import gzip
import re
import struct
import subprocess
import sys
from pathlib import Path

import pytest

from flabel.errors import CaptureError, ToolError
from flabel.ingest import (
    LINK_TYPES,
    NORMALIZED_NAME,
    EditcapError,
    link_type_name,
    normalize,
    sniff,
)

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"
if str(FIXTURE_DIR) not in sys.path:
    sys.path.insert(0, str(FIXTURE_DIR))

import make_awkward as awkward  # noqa: E402  (needs the path entry above)
import make_canary as canary  # noqa: E402

BENIGN = FIXTURE_DIR / "benign.pcap"

#: The canary capture's shape, asserted directly rather than derived, so a change to the
#: generator that silently altered the fixture would fail here instead of passing quietly.
CANARY_PACKETS = 14


# --- helpers -------------------------------------------------------------------------------


def capinfos(path: Path, *flags: str) -> str:
    """Run `capinfos` and return its report. Raises if the tool rejects the file."""
    result = subprocess.run(
        ["capinfos", *flags, str(path)], capture_output=True, text=True, check=True
    )
    return result.stdout


def capinfos_packet_count(path: Path) -> int:
    match = re.search(r"Number of packets:\s+(\d+)", capinfos(path, "-c"))
    assert match is not None, f"capinfos reported no packet count for {path}"
    return int(match.group(1))


def capinfos_encapsulation(path: Path) -> str:
    match = re.search(r"File encapsulation:\s+(.+)", capinfos(path, "-E"))
    assert match is not None, f"capinfos reported no encapsulation for {path}"
    return match.group(1).strip()


def is_pcap(path: Path) -> bool:
    with path.open("rb") as handle:
        return handle.read(4) in (
            b"\xa1\xb2\xc3\xd4",
            b"\xd4\xc3\xb2\xa1",
            b"\xa1\xb2\x3c\x4d",
            b"\x4d\x3c\xb2\xa1",
        )


def pcap_frames(path: Path) -> list[bytes]:
    """Every frame in a little-endian pcap, for comparing kept packets to the originals."""
    blob = path.read_bytes()
    frames: list[bytes] = []
    offset = 24
    while offset + 16 <= len(blob):
        captured = struct.unpack("<I", blob[offset + 8 : offset + 12])[0]
        frames.append(blob[offset + 16 : offset + 16 + captured])
        offset += 16 + captured
    return frames


# --- the generator itself ------------------------------------------------------------------


def test_generated_plain_pcap_reproduces_the_committed_canary(tmp_path):
    """`make_awkward` and the committed `benign.pcap` cannot drift apart unnoticed.

    Everything else here generates its input, so if the committed canary ever stopped matching
    what the generator produces, the two halves of the fixture strategy would be testing
    different captures. Byte equality also re-proves `make_canary`'s determinism claim.
    """
    generated = awkward.write_plain_pcap(tmp_path / "plain.pcap")
    assert generated.read_bytes() == BENIGN.read_bytes()


def test_fixtures_are_byte_deterministic(tmp_path):
    """Two generations produce identical bytes — including the gzipped variants.

    Gzip stores an mtime and optionally a filename; either would make the compressed fixtures
    differ run to run, and a fixture that is not byte-stable cannot support a reproducibility
    gate (Goal 2).
    """
    first = awkward.write_all(tmp_path / "first")
    second = awkward.write_all(tmp_path / "second")

    assert sorted(first) == sorted(second)
    differing = [name for name in first if first[name].read_bytes() != second[name].read_bytes()]
    assert not differing, f"non-deterministic fixtures: {differing}"


def test_every_generated_fixture_is_what_it_claims(tmp_path):
    """A generated fixture with the wrong magic bytes would test the wrong code path."""
    written = awkward.write_all(tmp_path)
    expected = {
        "plain.pcap": "pcap",
        "plain.pcapng": "pcapng",
        "truncated.pcap": "pcap",
        "truncated_record_header.pcap": "pcap",
        "truncated.pcapng": "pcapng",
        "multi_datalink.pcapng": "pcapng",
        "plain.pcap.gz": "gzip",
        "plain.pcapng.gz": "gzip",
    }
    assert {name: sniff(written[name]) for name in expected} == expected


# --- sniffing ------------------------------------------------------------------------------


def test_format_is_sniffed_by_magic_not_by_extension(tmp_path):
    """A misnamed capture is ordinary, and the name must never decide the code path."""
    lying = tmp_path / "definitely_a_pcap.pcap"
    awkward.write_plain_pcapng(lying)
    assert sniff(lying) == "pcapng"

    also_lying = tmp_path / "not_compressed.pcapng"
    awkward.write_gzipped(BENIGN, also_lying)
    assert sniff(also_lying) == "gzip"

    normalized = normalize(also_lying, tmp_path / "out")
    assert normalized.capture_format == "pcap.gz"


@pytest.mark.parametrize("variant", sorted(awkward.PCAP_VARIANTS))
def test_all_four_pcap_magics_are_recognised(tmp_path, variant):
    """Spec §8 step 1 names four pcap magics, and all four have to walk correctly.

    Byte order and timestamp precision are encoded *in the magic*, so a reader that assumes
    the common little-endian microsecond variant does not fail at the magic — it fails at the
    first record header, reading a length from the wrong end of the word. A capture from a
    big-endian host or a nanosecond-resolution capture is ordinary, not exotic.
    """
    byte_order, nanosecond = awkward.PCAP_VARIANTS[variant]
    capture = awkward.write_pcap_variant(tmp_path / f"{variant}.pcap", byte_order, nanosecond)

    assert sniff(capture) == "pcap"
    result = normalize(capture, tmp_path / "out")
    assert result.capture_format == "pcap"
    assert result.packets_read == CANARY_PACKETS
    assert result.input_status == "complete"
    assert result.path.read_bytes() == capture.read_bytes()


def test_the_default_pcap_variant_is_the_canary_byte_for_byte(tmp_path):
    """The variant writer and `make_canary`'s writer agree, so the parametrised test above
    is exercising the same capture in four encodings rather than four different captures."""
    assert awkward.write_pcap_variant(tmp_path / "default.pcap").read_bytes() == BENIGN.read_bytes()


@pytest.mark.requires_tools
@pytest.mark.parametrize("variant", sorted(awkward.PCAP_VARIANTS))
def test_the_toolchain_agrees_on_every_pcap_variant(tmp_path, variant):
    """Independent confirmation that the variant fixtures are real pcap files.

    Without this, a variant writer that produced something only flabel could read would make
    the test above pass while proving nothing.
    """
    byte_order, nanosecond = awkward.PCAP_VARIANTS[variant]
    capture = awkward.write_pcap_variant(tmp_path / f"{variant}.pcap", byte_order, nanosecond)
    assert capinfos_packet_count(capture) == CANARY_PACKETS
    assert capinfos_encapsulation(capture) == "Ethernet"


@pytest.mark.requires_tools
def test_the_compressed_payload_is_sniffed_too(tmp_path):
    """A `.pcap.gz` holding a pcapng: gzip says nothing about what it wraps.

    The inner format decides whether `editcap` runs, so it is sniffed after decompression
    rather than inferred from the outer name — which here would be wrong twice over.
    """
    inner = awkward.write_plain_pcapng(tmp_path / "inner.pcapng")
    capture = awkward.write_gzipped(inner, tmp_path / "misleading.pcap.gz")

    result = normalize(capture, tmp_path / "out")

    assert result.capture_format == "pcapng.gz"
    assert result.normalization == ("decompress: gzip", "convert: editcap -F pcap")
    assert is_pcap(result.path)


def test_unrecognised_magic_is_rejected(tmp_path):
    with pytest.raises(CaptureError, match="unrecognised capture format"):
        sniff(awkward.write_bad_header(tmp_path / "bad_header.pcap"))


def test_missing_file_is_a_capture_error(tmp_path):
    with pytest.raises(CaptureError, match="not a readable file"):
        normalize(tmp_path / "absent.pcap", tmp_path / "out")


# --- the complete-input control case -------------------------------------------------------


def test_plain_pcap_round_trips_byte_identically(tmp_path):
    """The whole point of normalization is that a pcap needs none of it.

    A byte-identical copy is the strongest available statement that nothing was silently
    rewritten, and it is what makes `sha256` meaningful as an input identity downstream.
    """
    workdir = tmp_path / "out"
    result = normalize(BENIGN, workdir)

    assert result.path == workdir / NORMALIZED_NAME
    assert result.path.read_bytes() == BENIGN.read_bytes()
    assert result.original_path == BENIGN
    assert result.capture_format == "pcap"
    assert result.input_status == "complete"
    assert result.packets_read == CANARY_PACKETS
    assert result.truncated_at_offset is None
    assert result.discarded_link_types == ()
    assert result.discarded_packets == 0
    assert result.normalization == ()
    assert result.bytes_total == BENIGN.stat().st_size
    assert list(workdir.iterdir()) == [result.path], "workdir must hold only the normalized file"


def test_recorded_hash_and_size_describe_the_input_as_given(tmp_path):
    """`sha256`/`bytes_total` identify the operator's file, compression included.

    A compressed capture hashes as the compressed bytes: `capture_format` says `pcap.gz`, so
    the three fields describe one consistent object — the thing that was handed to flabel —
    and the normalized file is reached from it through the recorded `normalization` steps.
    """
    compressed = awkward.write_gzipped(BENIGN, tmp_path / "benign.pcap.gz")
    result = normalize(compressed, tmp_path / "out")

    assert result.bytes_total == compressed.stat().st_size < BENIGN.stat().st_size
    assert result.sha256 == _sha256_of(compressed)
    assert result.sha256 != _sha256_of(BENIGN)


def _sha256_of(path: Path) -> str:
    import hashlib

    return hashlib.sha256(path.read_bytes()).hexdigest()


@pytest.mark.requires_tools
def test_walk_agrees_with_capinfos_on_complete_captures(tmp_path):
    """flabel's own walk is checked against the toolchain's reader, not against itself.

    The walk exists because no tool reports a truncation *offset* — but its packet count must
    still match what the tools see, or every downstream count is quietly wrong.
    """
    for fixture in (
        awkward.write_plain_pcap(tmp_path / "plain.pcap"),
        awkward.write_plain_pcapng(tmp_path / "plain.pcapng"),
    ):
        result = normalize(fixture, tmp_path / f"out-{fixture.suffix}")
        assert result.packets_read == capinfos_packet_count(fixture) == CANARY_PACKETS


# --- truncated pcap: partial, with an offset ------------------------------------------------


def test_truncated_pcap_is_partial_with_the_offset_of_the_short_record(tmp_path):
    """Spec §8 step 5 and §11's first loss condition: proceed, and say where it stopped."""
    capture = tmp_path / "truncated.pcap"
    offset = awkward.write_truncated_pcap(capture, keep=10, missing=8)

    result = normalize(capture, tmp_path / "out")

    assert result.input_status == "partial"
    assert result.truncated_at_offset == offset
    assert result.packets_read == 10
    assert result.capture_format == "pcap"
    assert result.normalization == (f"trim: dropped incomplete final record at offset {offset}",)


def test_truncation_offset_is_the_record_start_computed_independently(tmp_path):
    """The offset is pinned by arithmetic, not by whatever the generator happened to return.

    Both the generator and `ingest` could be wrong in the same direction; the pcap layout —
    a 24-byte file header then a 16-byte header per record — is the third opinion.
    """
    capture = tmp_path / "truncated.pcap"
    awkward.write_truncated_pcap(capture, keep=10, missing=8)
    packets = canary.build_packets()
    expected = 24 + sum(16 + len(frame) for _, frame in packets[:10])

    assert normalize(capture, tmp_path / "out").truncated_at_offset == expected


def test_truncation_inside_a_record_header_still_reports_that_record(tmp_path):
    """A cut so early there is no length to read: the offset is still the record's start.

    This is the case a length-driven reader gets wrong — with fewer than 16 bytes left there
    is no `caplen` to compare against the file size, so the short read itself has to be the
    signal.
    """
    capture = tmp_path / "truncated_record_header.pcap"
    offset = awkward.write_truncated_pcap(capture, keep=10, missing=80)
    assert capture.stat().st_size - offset < 16, "fixture must cut inside the record header"

    result = normalize(capture, tmp_path / "out")

    assert result.input_status == "partial"
    assert result.truncated_at_offset == offset
    assert result.packets_read == 10


@pytest.mark.requires_tools
def test_trimmed_output_is_cleanly_readable_by_the_toolchain(tmp_path):
    """The reason the incomplete tail record is dropped rather than passed through.

    libpcap errors on a short final record, so an untrimmed copy would turn one reportable
    partial input into tool failures in Zeek and Suricata. `capinfos` refusing the input but
    accepting the output is exactly that difference.
    """
    capture = tmp_path / "truncated.pcap"
    awkward.write_truncated_pcap(capture, keep=10, missing=8)

    rejected = subprocess.run(["capinfos", "-c", str(capture)], capture_output=True, text=True)
    assert rejected.returncode != 0, "fixture is supposed to be a capture the tools object to"
    assert "cut short" in rejected.stderr

    result = normalize(capture, tmp_path / "out")
    assert capinfos_packet_count(result.path) == 10
    assert capinfos_encapsulation(result.path) == "Ethernet"


# --- truncated pcapng and bad header: hard failure, no output --------------------------------


def test_truncated_pcapng_fails_and_names_editcap(tmp_path):
    """Spec §8 step 6. A partial block cannot be converted safely, so it is not attempted.

    The message has to be actionable: an operator holding a half-copied pcapng needs the
    repair command, not a diagnosis.
    """
    capture = tmp_path / "truncated.pcapng"
    offset = awkward.write_truncated_pcapng(capture, keep=10, missing=8)
    workdir = tmp_path / "out"

    with pytest.raises(CaptureError) as raised:
        normalize(capture, workdir)

    message = str(raised.value)
    assert f"offset {offset}" in message
    assert "editcap" in message
    assert not workdir.exists(), "a hard failure must leave no output directory (spec §13)"


def test_bad_header_fails_and_leaves_no_output(tmp_path):
    """Spec §8 step 4, for a file that is not a capture at all."""
    capture = awkward.write_bad_header(tmp_path / "bad_header.pcap")
    workdir = tmp_path / "out"

    with pytest.raises(CaptureError):
        normalize(capture, workdir)
    assert not workdir.exists()


def test_gzipped_bad_header_leaves_no_output_and_no_temporary_file(tmp_path):
    """The failure path that has already written to disk before it can validate.

    Decompression precedes validation (spec §8 steps 2-3), so this is the one case where the
    workdir exists at the moment of failure. It must not survive: `cli.py` distinguishes "a
    complete run directory" from "none", with nothing in between (spec §13).
    """
    inner = awkward.write_bad_header(tmp_path / "inner.pcap")
    capture = awkward.write_gzipped(inner, tmp_path / "bad_header.pcap.gz")
    workdir = tmp_path / "out"

    with pytest.raises(CaptureError):
        normalize(capture, workdir)
    assert not workdir.exists()


def test_a_pre_existing_workdir_is_emptied_but_kept(tmp_path):
    """A directory flabel did not create is not flabel's to delete — only its contents are."""
    capture = awkward.write_gzipped(
        awkward.write_bad_header(tmp_path / "inner.pcap"), tmp_path / "bad.pcap.gz"
    )
    workdir = tmp_path / "out"
    workdir.mkdir()
    bystander = workdir / "someone_elses.txt"
    bystander.write_text("not ours")

    with pytest.raises(CaptureError):
        normalize(capture, workdir)

    assert workdir.is_dir()
    assert list(workdir.iterdir()) == [bystander]


def test_corrupt_gzip_is_a_capture_error(tmp_path):
    capture = awkward.write_corrupt_gzip(tmp_path / "corrupt.pcap.gz")
    workdir = tmp_path / "out"

    with pytest.raises(CaptureError, match="gzip decompression failed"):
        normalize(capture, workdir)
    assert not workdir.exists()


# --- gzip is transparent --------------------------------------------------------------------


def test_gzipped_pcap_is_transparent(tmp_path):
    """Same packets, same bytes out, format records the compression."""
    capture = awkward.write_gzipped(BENIGN, tmp_path / "benign.pcap.gz")
    result = normalize(capture, tmp_path / "out")

    assert result.capture_format == "pcap.gz"
    assert result.normalization == ("decompress: gzip",)
    assert result.input_status == "complete"
    assert result.packets_read == CANARY_PACKETS
    assert result.path.read_bytes() == BENIGN.read_bytes()
    assert list(result.path.parent.iterdir()) == [result.path], "no intermediate left behind"


def test_gzipped_truncated_pcap_reports_the_uncompressed_offset(tmp_path):
    """Compression and truncation compose, and the offset is into the decompressed stream.

    A gzip member has no record boundaries, so an offset into the compressed file would be
    meaningless. Stating which file the offset refers to is the difference between a usable
    provenance field and a number nobody can act on.
    """
    plain = tmp_path / "truncated.pcap"
    offset = awkward.write_truncated_pcap(plain, keep=10, missing=8)
    capture = awkward.write_gzipped(plain, tmp_path / "truncated.pcap.gz")

    result = normalize(capture, tmp_path / "out")

    assert result.capture_format == "pcap.gz"
    assert result.input_status == "partial"
    assert result.truncated_at_offset == offset
    assert result.packets_read == 10
    assert result.normalization == (
        "decompress: gzip",
        f"trim: dropped incomplete final record at offset {offset}",
    )


@pytest.mark.requires_tools
def test_gzipped_pcapng_is_transparent(tmp_path):
    """Both transformations recorded, in the order they were applied."""
    plain = awkward.write_plain_pcapng(tmp_path / "plain.pcapng")
    capture = awkward.write_gzipped(plain, tmp_path / "plain.pcapng.gz")

    result = normalize(capture, tmp_path / "out")

    assert result.capture_format == "pcapng.gz"
    assert result.normalization == ("decompress: gzip", "convert: editcap -F pcap")
    assert result.input_status == "complete"
    assert result.packets_read == CANARY_PACKETS
    assert is_pcap(result.path)
    assert capinfos_packet_count(result.path) == CANARY_PACKETS


# --- pcapng conversion ----------------------------------------------------------------------


@pytest.mark.requires_tools
def test_pcapng_is_converted_to_pcap(tmp_path):
    capture = awkward.write_plain_pcapng(tmp_path / "plain.pcapng")
    result = normalize(capture, tmp_path / "out")

    assert result.capture_format == "pcapng"
    assert result.normalization == ("convert: editcap -F pcap",)
    assert result.input_status == "complete"
    assert result.packets_read == CANARY_PACKETS
    assert result.discarded_link_types == ()
    assert result.discarded_packets == 0
    assert is_pcap(result.path), "downstream tools read one pcap; a pcapng here is a defect"
    assert capinfos_packet_count(result.path) == CANARY_PACKETS
    assert capinfos_encapsulation(result.path) == "Ethernet"
    assert pcap_frames(result.path) == [frame for _, frame in canary.build_packets()]


@pytest.mark.requires_tools
def test_conversion_is_reproducible(tmp_path):
    """Two conversions of one capture are byte-identical — the Goal 2 precondition here."""
    capture = awkward.write_plain_pcapng(tmp_path / "plain.pcapng")
    first = normalize(capture, tmp_path / "first")
    second = normalize(capture, tmp_path / "second")

    assert first.path.read_bytes() == second.path.read_bytes()
    assert first.sha256 == second.sha256
    assert first.normalization == second.normalization


# --- multi-datalink: dominant kept, discards recorded ---------------------------------------


@pytest.mark.requires_tools
def test_multi_datalink_keeps_the_dominant_type_and_records_the_discards(tmp_path):
    """Spec §8 step 7 and §11's second loss condition.

    pcap cannot express two link types, so something has to go. What must not happen is
    losing it silently: `discarded_link_types`, `discarded_packets` and `partial` together are
    what stop this from looking like a complete capture downstream.
    """
    capture = awkward.write_multi_datalink_pcapng(tmp_path / "multi.pcapng")
    result = normalize(capture, tmp_path / "out")

    assert result.input_status == "partial"
    assert result.packets_read == CANARY_PACKETS
    assert result.discarded_link_types == ("LINUX_SLL",)
    assert result.discarded_packets == 4
    assert result.truncated_at_offset is None
    assert result.normalization == (
        "convert: editcap -F pcap",
        "split: kept link type EN10MB (10 packets); discarded 4 packets of link type(s) LINUX_SLL",
    )

    assert capinfos_packet_count(result.path) == 10
    assert capinfos_encapsulation(result.path) == "Ethernet"
    # The kept packets are the Ethernet ones, not merely ten of the fourteen.
    assert pcap_frames(result.path) == [frame for _, frame in canary.build_packets()[:10]]


@pytest.mark.requires_tools
def test_dominance_is_by_packet_count_not_by_ethernet_preference(tmp_path):
    """Flip the majority and the kept type flips with it.

    Without this, a rule that happened to prefer Ethernet — or the first interface — would
    pass the test above while discarding the bulk of a cooked-capture trace.
    """
    capture = awkward.write_multi_datalink_pcapng(
        tmp_path / "sll_dominant.pcapng", ethernet=4, other=10
    )
    result = normalize(capture, tmp_path / "out")

    assert result.discarded_link_types == ("EN10MB",)
    assert result.discarded_packets == 4
    assert capinfos_packet_count(result.path) == 10
    assert capinfos_encapsulation(result.path) == "Linux cooked-mode capture v1"


@pytest.mark.requires_tools
def test_a_tie_resolves_the_same_way_every_time(tmp_path):
    """Equal counts have no meaningful winner, so the rule only has to be *stable*.

    Reproducibility (Goal 2) requires two runs over one capture to keep the same packets;
    lowest link type wins, and both runs are compared here rather than trusting the tie-break
    to dictionary order.
    """
    capture = awkward.write_multi_datalink_pcapng(tmp_path / "tie.pcapng", ethernet=7, other=7)
    first = normalize(capture, tmp_path / "first")
    second = normalize(capture, tmp_path / "second")

    assert first.discarded_link_types == second.discarded_link_types == ("LINUX_SLL",)
    assert first.discarded_packets == second.discarded_packets == 7
    assert first.path.read_bytes() == second.path.read_bytes()


def test_an_unnameable_dominant_link_type_fails_loudly(tmp_path):
    """`editcap -T` needs a name for the kept type, and there is no guessing it.

    Discarding link types forces `-T` (editcap picks the output encapsulation from the
    interface blocks, not from the surviving packets), and `-T` is an assertion about what the
    kept packets are. Asserting the wrong link type would corrupt every downstream flow, so an
    unknown type is a hard failure with instructions instead.
    """
    capture = awkward.write_multi_datalink_pcapng(
        tmp_path / "unnameable.pcapng",
        ethernet=4,
        other=10,
        other_linktype=awkward.LINKTYPE_USER0,
    )
    workdir = tmp_path / "out"

    with pytest.raises(CaptureError, match="LINKTYPE_147") as raised:
        normalize(capture, workdir)

    assert "editcap -T" in str(raised.value)
    assert not workdir.exists()


def test_link_type_names_cover_the_generators_types():
    """Both link types the fixtures use are named, and the unnameable one really isn't."""
    assert link_type_name(1) == "EN10MB"
    assert link_type_name(awkward.LINKTYPE_LINUX_SLL) == "LINUX_SLL"
    assert link_type_name(awkward.LINKTYPE_USER0) == "LINKTYPE_147"
    assert awkward.LINKTYPE_USER0 not in LINK_TYPES


# --- tool failure ---------------------------------------------------------------------------


def test_missing_editcap_raises_a_tool_error_carrying_the_failure(tmp_path, monkeypatch):
    """Spec §11's "point at a non-existent binary" fault injection.

    PATH is emptied rather than `subprocess` patched: the failure being injected is an
    environment fault, and patching the call would test our mock of `editcap` instead of our
    handling of its absence. `EditcapError` is a `ToolError`, so `cli.py` gets exit 1 whether
    or not it knows to read `.failure`.
    """
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    capture = awkward.write_plain_pcapng(tmp_path / "plain.pcapng")
    workdir = tmp_path / "out"

    with pytest.raises(ToolError) as raised:
        normalize(capture, workdir)

    error = raised.value
    assert isinstance(error, EditcapError)
    assert error.failure.tool == "editcap"
    assert error.failure.exit_code is None
    assert error.failure.argv[0] == "editcap"
    assert "-F" in error.failure.argv and "pcap" in error.failure.argv
    assert not workdir.exists(), "a failed conversion must leave no output"


@pytest.mark.requires_tools
def test_a_real_non_zero_editcap_exit_is_reported(tmp_path):
    """The other half of spec §11's tool-failure row: a genuine non-zero exit and its stderr.

    Injected through the environment — the output path is occupied by a directory, so the real
    `editcap` fails to open it — rather than by patching `subprocess`, which would test our
    imitation of the tool instead of our handling of it. Deliberately not a permissions trick:
    CI runs as root in the toolchain container, where permissions are advisory.
    """
    capture = awkward.write_plain_pcapng(tmp_path / "plain.pcapng")
    workdir = tmp_path / "out"
    (workdir / NORMALIZED_NAME).mkdir(parents=True)

    with pytest.raises(EditcapError) as raised:
        normalize(capture, workdir)

    failure = raised.value.failure
    assert failure.exit_code not in (0, None), "the tool's own exit code, not a stand-in"
    assert failure.message.strip()
    assert (workdir / NORMALIZED_NAME).is_dir(), "cleanup must not delete what it did not write"
    assert list((workdir / NORMALIZED_NAME).iterdir()) == []


# --- structural guards ---------------------------------------------------------------------


def test_ingest_makes_no_network_call(tmp_path):
    """Spec §2.2: a labelling run performs no network I/O, and ingest is on that path.

    `test_architecture.py` proves the module imports no socket; this proves the *runtime* path
    opens none, which is the claim that matters. Cheap enough to keep next to the behaviour it
    guards.
    """
    import socket

    def refuse(*args, **kwargs):
        raise AssertionError("ingest attempted a network connection")

    original = socket.socket
    socket.socket = refuse  # type: ignore[assignment]
    try:
        assert normalize(BENIGN, tmp_path / "out").packets_read == CANARY_PACKETS
    finally:
        socket.socket = original  # type: ignore[assignment]


def test_gzip_fixtures_store_no_mtime(tmp_path):
    """The determinism claim, checked at the format level rather than by comparison alone.

    A stored mtime is the usual reason two gzips of one file differ, and it would only show up
    as flakiness minutes apart. Byte 4 of the header is where it lives.
    """
    compressed = awkward.write_gzipped(BENIGN, tmp_path / "benign.pcap.gz")
    assert struct.unpack("<I", compressed.read_bytes()[4:8])[0] == 0
    with gzip.open(compressed, "rb") as handle:
        assert handle.read() == BENIGN.read_bytes()
