"""`run_id` and `flow_key` — spec-label-store §3, and the reason neither may read Zeek's `uid`.

**Pure, and that is the whole point of putting them here.** Spec §2.4's testing line says the
`requires_bigquery` tests do not run in CI, so identity — the thing every row in every table is
keyed by — is deliberately computable without a client. These tests run on every push.

The measurement behind all of it (spec §3.2, Zeek 8.0.4, 2026-08-20): under `-D`, which
`docs/spec.md` §2.3 makes mandatory, uids are a fixed sequence in connection-creation order, so the
Nth connection of *any* capture gets the Nth value. Three unrelated captures all report
`CJKFoj4bpHEhTeaRoj` as flow #1, and one flow carried two different uids depending on its position
in the file. A uid is a per-run observation, never identity.
"""

from __future__ import annotations

import pytest

from flabeldb import identity

CAPTURE = "a" * 64
OTHER_CAPTURE = "b" * 64

#: One flow as `labels.json` serialises it. `ts_first` is the ISO STRING, which is the form
#: `flabel-ingest` actually reads — it parses the published archive, not a live `models.Flow`.
FLOW = {
    "proto": "tcp",
    "ip_proto": 6,
    "src_ip": "10.92.95.2",
    "src_port": 49161,
    "dst_ip": "10.92.67.138",
    "dst_port": 80,
    "ts_first_iso": "2023-08-27T09:20:35.672335Z",
}


def key(**changes) -> str:
    return identity.flow_key(changes.pop("capture_sha256", CAPTURE), **{**FLOW, **changes})


# --- the shape of the key ------------------------------------------------------------------


def test_a_flow_key_is_sixteen_hex_characters():
    """Matches the `snapshot_id` convention, so the existing `[0-9a-f]{16}` guard applies."""
    assert len(key()) == 16
    assert set(key()) <= set("0123456789abcdef")


def test_a_run_id_is_sixteen_hex_characters():
    found = identity.run_id(
        capture_sha256=CAPTURE,
        mode="offline",
        started_at_iso="2026-08-21T17:27:36.639594Z",
        flabel_version="0.0.0",
    )
    assert len(found) == 16
    assert set(found) <= set("0123456789abcdef")


# --- THE measurement: a uid is not identity -------------------------------------------------


def test_the_same_flow_from_two_runs_with_different_uids_has_one_key():
    """§3.2's central claim. `uid` is not an argument at all, so this cannot regress by accident —
    but it is asserted anyway, because "the parameter does not exist" is exactly the kind of thing
    a later refactor helpfully "fixes"."""
    assert key() == key()
    with pytest.raises(TypeError):
        identity.flow_key(CAPTURE, **FLOW, uid="CJKFoj4bpHEhTeaRoj")


def test_two_flows_sharing_a_five_tuple_and_differing_only_in_ts_first_are_two_flows():
    """The complement. Without `ts_first` in the material, a host pair that reconnects on the same
    source port — which is ordinary, and is #143's measured cause of unmatched detections — would
    collapse into one row and union two flows' labels."""
    assert key() != key(ts_first_iso="2023-08-27T09:20:36.672335Z")


def test_one_microsecond_apart_is_two_flows():
    assert key() != key(ts_first_iso="2023-08-27T09:20:35.672336Z")


def test_the_key_is_computed_from_the_ISO_STRING_and_never_a_reparsed_float():
    """§3.2 is explicit: a float -> ISO -> float -> ISO round trip is where a one-microsecond drift
    silently produces two keys for one flow. Two strings that would parse to the same instant must
    therefore still be distinguishable here — the string is the input, not the instant it denotes.
    """
    trailing_zeros = key(ts_first_iso="2023-08-27T09:20:35.672335Z")
    padded = key(ts_first_iso="2023-08-27T09:20:35.6723350Z")
    assert trailing_zeros != padded, (
        "the key normalised the timestamp, so it is parsing rather than hashing the string"
    )


# --- canonical ordering --------------------------------------------------------------------


def test_swapping_the_endpoints_yields_the_same_key():
    """§3.2: ordering the pair means an orientation disagreement cannot split one flow into two
    rows. `docs/spec.md` §9 already declines to require Zeek and Suricata to agree on who
    initiated; this declines to require two Zeek *versions* to."""
    swapped = key(
        src_ip=FLOW["dst_ip"],
        src_port=FLOW["dst_port"],
        dst_ip=FLOW["src_ip"],
        dst_port=FLOW["src_port"],
    )
    assert key() == swapped


def test_the_pair_is_ordered_by_packed_address_not_by_its_string_form():
    """`"10.0.0.1" < "9.0.0.1"` as TEXT and the other way round as ADDRESSES.

    **This test exists in this form because the first version of it was worthless**, and the
    sabotage round proved it: replacing the packed sort with a sort on the address string left all
    26 tests green. The original asserted only that swapping src and dst gives one key — but both
    calls order the same *set* of endpoints, so any consistent rule satisfies that. It was a test
    of stability wearing the name of a test of ordering.

    Observing `canonical_pair` directly is what distinguishes them: a string sort puts `10.0.0.1`
    first, a packed sort puts `9.0.0.1` first.
    """
    assert identity.canonical_pair("10.0.0.1", 2, "9.0.0.1", 1) == ("9.0.0.1:1", "10.0.0.1:2")
    assert identity.canonical_pair("9.0.0.1", 1, "10.0.0.1", 2) == ("9.0.0.1:1", "10.0.0.1:2")


def test_the_ordering_is_stable_under_a_swap():
    """The property the old test *did* check, kept — it is necessary, just not sufficient."""
    swapped = key(
        src_ip=FLOW["dst_ip"],
        src_port=FLOW["dst_port"],
        dst_ip=FLOW["src_ip"],
        dst_port=FLOW["src_port"],
    )
    assert key() == swapped


def test_ipv6_is_not_ordered_against_ipv4_by_spelling():
    """A 4-byte packed address always sorts before a 16-byte one; as text, `"2001:..."` sorts
    before `"9.0.0.1"`. Deterministic either way, which is precisely why only a direct check
    catches it."""
    assert identity.canonical_pair("2001:db8::1", 1, "9.0.0.1", 2) == ("9.0.0.1:2", "2001:db8::1:1")


def test_the_lower_port_breaks_a_tie_between_one_host_and_itself():
    """Zeek does report loopback conversations. Without the port in the sort key the pair would be
    unordered between two identical addresses, and `sorted` would fall back to comparing ints —
    which is what it does; this pins it rather than leaving it to tuple-comparison luck."""
    assert identity.canonical_pair("127.0.0.1", 9, "127.0.0.1", 2) == ("127.0.0.1:2", "127.0.0.1:9")


def test_a_different_capture_gives_a_different_key_for_the_same_flow():
    """Identity is *within* a capture (§3.2), which is what bounds the birthday exposure."""
    assert key() != key(capture_sha256=OTHER_CAPTURE)


# --- the ESP/SCTP collision, which is why ip_proto is in the key ----------------------------


def test_ip_proto_separates_two_flows_zeek_writes_with_identical_five_tuples():
    """`docs/spec.md` §9 step 0 measured it: two ESP or SCTP conversations between one host pair
    are written with IDENTICAL 5-tuples — `10.0.0.5 0 10.0.0.200 0 unknown_transport` — differing
    only in `conn.log`'s `ip_proto` column, 50 for ESP and 132 for SCTP.

    Without `ip_proto` the key degenerates to `(capture, "unknown_transport", ip:0, ip:0, ts)` and
    two real flows produce one key, whose labels and sources are then unioned into a flow that
    never existed.
    """
    esp = dict(
        proto="unknown_transport",
        src_ip="10.0.0.5",
        src_port=0,
        dst_ip="10.0.0.200",
        dst_port=0,
        ts_first_iso=FLOW["ts_first_iso"],
    )
    assert identity.flow_key(CAPTURE, ip_proto=50, **esp) != identity.flow_key(
        CAPTURE, ip_proto=132, **esp
    )


def test_proto_is_lowercased_so_zeek_casing_cannot_split_a_flow():
    assert key(proto="TCP") == key(proto="tcp")


# --- what ingest may write, until #96 lands -------------------------------------------------


@pytest.mark.parametrize("proto", ["tcp", "udp", "icmp"])
def test_the_three_supported_protos_are_writable(proto):
    assert identity.is_writable(proto) is True


@pytest.mark.parametrize("proto", ["unknown_transport", "esp", "sctp", "gre", ""])
def test_any_other_proto_is_refused_until_ip_proto_is_carried(proto):
    """§3.2: `Flow` does not carry `ip_proto`, so until #96 lands `flabel-ingest` refuses to write
    a `flow_labels` row for such a flow, counts the refusal, and records it on the run.

    Refusing is not a loss of labels — these detections are already `unsupported_transport`
    unmatched detections and never became labels in the first place.
    """
    assert identity.is_writable(proto) is False


def test_the_writable_set_is_case_insensitive():
    assert identity.is_writable("TCP") is True


# --- run_id ---------------------------------------------------------------------------------


def test_run_id_is_derived_from_the_run_block_alone_so_a_reread_recomputes_it():
    """§3.3: re-reading the same tarball computes the same id, which is what makes `--backfill`
    idempotent and what the duplicate-`run_id` guard in §5.3 relies on."""
    args = dict(
        capture_sha256=CAPTURE,
        mode="offline",
        started_at_iso="2026-08-21T17:27:36.639594Z",
        flabel_version="0.0.0",
    )
    assert identity.run_id(**args) == identity.run_id(**args)


@pytest.mark.parametrize(
    "field, value",
    [
        ("capture_sha256", OTHER_CAPTURE),
        ("mode", "both"),
        ("started_at_iso", "2026-08-21T17:27:36.639595Z"),
        ("flabel_version", "0.1.0"),
    ],
)
def test_every_component_of_the_run_id_changes_it(field, value):
    """All four, separately. "the id changes" is satisfied by code that reads only one of them —
    and `mode` is the one that matters most, because the same capture labelled `--offline` and then
    `--both` is two runs whose rows must not collide."""
    args = dict(
        capture_sha256=CAPTURE,
        mode="offline",
        started_at_iso="2026-08-21T17:27:36.639594Z",
        flabel_version="0.0.0",
    )
    assert identity.run_id(**args) != identity.run_id(**{**args, field: value})


def test_the_run_id_does_not_read_the_wall_clock():
    """It is content-derived or it is not an identity. §5.5's rebuild claim rests on this."""
    args = dict(
        capture_sha256=CAPTURE,
        mode="offline",
        started_at_iso="2026-08-21T17:27:36.639594Z",
        flabel_version="0.0.0",
    )
    first = identity.run_id(**args)
    assert identity.run_id(**args) == first


# --- deriving ip_proto, which labels.json does not carry ----------------------------------------


@pytest.mark.parametrize("proto, number", [("icmp", 1), ("tcp", 6), ("udp", 17)])
def test_the_writable_protos_have_their_iana_number(proto, number):
    """`labels.json` carries no `ip_proto` (#96), so ingest derives it from the name."""
    assert identity.ip_proto_of(proto) == number
    assert identity.ip_proto_of(proto.upper()) == number


def test_the_writable_set_and_the_numbers_are_one_fact():
    """Written twice they would drift, and the drift would be silent: a proto in the writable set
    with no number crashes ingest, and a number with no writable entry is dead code."""
    assert frozenset(identity.IP_PROTO_BY_NAME) == identity.WRITABLE_PROTOS


@pytest.mark.parametrize("proto", ["unknown_transport", "esp", "sctp", "gre"])
def test_an_unwritable_proto_has_no_derivable_number_and_is_not_guessed(proto):
    """THE REASON the refusal is safe rather than merely cautious. `unknown_transport` is exactly
    the case where the name does not determine the number — 50 for ESP, 132 for SCTP, and Zeek
    writes both with identical 5-tuples — so a default here would reinstate the very collision
    `ip_proto` is in the key to prevent."""
    with pytest.raises(ValueError, match="no derivable ip_proto"):
        identity.ip_proto_of(proto)


def test_every_writable_proto_can_actually_be_keyed():
    """The two halves meeting: anything `is_writable` admits must survive `flow_key`."""
    for proto in sorted(identity.WRITABLE_PROTOS):
        assert identity.is_writable(proto)
        assert len(key(proto=proto, ip_proto=identity.ip_proto_of(proto))) == 16
