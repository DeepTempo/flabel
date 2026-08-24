"""How a run and a flow are named — spec-label-store §3.

**Pure: no client, no network, no clock.** Every row in every table is keyed by something computed
here, and spec §2.4's testing line records that the `requires_bigquery` tests do not run in CI. So
identity is deliberately computable with nothing installed, and its tests run on every push.

Both ids are **content-derived**, which is what §5.5's rebuild claim rests on: `TRUNCATE` the
dataset, re-ingest the archive, and every id comes back the same. The things that do *not* come
back — `ingested_at`, `observed_at`, `run_exclusions` — are exactly the ones that are not derived
from content, which is why exclusions are data rather than deletions.
"""

from __future__ import annotations

from hashlib import sha256
from ipaddress import ip_address

#: Sixteen hex characters, matching the `snapshot_id` convention so the existing
#: `fullmatch(r"[0-9a-f]{16}")` guard applies unchanged.
DIGEST_CHARS = 16

#: The protos `flabel-ingest` may write a `flow_labels` row for, until #96 carries `ip_proto` on
#: `Flow`.
#:
#: `models.Flow` has no `ip_proto`, and spec §3.2 measured why that matters: Zeek writes two ESP or
#: two SCTP conversations between one host pair with **identical 5-tuples**
#: (`10.0.0.5 0 10.0.0.200 0 unknown_transport`), recording the difference only in `conn.log`'s
#: `ip_proto` column. Without it the key degenerates and two real flows produce one, whose labels
#: and sources would be unioned into a flow that never existed.
#:
#: Refusing is not a loss of labels: such detections are already `unsupported_transport` unmatched
#: detections and never became labels in the first place. `flabel-ingest` counts the refusals and
#: records them on the run, so the refusal is visible rather than silent.
WRITABLE_PROTOS = frozenset({"tcp", "udp", "icmp"})


def is_writable(proto: str) -> bool:
    """Whether a `flow_labels` row may be written for a flow of this proto (§3.2, #96)."""
    return proto.lower() in WRITABLE_PROTOS


def _endpoint(packed_and_port: tuple[bytes, int]) -> str:
    """One side of the canonical pair, as key material."""
    packed, port = packed_and_port
    return f"{ip_address(packed)}:{port}"


def canonical_pair(src_ip: str, src_port: int, dst_ip: str, dst_port: int) -> tuple[str, str]:
    """The two endpoints as key material, in canonical order — `(lo, hi)`.

    Public so it can be tested for the property that matters rather than merely for stability.
    That distinction is not academic: the sabotage round for this module replaced the packed sort
    with a sort on the address *string* and every test still passed, because a test that swaps
    src and dst only proves the sort is CONSISTENT — both calls order the same set of endpoints,
    so any consistent rule satisfies it.

    Sorting on `ip_address(...).packed` rather than on the text is what makes `9.0.0.1` come before
    `10.0.0.1` (as text, `"10." < "9."`) and what stops IPv6 being ordered against IPv4 by spelling.
    """
    lo, hi = sorted(
        (
            (ip_address(src_ip).packed, src_port),
            (ip_address(dst_ip).packed, dst_port),
        )
    )
    return _endpoint(lo), _endpoint(hi)


def flow_key(
    capture_sha256: str,
    *,
    proto: str,
    ip_proto: int,
    src_ip: str,
    src_port: int,
    dst_ip: str,
    dst_port: int,
    ts_first_iso: str,
) -> str:
    """Identity of a flow within a capture. Derived from content; **never reads Zeek's `uid`.**

    Measured on Zeek 8.0.4, 2026-08-20 (spec §3.2): under `-D` — which `docs/spec.md` §2.3 makes
    mandatory — uids are a fixed sequence assigned in connection-creation order, so the Nth
    connection of *any* capture gets the Nth value. Three unrelated captures all report
    `CJKFoj4bpHEhTeaRoj` as flow #1, and one flow carried `CRdT6w4PA64qWKmBk3` when second in a
    file and `CJKFoj4bpHEhTeaRoj` when first. A uid both collides across captures and is unstable
    for a given flow: it is a per-run observation, and there is no `uid` parameter here so that it
    cannot become one by accident.

    `ts_first_iso` is **the ISO-8601 string exactly as it appears in `labels.json`, not a float.**
    A float -> ISO -> float -> ISO round trip is where a one-microsecond drift would silently
    produce two keys for one flow, and ingest reads the serialised archive rather than a live
    `models.Flow`. The string is hashed as given; it is never parsed.

    **The endpoint pair is canonically ordered** on the *packed* address, so an orientation
    disagreement cannot split one flow into two rows — and so that IPv6 is not ordered against IPv4
    by spelling. The orientation Zeek reported is stored beside the key, not in it.

    **ICMP has no ports.** Zeek puts type in `id.orig_p` and code in `id.resp_p`, so the canonical
    sort orders on type/code. Deterministic, so identity holds — but `port_lo`/`port_hi` are not
    ports for an ICMP row and no consumer should read them as such.
    """
    lo, hi = canonical_pair(src_ip, src_port, dst_ip, dst_port)
    material = "|".join(
        (
            capture_sha256,
            proto.lower(),
            str(ip_proto),
            lo,
            hi,
            ts_first_iso,
        )
    )
    return sha256(material.encode()).hexdigest()[:DIGEST_CHARS]


def run_id(
    *,
    capture_sha256: str,
    mode: str,
    started_at_iso: str,
    flabel_version: str,
) -> str:
    """Identity of one labelling run — spec §3.3.

    Derived from the run block alone, so re-reading the same tarball computes the same id. That is
    what makes `--backfill` idempotent and what §5.3's duplicate-`run_id` short circuit relies on.

    Two honest limits, recorded in the spec rather than assumed away. **`flabel_version`
    contributes nothing today** — it is `"0.0.0"` and nobody bumps it — so uniqueness rests on
    `(capture, mode, started_at)` with a microsecond timestamp. And that holds only because there
    is **one runner**: a second concurrent runner would need the host in the material.
    """
    material = f"{capture_sha256}|{mode}|{started_at_iso}|{flabel_version}"
    return sha256(material.encode()).hexdigest()[:DIGEST_CHARS]
