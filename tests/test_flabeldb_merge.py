"""The merge rule — spec-label-store §5.1, §5.2, and the two failures §9 says must never be quiet.

**These are the tests that matter and they are pure.** §2's testing line records that the
`requires_bigquery` tests run on `fl-replay` and nowhere else, so the one rule the store exists to
express is checked here, on every push, over plain dicts — not behind a client.

§9 also records that this path **has never met real data**: both measured captures put exactly one
source on every labelled flow, 432/432 and 367/367 (#144). Every cross-tier composition below is a
fixture, and that is the whole of the evidence for it.
"""

from __future__ import annotations

import dataclasses

import pytest

from flabel import labels as labels_module
from flabel.models import LABEL_KINDS, Label, SourceEntry
from flabeldb import merge

CAPTURE = "a" * 64
OTHER_CAPTURE = "b" * 64
FLOW_KEY = "3c9a" + "0" * 60
TIER1_RUN = "1111111111111111"
TIER2_RUN = "2222222222222222"
BOTH_RUN = "b0b0b0b0b0b0b0b0"


# --- fixtures ------------------------------------------------------------------------------------


def source(*, tier: int, sid: int, name: str = "et-open", rev: int = 1, **overrides) -> dict:
    """One `sources` struct as §4.3 stores it. Keys are `models.SourceEntry`'s, by construction."""
    row = {
        "tier": tier,
        "source": name,
        "sid": sid,
        "rev": rev,
        "ruleset": "8c9e8d58af0a8d64",
        "admission_basis": "wholesale",
        "licence": "unstated",
        "classtype": "trojan-activity",
        "label_basis": "direct",
        "threat": f"threat {sid}",
        "direction": "to_server",
    }
    row.update(overrides)
    assert set(row) == set(merge.SOURCE_FIELDS), "fixture drifted from models.SourceEntry"
    return row


def entry(*, name: str, value, tier: int, sids: list[int]) -> dict:
    """One `labels` struct. `value` is REPEATED in §4.3 even for a single-arity kind."""
    return {
        "name": name,
        "value": value if isinstance(value, list) else [value],
        "tier": tier,
        "sids": sids,
    }


def flow_struct(**overrides) -> dict:
    row = {
        "proto": "tcp",
        "ip_proto": 6,
        "ip_lo": "10.0.0.1",
        "port_lo": 1234,
        "ip_hi": "10.0.0.2",
        "port_hi": 443,
        "src_ip": "10.0.0.1",
        "src_port": 1234,
        "dst_ip": "10.0.0.2",
        "dst_port": 443,
        "ts_first": "2026-07-08T12:00:00.000000Z",
        "ts_last": "2026-07-08T12:00:09.000000Z",
        "zeek_uid": "CabCdE1",
        "ja4": None,
        "ja4s": None,
        "server_name": None,
    }
    row.update(overrides)
    return row


def row(
    *,
    run_id: str,
    sources: list[dict],
    entries: list[dict] | None = None,
    capture: str = CAPTURE,
    flow_key: str = FLOW_KEY,
    flow: dict | None = None,
) -> dict:
    """One `flow_labels` row. `entries` defaults to the verdict the writer would have stored."""
    if entries is None:
        entries = [
            entry(
                name="verdict",
                value="malicious",
                tier=min(item["tier"] for item in sources),
                sids=sorted({item["sid"] for item in sources}),
            )
        ]
    return {
        "run_id": run_id,
        "capture_sha256": capture,
        "flow_key": flow_key,
        "flow": flow if flow is not None else flow_struct(),
        "best_tier": min(item["tier"] for item in sources),
        "labels": entries,
        "sources": sources,
    }


def authority_of(**by_capture_tier) -> merge.Authority:
    """`authority({...})` from `tier1=`/`tier2=` keywords, for the ordinary single-capture case."""
    rows = [
        {"capture_sha256": CAPTURE, "tier": int(key[-1]), "run_id": run_id}
        for key, run_id in by_capture_tier.items()
    ]
    return merge.authority(rows)


# --- §5.2 rule 2: the tier filter ------------------------------------------------------------


def test_a_both_run_authoritative_for_tier_1_contributes_no_tier_2_sources():
    """§5.2 rule 2, and the plan's first named test.

    A `--both` run asserts both tiers. When a newer `--offline` run has superseded its tier 2, the
    tier-2 half of what it said is **not** knowledge any more — keeping it would be the pure
    accumulation §5.1 rejected, inside a dataset whose purpose is ground truth.
    """
    both = row(
        run_id=BOTH_RUN,
        sources=[source(tier=1, sid=700, name="panw"), source(tier=2, sid=2001)],
    )
    merged = merge.compose([both], authority_of(tier1=BOTH_RUN))

    (record,) = merged.flows
    assert [item.tier for item in record.label.sources] == [1]
    assert [item.sid for item in record.label.sources] == [700]
    assert record.run_ids == {"1": BOTH_RUN}


def test_the_dropped_tier_takes_its_sids_out_of_the_verdict_with_it():
    """The reason §5.2 names `verdict_entry` and not just `Label`.

    The stored verdict entry on that `--both` row cites **both** sids, because every source on a
    flow asserts the verdict. Merging the stored entry forward would leave the record citing sid
    2001 with no tier-2 source behind it — untraceable, and `Label.__post_init__` refuses it. So
    the verdict is rebuilt from what survived rather than carried over.
    """
    both = row(
        run_id=BOTH_RUN,
        sources=[source(tier=1, sid=700, name="panw"), source(tier=2, sid=2001)],
    )
    assert both["labels"][0]["sids"] == [700, 2001], "the fixture must store what a writer stores"

    (record,) = merge.compose([both], authority_of(tier1=BOTH_RUN)).flows
    (verdict,) = [item for item in record.label.labels if item.name == "verdict"]
    assert verdict.sids == (700,)
    assert verdict.tier == 1


def test_a_run_authoritative_for_nothing_is_skipped_rather_than_refused():
    """§2.4: an unattested tier is loaded but does not supersede. Its rows existing is the store
    working as specified, so there is nothing to report about them."""
    merged = merge.compose(
        [row(run_id="deadbeefdeadbeef", sources=[source(tier=2, sid=2001)])],
        authority_of(tier2=TIER2_RUN),
    )
    assert merged.flows == ()
    assert merged.refused == 0
    assert merged.refusal_notes == ()


def test_a_flow_whose_every_tier_was_superseded_drops_out_and_is_not_a_refusal():
    """The authoritative tier-1 run never labelled this flow; the run that did supplies tier 2
    only, and tier 2 here is somebody else's. Nothing is asserted about the flow any more — which
    is the merge working, not a row that could not be read."""
    stale = row(run_id=BOTH_RUN, sources=[source(tier=2, sid=2001)])
    merged = merge.compose([stale], authority_of(tier1=BOTH_RUN))
    assert merged.flows == ()
    assert merged.refused == 0


# --- §5.2 rules 3-5: composition ---------------------------------------------------------------


def test_two_runs_compose_into_one_record_naming_both_in_run_ids():
    """The plan's second named test. `run_ids` is a `{tier: run_id}` MAP, not a flat list: this
    record is a `Label` no single run ever asserted, and `docs/spec.md` §13 requires every
    assertion to name what produced it."""
    merged = merge.compose(
        [
            row(run_id=TIER1_RUN, sources=[source(tier=1, sid=700, name="panw")]),
            row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)]),
        ],
        authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN),
    )

    (record,) = merged.flows
    assert record.run_ids == {"1": TIER1_RUN, "2": TIER2_RUN}
    assert [item.sid for item in record.label.sources] == [700, 2001]
    (verdict,) = [item for item in record.label.labels if item.name == "verdict"]
    assert verdict.sids == (700, 2001)


def test_best_tier_is_recomputed_and_agrees_with_min_of_the_surviving_sources():
    """§5.2 rule 5 — `Label.__post_init__` enforcing itself. Note the rows' own `best_tier` is
    ignored: a stored 2 must not survive onto a record whose tier-1 source now composes in."""
    tier2_only = row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)])
    assert tier2_only["best_tier"] == 2

    (record,) = merge.compose(
        [tier2_only, row(run_id=TIER1_RUN, sources=[source(tier=1, sid=700, name="panw")])],
        authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN),
    ).flows

    assert record.label.best_tier == 1
    assert record.label.best_tier == min(item.tier for item in record.label.sources)


def test_sources_come_out_in_spec_10s_order():
    """§5.2 rule 3 defers to `docs/spec.md` §10's existing key rather than inventing one."""
    (record,) = merge.compose(
        [
            row(
                run_id=TIER2_RUN,
                sources=[
                    source(tier=2, sid=2002, name="et-open"),
                    source(tier=2, sid=2001, name="et-open"),
                    source(tier=2, sid=2001, name="abuse-ch"),
                ],
            )
        ],
        authority_of(tier2=TIER2_RUN),
    ).flows
    assert [(item.source, item.sid) for item in record.label.sources] == [
        ("abuse-ch", 2001),
        ("et-open", 2001),
        ("et-open", 2002),
    ]


def test_the_source_order_is_the_same_key_labels_json_uses():
    """Two copies of one ordering rule is the duplicate-authority defect this repo keeps catching.

    `source_key` cannot import `labels._entry_key` — `tests/test_architecture.py` shares only
    `flabel.models` with the store — so the two are pinned to each other here instead. This is
    `test_the_two_sort_keys_are_the_same_key`'s pattern applied to a third copy.
    """
    entries = [
        SourceEntry(**source(tier=2, sid=2001, direction="to_client")),
        SourceEntry(**source(tier=1, sid=700, name="panw")),
        SourceEntry(**source(tier=2, sid=2001, direction="to_server")),
    ]
    assert [merge.source_key(item) for item in entries] == [
        labels_module._entry_key(item) for item in entries
    ]
    assert sorted(entries, key=merge.source_key) == sorted(entries, key=labels_module._entry_key)


def test_duplicate_sources_are_kept_because_58_is_an_accepted_consequence():
    """§9: duplicate `SourceEntry` values are unbounded (#58), so a composed list can carry
    repeats. Collapsing them here would say a rule fired once where two entries recorded two
    firings — and the sid set behind the verdict is deduplicated either way (#140)."""
    duplicated = [source(tier=2, sid=2001), source(tier=2, sid=2001)]
    (record,) = merge.compose(
        [row(run_id=TIER2_RUN, sources=duplicated)], authority_of(tier2=TIER2_RUN)
    ).flows
    assert len(record.label.sources) == 2
    (verdict,) = [item for item in record.label.labels if item.name == "verdict"]
    assert verdict.sids == (2001,)


def test_a_threat_name_survives_from_the_tier_it_was_asserted_at():
    """§5.2 rule 4. `threat-name` is tier-1 only (`LABEL_KINDS`), so composing a tier-2 run beside
    it must leave the entry at tier 1 while the verdict moves to the better tier."""
    tier1 = row(
        run_id=TIER1_RUN,
        sources=[source(tier=1, sid=700, name="panw")],
        entries=[
            entry(name="verdict", value="malicious", tier=1, sids=[700]),
            entry(name="threat-name", value="Zbot", tier=1, sids=[700]),
        ],
    )
    (record,) = merge.compose(
        [tier1, row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)])],
        authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN),
    ).flows

    by_name = {item.name: item for item in record.label.labels}
    assert by_name["threat-name"].value == "Zbot"
    assert by_name["threat-name"].tier == 1
    assert by_name["threat-name"].sids == (700,)
    assert [item.name for item in record.label.labels] == ["threat-name", "verdict"]


# --- the hard failure §9 names -----------------------------------------------------------------


def test_a_cross_tier_value_conflict_on_a_single_arity_label_is_a_hard_failure():
    """The plan's fourth named test, §5.2's first latent loss, and §9's "must never silently pick
    a winner".

    Rule 4 as written keeps the lowest tier's value and discards the other. Today `verdict` is
    always `"malicious"` so nothing is lost — which is exactly why the guard has to be built now:
    the day a second value exists, a silent pick hides a genuine disagreement inside a dataset
    whose purpose is ground truth.
    """
    tier1 = row(
        run_id=TIER1_RUN,
        sources=[source(tier=1, sid=700, name="panw")],
        entries=[entry(name="verdict", value="malicious", tier=1, sids=[700])],
    )
    tier2 = row(
        run_id=TIER2_RUN,
        sources=[source(tier=2, sid=2001)],
        entries=[entry(name="verdict", value="suspicious", tier=2, sids=[2001])],
    )
    # `verdict` is rebuilt rather than merged, so the conflict must be detected on a kind the
    # merge actually carries forward. `threat-name` is tier-1 only, so `verdict` is the only kind
    # LABEL_KINDS permits at two tiers — the check therefore runs over the stored entries.
    with pytest.raises(merge.MergeConflict) as raised:
        merge.compose([tier1, tier2], authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN))

    message = str(raised.value)
    assert "verdict" in message
    assert "malicious" in message and "suspicious" in message
    assert "tier 1" in message and "tier 2" in message


def test_merge_conflict_is_not_a_value_error_so_the_refusal_handler_cannot_eat_it():
    """The guard behind the guard.

    `compose` catches `ValueError` to turn a row it cannot construct into a counted refusal (§9).
    If `MergeConflict` were a `ValueError`, the one failure §9 says must never be silent would be
    counted and dropped by that handler — and the test above would still pass, because it asserts
    on the exception type it was handed.
    """
    assert not issubclass(merge.MergeConflict, ValueError)


def test_a_conflict_beside_an_unreadable_row_still_raises_rather_than_being_counted():
    """The two paths meeting. One flow refuses, another conflicts; the conflict wins."""
    unreadable = row(
        run_id=TIER2_RUN,
        sources=[source(tier=2, sid=2001)],
        flow_key="f" * 64,
        entries=[
            entry(name="verdict", value="malicious", tier=2, sids=[2001]),
            entry(name="mitre-technique", value="T1071", tier=2, sids=[2001]),
        ],
    )
    conflicting = [
        row(
            run_id=TIER1_RUN,
            sources=[source(tier=1, sid=700, name="panw")],
            entries=[entry(name="verdict", value="malicious", tier=1, sids=[700])],
        ),
        row(
            run_id=TIER2_RUN,
            sources=[source(tier=2, sid=2001)],
            entries=[entry(name="verdict", value="suspicious", tier=2, sids=[2001])],
        ),
    ]
    with pytest.raises(merge.MergeConflict):
        merge.compose([unreadable, *conflicting], authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN))


# --- §9's deliberate decision: refuse, count, name ---------------------------------------------


def test_a_kind_this_build_does_not_know_is_counted_rather_than_fatal():
    """§9 says **LS-7 must decide deliberately**, on §3.2's `ip_proto` precedent: refuse the row,
    count it, record it.

    `LABEL_KINDS` is enforced at construction, and LS-7 and LS-8 build entries from archived rows.
    A historical row whose kind this build no longer knows is data an older writer produced
    legally; raising on it is how a backfill becomes unrunnable.
    """
    assert "mitre-technique" not in LABEL_KINDS, "pick a kind the build genuinely does not know"
    merged = merge.compose(
        [
            row(
                run_id=TIER2_RUN,
                sources=[source(tier=2, sid=2001)],
                entries=[
                    entry(name="verdict", value="malicious", tier=2, sids=[2001]),
                    entry(name="mitre-technique", value="T1071", tier=2, sids=[2001]),
                ],
            )
        ],
        authority_of(tier2=TIER2_RUN),
    )
    assert merged.flows == ()
    assert merged.refused == 1
    (note,) = merged.refusal_notes
    assert "mitre-technique" in note
    assert FLOW_KEY in note


def test_a_tier_a_kind_does_not_permit_is_counted_the_same_way():
    """The other half of §9's case: a (kind, tier) pair outside the table. `LabelEntry` refuses it
    at construction, and that refusal must land in the count rather than in a traceback."""
    assert LABEL_KINDS["threat-name"].tiers == (1,)
    merged = merge.compose(
        [
            row(
                run_id=TIER2_RUN,
                sources=[source(tier=2, sid=2001)],
                entries=[
                    entry(name="verdict", value="malicious", tier=2, sids=[2001]),
                    entry(name="threat-name", value="Zbot", tier=2, sids=[2001]),
                ],
            )
        ],
        authority_of(tier2=TIER2_RUN),
    )
    assert merged.flows == ()
    assert merged.refused == 1
    assert "threat-name" in merged.refusal_notes[0]


def test_a_refused_flow_does_not_take_its_neighbours_with_it():
    """A counted refusal is per flow. One unreadable row must not empty the collection."""
    good = row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)], flow_key="e" * 64)
    bad = row(
        run_id=TIER2_RUN,
        sources=[source(tier=2, sid=2002)],
        entries=[
            entry(name="verdict", value="malicious", tier=2, sids=[2002]),
            entry(name="threat-name", value="Zbot", tier=2, sids=[2002]),
        ],
    )
    merged = merge.compose([good, bad], authority_of(tier2=TIER2_RUN))
    assert [record.flow_key for record in merged.flows] == ["e" * 64]
    assert merged.refused == 1


# --- `authority` -------------------------------------------------------------------------------


def test_authority_reads_the_view_in_both_directions():
    auth = merge.authority(
        [
            {"capture_sha256": CAPTURE, "tier": 1, "run_id": TIER1_RUN},
            {"capture_sha256": CAPTURE, "tier": 2, "run_id": TIER2_RUN},
            {"capture_sha256": OTHER_CAPTURE, "tier": 1, "run_id": BOTH_RUN},
            {"capture_sha256": OTHER_CAPTURE, "tier": 2, "run_id": BOTH_RUN},
        ]
    )
    assert auth.by_capture[CAPTURE] == {1: TIER1_RUN, 2: TIER2_RUN}
    assert auth.by_run[BOTH_RUN] == (1, 2)
    assert auth.by_run[TIER1_RUN] == (1,)


def test_two_runs_for_one_capture_and_tier_is_a_defect_in_the_view_not_data_to_pick_from():
    """`recency = 1` makes it one row. Two means §4.6's `run_id` tie-break has failed, and picking
    a winner here would invent an answer the store does not hold."""
    with pytest.raises(merge.StoreInconsistent, match="two runs for capture"):
        merge.authority(
            [
                {"capture_sha256": CAPTURE, "tier": 2, "run_id": TIER2_RUN},
                {"capture_sha256": CAPTURE, "tier": 2, "run_id": BOTH_RUN},
            ]
        )


def test_that_defect_is_not_a_value_error_either():
    """`compose` counts `ValueError`s as refused flows, and `blfile.main` maps a bare `ValueError`
    to a defect in itself. A store contradiction is neither, so it gets its own class — the same
    argument `MergeConflict` is built on, one level up."""
    assert not issubclass(merge.StoreInconsistent, ValueError)
    assert not issubclass(merge.MergeConflict, merge.StoreInconsistent)


# --- the store's shapes, on the way back in ----------------------------------------------------


def test_the_flow_struct_is_carried_verbatim_because_it_is_a_superset_of_models_flow():
    """§4.3 stores the canonical pair and `ip_proto` beside `labels.json`'s fields — the
    content-derived halves of the flow key, which `models.Flow` has nowhere to put."""
    (record,) = merge.compose(
        [row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)])],
        authority_of(tier2=TIER2_RUN),
    ).flows
    assert record.flow == flow_struct()
    assert record.label.flow.uid == "CabCdE1", "zeek_uid is models.Flow's uid (§4.3's rename)"


@pytest.mark.parametrize(
    "stored",
    [
        "2026-07-08T12:00:00.000000Z",
        "2026-07-08T12:00:00+00:00",
        1783166400.0,
    ],
)
def test_a_timestamp_is_read_whichever_way_the_store_hands_it_over(stored):
    """A `TIMESTAMP` column comes back from the client as an aware `datetime`, while the rows
    `parse.py` builds carry `labels.json`'s ISO strings. Both reach `blfile` — from BigQuery and
    from a fixture — and a module that accepted only one would be tested against a shape
    production never produces."""
    (record,) = merge.compose(
        [
            row(
                run_id=TIER2_RUN,
                sources=[source(tier=2, sid=2001)],
                flow=flow_struct(ts_first=stored),
            )
        ],
        authority_of(tier2=TIER2_RUN),
    ).flows
    assert isinstance(record.label.flow.ts_first, float)


def test_a_naive_datetime_is_read_as_utc_rather_than_local():
    """`datetime.timestamp()` on a naive value applies the LOCAL zone — invisible on a UTC CI
    runner and silently wrong by whole hours everywhere else (`docs/spec.md` §10)."""
    from datetime import UTC, datetime

    naive = datetime(2026, 7, 8, 12, 0, 0)
    assert merge._epoch(naive) == datetime(2026, 7, 8, 12, 0, 0, tzinfo=UTC).timestamp()


def test_the_source_field_list_is_taken_from_the_model_rather_than_written_out_again():
    """If §4.3's struct and `models.SourceEntry` ever disagree, the load side already fails. This
    pins the read side to the same single authority."""
    assert tuple(field.name for field in dataclasses.fields(SourceEntry)) == merge.SOURCE_FIELDS


def test_composition_goes_through_models_label():
    """§5.2: the same constructors, with the same `__post_init__` invariants, that produced the
    rows in the first place."""
    (record,) = merge.compose(
        [row(run_id=TIER2_RUN, sources=[source(tier=2, sid=2001)])],
        authority_of(tier2=TIER2_RUN),
    ).flows
    assert isinstance(record.label, Label)


# --- the verdict rebuild, and what it must not overwrite (review, 2026-08-25) --------------------


def test_a_stored_verdict_that_is_not_malicious_is_a_conflict_not_a_rewrite():
    """`models.verdict_entry` hardcodes `value="malicious"`, so rebuilding is a WRITE.

    Measured before this test existed: a single-tier row storing `"suspicious"` came out of
    `compose` as `"malicious"`, with nothing raised and nothing counted — a verdict no run
    asserted, published as ground truth. `docs/spec.md` §13 and Goal 1 both forbid exactly that,
    and `Label.__post_init__` cannot catch it because it only ever sees the rebuilt entry.

    Note there is no cross-TIER disagreement here. The guard this closes is not "two tiers differ"
    but "the document differs from what any run said", of which the cross-tier case is one shape.
    """
    stored = row(
        run_id=TIER2_RUN,
        sources=[source(tier=2, sid=2001)],
        entries=[entry(name="verdict", value="suspicious", tier=2, sids=[2001])],
    )
    with pytest.raises(merge.MergeConflict) as raised:
        merge.compose([stored], authority_of(tier2=TIER2_RUN))
    assert "suspicious" in str(raised.value)
    assert TIER2_RUN in str(raised.value), "§13: name what produced the assertion"


def test_a_both_runs_verdict_is_checked_even_when_its_tier_has_been_superseded():
    """The verdict is **not** tier-filtered, and this is why.

    Every source on a flow asserts the verdict, so a `--both` run stores its verdict at
    `min(sources.tier)` — tier 1 — even when the tier it still supplies is 2. Filtering the stored
    entry by that number dropped it entirely, leaving the run shape §5.2 rule 2 exists for with no
    cross-tier value comparison at all. Measured 2026-08-25: this composed silently.
    """
    both = row(
        run_id=BOTH_RUN,
        sources=[source(tier=1, sid=700, name="panw"), source(tier=2, sid=2001)],
        entries=[entry(name="verdict", value="suspicious", tier=1, sids=[700, 2001])],
    )
    newer_tier_1 = row(
        run_id=TIER1_RUN,
        sources=[source(tier=1, sid=701, name="panw")],
        entries=[entry(name="verdict", value="malicious", tier=1, sids=[701])],
    )
    auth = merge.authority(
        [
            {"capture_sha256": CAPTURE, "tier": 1, "run_id": TIER1_RUN},
            {"capture_sha256": CAPTURE, "tier": 2, "run_id": BOTH_RUN},
        ]
    )
    assert auth.by_run[BOTH_RUN] == (2,), "the fixture must actually supersede BOTH_RUN's tier 1"
    with pytest.raises(merge.MergeConflict) as raised:
        merge.compose([both, newer_tier_1], auth)
    assert BOTH_RUN in str(raised.value)


def test_a_stored_verdict_with_no_value_is_not_a_disagreement():
    """`parse._label` writes `[None]` for an archived label whose `value` key was absent.

    Losing a flow whose sources are intact — and whose verdict is rebuilt from them regardless —
    over a field that is then discarded would be a refusal for nothing. The rebuild is what makes
    this safe: the published verdict comes from the sources either way.
    """
    stored = row(
        run_id=TIER2_RUN,
        sources=[source(tier=2, sid=2001)],
        entries=[{"name": "verdict", "value": [None], "tier": 2, "sids": [2001]}],
    )
    merged = merge.compose([stored], authority_of(tier2=TIER2_RUN))
    (record,) = merged.flows
    assert merged.refused == 0
    (verdict,) = [item for item in record.label.labels if item.name == "verdict"]
    assert verdict.value == "malicious"


def test_a_superseded_tiers_non_verdict_label_does_not_survive():
    """§5.2's second latent loss, and the half of rule 2's tier filter nothing could see.

    The filter on `sources` had a test; the filter on `labels` did not — every fixture stored its
    non-verdict entry at a tier the run was still authoritative for, so `if entry.tier in tiers`
    could be replaced with `if True` and the whole suite stayed green. It matters the moment §6.2's
    "purely additive" widening of `threat-name` to tier 2 happens: without the filter, a superseded
    tier's `threat-name` survives into the collection.
    """
    monkeyed = dict(LABEL_KINDS)
    both = row(
        run_id=BOTH_RUN,
        sources=[source(tier=1, sid=700, name="panw"), source(tier=2, sid=2001)],
        entries=[
            entry(name="verdict", value="malicious", tier=1, sids=[700, 2001]),
            # Legal today only because `threat-name` is tier-1 only; the row is written by hand
            # precisely to stand in for the tier-2 kind §6.2 says is coming.
            entry(name="threat-name", value="Zbot", tier=1, sids=[700]),
        ],
    )
    assert "threat-name" in monkeyed
    # BOTH_RUN supplies tier 2 only, so its tier-1 `threat-name` has been superseded.
    auth = merge.authority(
        [
            {"capture_sha256": CAPTURE, "tier": 1, "run_id": TIER1_RUN},
            {"capture_sha256": CAPTURE, "tier": 2, "run_id": BOTH_RUN},
        ]
    )
    tier_1 = row(run_id=TIER1_RUN, sources=[source(tier=1, sid=701, name="panw")])
    (record,) = merge.compose([both, tier_1], auth).flows
    assert [item.name for item in record.label.labels] == ["verdict"], (
        "BOTH_RUN's tier-1 threat-name survived a supersession of tier 1"
    )


def test_the_generic_conflict_rule_fires_when_a_single_arity_kind_gains_a_second_tier(monkeypatch):
    """`_merge_entry`'s cross-tier check is unreachable **today**, and this makes it true anyway.

    `verdict` is guarded by its own rebuild check, and `threat-name` is tier-1 only — so no kind
    `LABEL_KINDS` currently declares can reach the generic branch with entries at two tiers, and a
    sabotage that removed it stayed green. §6.2 says widening `threat-name` to tier 2 is "purely
    additive"; that claim is only true if the guard it lands on already works, so the widening is
    performed here and the rule exercised against it.
    """
    from flabel import models

    widened = {**LABEL_KINDS, "threat-name": models.LabelKind(arity="single", tiers=(1, 2))}
    monkeypatch.setattr(models, "LABEL_KINDS", widened)
    monkeypatch.setattr(merge, "LABEL_KINDS", widened)

    tier_1 = row(
        run_id=TIER1_RUN,
        sources=[source(tier=1, sid=700, name="panw")],
        entries=[
            entry(name="verdict", value="malicious", tier=1, sids=[700]),
            entry(name="threat-name", value="Zbot", tier=1, sids=[700]),
        ],
    )
    tier_2 = row(
        run_id=TIER2_RUN,
        sources=[source(tier=2, sid=2001)],
        entries=[
            entry(name="verdict", value="malicious", tier=2, sids=[2001]),
            entry(name="threat-name", value="Emotet", tier=2, sids=[2001]),
        ],
    )
    with pytest.raises(merge.MergeConflict) as raised:
        merge.compose([tier_1, tier_2], authority_of(tier1=TIER1_RUN, tier2=TIER2_RUN))

    message = str(raised.value)
    assert "threat-name" in message
    assert "Zbot" in message and "Emotet" in message
    assert "tier 1" in message and "tier 2" in message
