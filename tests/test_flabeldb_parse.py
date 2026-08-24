"""Turning a published run directory into the rows of spec §4 — LS-4's parser.

**Pure: filesystem reads only.** `docs/spec.md` §3 classes a filesystem read as pure, and that is
what lets these run in CI — spec-label-store §2.4's testing line records that the
`requires_bigquery` tests run nowhere else. The `gs://` fetch is network I/O and lives in
`ingest.py`; this module is handed a directory that already exists on disk.

The fixtures here are trimmed from REAL runs on `fl-replay`, not invented: a tier-1 replay run
that produced two labels, and the `--offline` run whose two skipped rules make it tier-2
unattested.
"""

from __future__ import annotations

import copy
import json

import pytest

from flabeldb import identity, parse

CAPTURE = "7aa343087a8743a73ced055b4af2c743de8e96a1a7112e127c1d97499f522ab1"

#: A real tier-1 label, verbatim except for trimming `sources` to one entry.
LABEL = {
    "best_tier": 1,
    "flow": {
        "dst_ip": "216.106.176.186",
        "dst_port": 3401,
        "ja4": None,
        "ja4s": None,
        "proto": "udp",
        "server_name": None,
        "src_ip": "198.199.72.137",
        "src_port": 44669,
        "ts_first": "2026-08-03T07:49:39.318814Z",
        "ts_last": "2026-08-03T07:49:39.318814Z",
        "uid": "C3fcaQLN7RrPm157",
    },
    "labels": [
        {"name": "threat-name", "sids": [54782], "tier": 1, "value": "Squid Proxy SNMP Query"},
        {"name": "verdict", "sids": [54782], "tier": 1, "value": "malicious"},
    ],
    "sources": [
        {
            "admission_basis": "device-policy",
            "classtype": "dos",
            "direction": "to_server",
            "label_basis": "direct",
            "licence": "proprietary:vendor-signature (not redistributed)",
            "rev": 0,
            "ruleset": "AppThreat-9136-10199/config-2818",
            "sid": 54782,
            "source": "panw/threat-prevention",
            "threat": "Squid Proxy SNMP Query",
            "tier": 1,
        }
    ],
}

UNMATCHED = {
    "detection": {
        "app_proto": "ssh",
        "classtype": "brute-force",
        "direction": "to_server",
        "dst_ip": "216.106.176.186",
        "dst_port": 22,
        "metadata": [],
        "proto": "tcp",
        "rev": 0,
        "sid": 40071,
        "source": "panw/threat-prevention",
        "src_ip": "195.3.221.14",
        "src_port": 32830,
        "threat": "OpenSSH Denial of Service Vulnerability",
        "tier": 1,
        "ts": "2026-08-20T00:53:16.000000Z",
    },
    "reason": "ambiguous_flow_match",
}

RUN = {
    "counts": {"rules_loaded": 84958, "rules_failed": 0, "rules_skipped": 2},
    "duration_seconds": 84.187552,
    "finished_at": "2026-08-21T17:29:00.827146Z",
    "started_at": "2026-08-21T17:27:36.639594Z",
    "flabel_version": "0.0.0",
    "input": {
        "bytes": 1082,
        "format": "pcap",
        "link_type": 1,
        "path": "/home/bigdaddy/flabel-dev/tests/fixtures/benign.pcap",
        "sha256": CAPTURE,
        "snaplens": [96, 65535],
        "uri": "gs://bucket/benign.pcap",
        "uri_status": "gs",
    },
    "mode": "offline",
    "ruleset": {"snapshot_id": "b8b1e00ed2285240", "total_admitted": 84960},
    "schema_version": "2.0",
    "tiers_attempted": [2],
    "tiers_unavailable": [],
    "tool_failures": [],
}


def document(**changes) -> dict:
    found = {
        "schema_version": "2.0",
        "run": copy.deepcopy(RUN),
        "labels": [copy.deepcopy(LABEL)],
        "unmatched_detections": [copy.deepcopy(UNMATCHED)],
    }
    found.update(copy.deepcopy(changes))
    return found


def parsed(**changes):
    return parse.rows(document(**changes), ingested_at="2026-08-24T12:00:00.000000Z")


# --- the runs row: the commit marker -----------------------------------------------------------


def test_the_run_row_carries_the_identity_and_the_attestation():
    found = parsed().run

    assert found["run_id"] == identity.run_id(
        capture_sha256=CAPTURE,
        mode="offline",
        started_at_iso=RUN["started_at"],
        flabel_version="0.0.0",
    )
    assert found["capture_sha256"] == CAPTURE
    assert found["mode"] == "offline"
    assert found["tiers_attempted"] == [2]
    # 84,958 of 84,960 — the real box, and it does not attest (§2.4).
    assert found["tiers_attested"] == []
    assert found["attestation_notes"]


def test_run_block_is_a_verbatim_string_and_not_a_dict():
    """§4.1: STRING, not JSON, because the JSON type normalises on ingest — it sorts keys, drops
    duplicates and renders 12.30 as 12.3 — and spec §6.4 embeds this VERBATIM."""
    block = parsed().run["run_block"]

    assert isinstance(block, str), (
        "run_block reached the row as a dict; BigQuery would normalise it"
    )
    assert json.loads(block) == RUN


def test_the_run_block_round_trips_a_float_without_normalising_it():
    """`duration_seconds` is the one float in a run block. A parse -> dump cycle that lost
    precision would make a rebuilt row differ from the original, breaking §5.5."""
    assert json.loads(parsed().run["run_block"])["duration_seconds"] == 84.187552


def test_the_run_block_is_canonical_so_two_ingests_of_one_tarball_agree():
    """Byte-identical, not merely equal-as-objects: the column is a STRING, so two ingests that
    serialised differently would be two different values for one fact."""
    assert parsed().run["run_block"] == parsed().run["run_block"]
    shuffled = document()
    shuffled["run"] = dict(reversed(list(shuffled["run"].items())))
    assert parse.rows(shuffled, ingested_at="x").run["run_block"] == parsed().run["run_block"]


def test_ingested_at_is_passed_in_and_never_read_from_a_clock():
    """§5.5 lists `ingested_at` among the things a rebuild does NOT reproduce, which is only
    meaningful if the parser cannot invent one."""
    assert parsed().run["ingested_at"] == "2026-08-24T12:00:00.000000Z"


def test_the_archive_uri_is_recorded_when_given_and_null_when_not():
    """Null is "not measured" (§10), which is the honest value for a directory nobody published."""
    assert parse.rows(document(), ingested_at="x", archive_uri=None).run["archive_uri"] is None
    with_uri = parse.rows(document(), ingested_at="x", archive_uri="gs://b/o.tar.gz")
    assert with_uri.run["archive_uri"] == "gs://b/o.tar.gz"


# --- the captures row --------------------------------------------------------------------------


def test_the_capture_row_is_a_sighting_and_names_the_run_that_saw_it():
    found = parsed().capture

    assert found["capture_sha256"] == CAPTURE
    assert found["observed_by_run_id"] == parsed().run["run_id"]
    assert found["uri"] == "gs://bucket/benign.pcap"
    assert found["uri_status"] == "gs"
    assert found["filename"] == "benign.pcap"
    assert found["bytes"] == 1082
    assert found["snaplens"] == [96, 65535]


def test_snaplens_stays_plural_and_keeps_the_disagreement():
    """LS-1's correction. A mergecap pcapng's interfaces need not agree (measured: 96 and 65535),
    and collapsing them would erase the fact the field exists to expose."""
    assert parsed().capture["snaplens"] == [96, 65535]


def test_a_run_block_predating_uri_reads_as_not_recorded_rather_than_local():
    """§6.1: flabel writes `gs` or `local`; only `flabel-ingest` writes `not-recorded`, for a block
    that has no such key. Guessing `local` would assert something never measured."""
    old = document()
    del old["run"]["input"]["uri"]
    del old["run"]["input"]["uri_status"]
    capture = parse.rows(old, ingested_at="x").capture

    assert capture["uri"] is None
    assert capture["uri_status"] == "not-recorded"


# --- flow_labels -------------------------------------------------------------------------------


def test_one_row_per_labelled_flow_keyed_by_content():
    row = parsed().flow_labels[0]

    assert row["capture_sha256"] == CAPTURE
    assert row["flow_key"] == identity.flow_key(
        CAPTURE,
        proto="udp",
        ip_proto=17,
        src_ip="198.199.72.137",
        src_port=44669,
        dst_ip="216.106.176.186",
        dst_port=3401,
        ts_first_iso="2026-08-03T07:49:39.318814Z",
    )
    assert row["best_tier"] == 1


def test_the_flow_struct_keeps_the_orientation_beside_the_canonical_pair():
    """§3.2: ordering the pair is what stops an orientation disagreement splitting one flow into
    two rows; storing what Zeek reported is what keeps the observation."""
    flow = parsed().flow_labels[0]["flow"]

    assert (flow["ip_lo"], flow["port_lo"]) == ("198.199.72.137", 44669)
    assert (flow["ip_hi"], flow["port_hi"]) == ("216.106.176.186", 3401)
    assert (flow["src_ip"], flow["src_port"]) == ("198.199.72.137", 44669)
    assert (flow["dst_ip"], flow["dst_port"]) == ("216.106.176.186", 3401)


def test_the_zeek_uid_is_stored_under_its_own_name_and_never_as_identity():
    """Kept because it is how an operator finds the flow in that run's conn.log; renamed from
    `uid` so no join can be written against it by habit."""
    flow = parsed().flow_labels[0]["flow"]
    assert flow["zeek_uid"] == "C3fcaQLN7RrPm157"
    assert "uid" not in flow


def test_ip_proto_is_derived_and_stored():
    assert parsed().flow_labels[0]["flow"]["ip_proto"] == 17


def test_a_label_value_becomes_a_one_element_list_because_the_column_is_repeated():
    """§4.3's `labels.value` is REPEATED while `LABEL_KINDS` says every kind is arity=single
    today. The column is the general shape; the wrap is where the two meet."""
    labels = {entry["name"]: entry for entry in parsed().flow_labels[0]["labels"]}

    assert labels["verdict"]["value"] == ["malicious"]
    assert labels["threat-name"]["value"] == ["Squid Proxy SNMP Query"]
    assert labels["verdict"]["sids"] == [54782]


def test_sources_are_carried_through_whole():
    source = parsed().flow_labels[0]["sources"][0]
    assert source["sid"] == 54782
    assert source["source"] == "panw/threat-prevention"
    assert source["licence"].startswith("proprietary:")
    assert source["label_basis"] == "direct"


# --- the refusal, until #96 ---------------------------------------------------------------------


@pytest.mark.parametrize("proto", ["unknown_transport", "esp", "gre"])
def test_a_flow_whose_proto_is_not_writable_is_refused_and_counted(proto):
    """§3.2: `Flow` carries no `ip_proto`, so two ESP conversations between one host pair are
    indistinguishable and one key would union two real flows. Refusing loses no labels — such
    detections were already `unsupported_transport` unmatched detections."""
    doc = document()
    doc["labels"][0]["flow"]["proto"] = proto
    found = parse.rows(doc, ingested_at="x")

    assert found.flow_labels == []
    assert found.refused == 1
    assert any(proto in note for note in found.refusal_notes), found.refusal_notes


def test_a_refusal_does_not_stop_the_writable_flows_in_the_same_run():
    """One bad flow must not cost the run its other rows — that would turn a partial loss into a
    total one, which is the shape spec §2.5 forbids."""
    doc = document()
    second = copy.deepcopy(LABEL)
    second["flow"]["proto"] = "esp"
    doc["labels"].append(second)
    found = parse.rows(doc, ingested_at="x")

    assert len(found.flow_labels) == 1
    assert found.refused == 1


def test_nothing_is_refused_in_the_ordinary_case():
    found = parsed()
    assert found.refused == 0
    assert found.refusal_notes == ()


# --- unmatched -----------------------------------------------------------------------------------


def test_an_unmatched_detection_is_flattened_with_its_reason():
    row = parsed().unmatched[0]

    assert row["run_id"] == parsed().run["run_id"]
    assert row["capture_sha256"] == CAPTURE
    assert row["reason"] == "ambiguous_flow_match"
    assert row["sid"] == 40071
    assert row["ts"] == "2026-08-20T00:53:16.000000Z"
    assert row["proto"] == "tcp"
    assert row["src_port"] == 32830


def test_an_empty_unmatched_list_is_a_real_result_not_a_missing_one():
    """A capture where everything correlated is the ordinary case."""
    assert parse.rows(document(unmatched_detections=[]), ingested_at="x").unmatched == []


# --- every row carries the run id, which is what the commit marker joins through -----------------


def test_every_row_in_every_table_carries_the_same_run_id():
    """§5.3: `runs` lands LAST and every read joins through it, so a row that carried a different
    id — or none — would be permanently unreachable rather than merely wrong."""
    found = parsed()
    run_id = found.run["run_id"]

    assert found.capture["observed_by_run_id"] == run_id
    for row in (*found.flow_labels, *found.unmatched):
        assert row["run_id"] == run_id


def test_only_the_five_declared_columns_of_each_table_are_produced():
    """A key the table does not declare fails the load job with a message about the row, not about
    the parser. Caught here instead."""
    from flabeldb import schema

    found = parsed()
    for name, rows in (
        ("runs", [found.run]),
        ("captures", [found.capture]),
        ("flow_labels", found.flow_labels),
        ("unmatched", found.unmatched),
    ):
        declared = {column.name for column in schema.TABLES[name].fields}
        for row in rows:
            assert set(row) <= declared, f"{name}: undeclared {sorted(set(row) - declared)}"
