"""Canonical comparison of run directories — Goal 2's primitive (docs/spec.md §10, step 10).

Every rule here is tested in **both directions**: that it erases the difference it is meant to
erase, and that it still catches a real one. A canonicalizer tested only the first way passes by
deleting everything, and a reproducibility gate built on it would be green forever.

The `reporter.log` rule rests on a measurement taken against Zeek 8.0.4 on 2026-08-13 and
recorded in `test_the_reporter_timestamp_is_why_the_ts_column_goes`.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from flabel import canonical

# --- fixtures ---------------------------------------------------------------------------------

TSV_HEADER = "\n".join(
    [
        "#separator \\x09",
        "#set_separator\t,",
        "#path\tconn",
        "#open\t2026-08-13-11-11-51",
        "#fields\tts\tuid\tid.orig_h",
        "#types\ttime\tstring\taddr",
    ]
)


def tsv(records: str, opened: str = "2026-08-13-11-11-51") -> str:
    """A Zeek TSV log with `records` between the usual headers and the `#close` footer."""
    return f"{TSV_HEADER.replace('2026-08-13-11-11-51', opened)}\n{records}\n#close\t{opened}\n"


#: Two real `reporter.log` bodies, captured from consecutive runs over one capture on Zeek 8.0.4.
#: The `zeek_init` record's `ts` is wall-clock and differs by the 1.4s between the two runs; the
#: packet-time records carry network time and are identical.
REPORTER_RUN_A = (
    "1786644711.886324\tReporter::WARNING\tstartup message\t<command line>, line 1\n"
    "1700000000.000000\tReporter::WARNING\tpacket-time message for 10.0.0.5\t-\n"
)
REPORTER_RUN_B = (
    "1786644713.298930\tReporter::WARNING\tstartup message\t<command line>, line 1\n"
    "1700000000.000000\tReporter::WARNING\tpacket-time message for 10.0.0.5\t-\n"
)


def eve(*records: dict) -> str:
    return "".join(json.dumps(record, sort_keys=True) + "\n" for record in records)


ALERT = {"event_type": "alert", "alert": {"signature_id": 9000001}, "src_ip": "10.0.0.5"}
STATS = {"event_type": "stats", "stats": {"uptime": 3, "detect": {"alert": 1}}}
FLOW = {"event_type": "flow", "flow": {"pkts_toserver": 7}}


def document(**overrides) -> dict:
    """A `labels.json` document, reduced to the fields canonicalisation cares about."""
    run = {
        "flabel_version": "0.1.0",
        "started_at": "2026-08-13T10:02:11.004530Z",
        "finished_at": "2026-08-13T10:04:36.918274Z",
        "duration_seconds": 145.913744,
        "input": {"path": "/captures/branch.pcapng", "sha256": "9f2c", "packets_read": 14},
        "counts": {"labels": 2},
    }
    run.update(overrides.pop("run", {}))
    return {"schema_version": "1.0", "run": run, "labels": [], **overrides}


# --- dropping the `#` headers -------------------------------------------------------------------


def test_the_wall_clock_headers_are_dropped():
    """Every Zeek TSV log carries `#open`/`#close`, which is why byte-identity was unachievable."""
    records = canonical.canonical_records(tsv("1700000000.000000\tCabc\t10.0.0.5"))

    assert records == ("1700000000.000000\tCabc\t10.0.0.5",)


def test_two_logs_differing_only_in_their_headers_are_equal():
    """The whole reason spec §10 stopped claiming byte-identity."""
    first = tsv("1700000000.000000\tCabc\t10.0.0.5", opened="2026-08-13-11-11-51")
    second = tsv("1700000000.000000\tCabc\t10.0.0.5", opened="2026-08-13-23-40-02")

    assert canonical.canonical_records(first) == canonical.canonical_records(second)


def test_a_real_record_difference_still_shows():
    """The direction that matters: canonicalisation must not be a way of passing."""
    first = tsv("1700000000.000000\tCabc\t10.0.0.5")
    second = tsv("1700000000.000000\tCabc\t10.0.0.9")

    assert canonical.canonical_records(first) != canonical.canonical_records(second)


def test_a_dropped_record_shows():
    """A run that lost a connection must not canonicalise to the same thing as one that did not."""
    first = tsv("1700000000.000000\tCabc\t10.0.0.5\n1700000010.000000\tCdef\t10.0.0.6")
    second = tsv("1700000000.000000\tCabc\t10.0.0.5")

    assert canonical.canonical_records(first) != canonical.canonical_records(second)


# --- reporter.log: the file spec §10 canonicalises rather than excludes -------------------------


def test_the_reporter_timestamp_is_why_the_ts_column_goes():
    """Measured on Zeek 8.0.4, 2026-08-13, and the reason this file needs its own rule.

    Spec §10 said canonicalisation "drops `#`-prefixed header lines", and named `reporter.log` as
    canonicalised rather than excluded so Goal 3's protocol violations stay visible. Both halves
    are right; the definition was incomplete for this one file.

    Two consecutive runs over one capture, 1.4s apart:

        run a   1786644711.886324   Reporter::WARNING   startup message
        run b   1786644713.298930   Reporter::WARNING   startup message

    A message raised in `zeek_init` carries **wall-clock** time in `ts` even under `-D`, so
    dropping `#` lines leaves a record that still differs. A message raised while reading packets
    carries **network** time (`1700000000.000000`, the canary's own base) and is identical run to
    run. The two are interleaved in one file and cannot be told apart from content — a wall-clock
    reading and a packet time are both just floats, and a capture recorded today would have
    packet times indistinguishable from now.

    So the `ts` column goes and everything else stays. Level, message and location are the
    analytic content Goal 3 wants reported; *when* a reporter message was emitted is not
    something the reproducibility gate needs to police, and for a whole class of messages it
    provably cannot.
    """
    assert canonical.canonical_records(REPORTER_RUN_A) != canonical.canonical_records(
        REPORTER_RUN_B
    ), "dropping # lines alone leaves the wall-clock ts in place — this is the measurement"

    assert canonical.canonical_reporter_records(
        REPORTER_RUN_A
    ) == canonical.canonical_reporter_records(REPORTER_RUN_B)


def test_the_reporter_message_itself_is_still_compared():
    """Dropping `ts` must not become dropping the file — Goal 3 reads this log."""
    changed = REPORTER_RUN_A.replace("packet-time message for 10.0.0.5", "a different violation")

    assert canonical.canonical_reporter_records(
        REPORTER_RUN_A
    ) != canonical.canonical_reporter_records(changed)


def test_a_new_reporter_record_shows():
    """A run that started reporting protocol violations is a change worth failing on."""
    extra = REPORTER_RUN_A + "1700000005.000000\tReporter::WARNING\tbad checksum\t-\n"

    assert canonical.canonical_reporter_records(
        REPORTER_RUN_A
    ) != canonical.canonical_reporter_records(extra)


# --- eve.json: only the `stats` records are excluded --------------------------------------------


def test_stats_records_are_dropped_and_alerts_are_kept():
    """Spec §10: `stats` carries wall-clock counters; `alert` and `flow` are byte-stable.

    Excluding the file wholesale would exclude the alerts, which are exactly what a
    reproducibility gate over a labelling tool should be comparing.
    """
    records = canonical.canonical_eve_records(eve(ALERT, STATS, FLOW))

    kinds = [json.loads(record)["event_type"] for record in records]
    assert kinds == ["alert", "flow"]


def test_two_runs_differing_only_in_stats_are_equal():
    first = eve(ALERT, {**STATS, "stats": {"uptime": 3}})
    second = eve(ALERT, {**STATS, "stats": {"uptime": 9}})

    assert canonical.canonical_eve_records(first) == canonical.canonical_eve_records(second)


def test_an_alert_difference_still_shows():
    """The gate's whole purpose: two runs must fire the same rules on the same capture."""
    other = {**ALERT, "alert": {"signature_id": 9000002}}

    assert canonical.canonical_eve_records(eve(ALERT)) != canonical.canonical_eve_records(
        eve(other)
    )


def test_a_lost_alert_shows():
    assert canonical.canonical_eve_records(eve(ALERT, FLOW)) != canonical.canonical_eve_records(
        eve(FLOW)
    )


def test_a_malformed_eve_line_is_not_silently_skipped():
    """A line that cannot be parsed is a difference, not a nothing.

    Dropping it would make a corrupted `eve.json` compare equal to a healthy one, which is the
    failure this whole module exists to prevent.
    """
    with pytest.raises(ValueError):
        canonical.canonical_eve_records(eve(ALERT) + "{not json\n")


# --- labels.json / run.json: the wall-clock and path fields --------------------------------------


def test_the_three_wall_clock_fields_and_the_input_path_are_removed():
    """Spec §10's exclusion list, and only it."""
    reduced = canonical.canonical_document(document())

    assert "started_at" not in reduced["run"]
    assert "finished_at" not in reduced["run"]
    assert "duration_seconds" not in reduced["run"]
    assert "path" not in reduced["run"]["input"]
    # Everything else survives, including the rest of the input section.
    assert reduced["run"]["input"]["sha256"] == "9f2c"
    assert reduced["run"]["input"]["packets_read"] == 14
    assert reduced["run"]["flabel_version"] == "0.1.0"


def test_the_same_capture_from_two_directories_compares_equal():
    """`run.input.path` is the operator's own path, so it differs by where they ran flabel.

    Spec §10 excludes it for exactly this reason: the same capture labelled from two directories
    would otherwise fail Goal 2, which would be a false alarm about the pipeline.
    """
    here = document()
    there = document(
        run={"input": {"path": "/mnt/other/branch.pcapng", "sha256": "9f2c", "packets_read": 14}}
    )

    assert (
        canonical.canonical_document(here)["run"]["input"]
        == canonical.canonical_document(there)["run"]["input"]
    )


def test_a_different_capture_still_shows():
    """The sha256 stays, so a different input is still a difference."""
    other = document(
        run={"input": {"path": "/captures/branch.pcapng", "sha256": "0000", "packets_read": 14}}
    )

    assert canonical.canonical_document(document()) != canonical.canonical_document(other)


def test_a_label_difference_still_shows():
    assert canonical.canonical_document(document()) != canonical.canonical_document(
        document(labels=[{"verdict": "malicious"}])
    )


def test_a_null_input_section_survives_canonicalisation():
    """A run that died before ingest has `input: null`, and the gate must not crash on it."""
    died = {"schema_version": "1.0", "run": {"started_at": "x", "input": None}}

    assert canonical.canonical_document(died)["run"]["input"] is None


def test_canonicalising_does_not_mutate_the_original():
    """The caller's document is theirs; a gate that edits what it inspects is a trap."""
    original = document()
    canonical.canonical_document(original)

    assert original["run"]["started_at"] == "2026-08-13T10:02:11.004530Z"
    assert original["run"]["input"]["path"] == "/captures/branch.pcapng"


# --- whole run directories -----------------------------------------------------------------------


def write_run(root: Path, *, opened: str, started: str, eve_uptime: int, conn: str) -> Path:
    """A run directory close enough to a real one to exercise every rule."""
    root.mkdir(parents=True, exist_ok=True)
    (root / "zeek").mkdir(exist_ok=True)
    (root / "suricata").mkdir(exist_ok=True)
    (root / "zeek" / "conn.log").write_text(tsv(conn, opened=opened), encoding="utf-8")
    (root / "zeek" / "packet_filter.log").write_text(tsv(f"{opened}\tfilter", opened=opened))
    (root / "suricata" / "eve.json").write_text(
        eve(ALERT, {**STATS, "stats": {"uptime": eve_uptime}}), encoding="utf-8"
    )
    (root / "suricata" / "suricata.log").write_text(f"{started} - <Notice> - running\n")
    (root / "run.json").write_text(
        json.dumps(document(run={"started_at": started})), encoding="utf-8"
    )
    (root / "NOTICE").write_text("flabel — attribution\n", encoding="utf-8")
    return root


def test_two_runs_over_one_capture_canonicalise_identically(tmp_path: Path):
    """Goal 2, in miniature: everything that legitimately differs run to run is erased."""
    first = write_run(
        tmp_path / "a",
        opened="2026-08-13-11-11-51",
        started="2026-08-13T11:11:51.000000Z",
        eve_uptime=3,
        conn="1700000000.000000\tCabc\t10.0.0.5",
    )
    second = write_run(
        tmp_path / "b",
        opened="2026-08-13-23-40-02",
        started="2026-08-13T23:40:02.000000Z",
        eve_uptime=91,
        conn="1700000000.000000\tCabc\t10.0.0.5",
    )

    assert canonical.differences(first, second) == []


def test_a_genuine_difference_is_reported_with_the_file_that_carries_it(tmp_path: Path):
    """A gate that says "these differ" without saying where is a gate nobody can act on."""
    first = write_run(
        tmp_path / "a",
        opened="2026-08-13-11-11-51",
        started="2026-08-13T11:11:51.000000Z",
        eve_uptime=3,
        conn="1700000000.000000\tCabc\t10.0.0.5",
    )
    second = write_run(
        tmp_path / "b",
        opened="2026-08-13-11-11-51",
        started="2026-08-13T11:11:51.000000Z",
        eve_uptime=3,
        conn="1700000000.000000\tCabc\t10.0.0.9",
    )

    reported = canonical.differences(first, second)

    assert len(reported) == 1
    assert "zeek/conn.log" in reported[0]


def test_a_file_present_in_only_one_run_is_a_difference(tmp_path: Path):
    """The sharpest case: a second run that lost `labels.json` entirely.

    An absent file compares equal to nothing at all if the walk only visits the first run's
    files, so a run that stopped writing verdicts would pass the gate silently.
    """
    first = write_run(
        tmp_path / "a",
        opened="2026-08-13-11-11-51",
        started="2026-08-13T11:11:51.000000Z",
        eve_uptime=3,
        conn="1700000000.000000\tCabc\t10.0.0.5",
    )
    second = write_run(
        tmp_path / "b",
        opened="2026-08-13-11-11-51",
        started="2026-08-13T11:11:51.000000Z",
        eve_uptime=3,
        conn="1700000000.000000\tCabc\t10.0.0.5",
    )
    (first / "labels.json").write_text(json.dumps(document()), encoding="utf-8")

    reported = canonical.differences(first, second)

    assert len(reported) == 1
    assert "labels.json" in reported[0]


def test_the_excluded_files_are_ignored_even_when_they_differ(tmp_path: Path):
    """`packet_filter.log` and `suricata.log` are wall-clock and pid, with no analytic content.

    Retained on disk rather than deleted — deleting a log the tool wrote would misrepresent the
    run — but never compared.
    """
    first = write_run(
        tmp_path / "a",
        opened="2026-08-13-11-11-51",
        started="2026-08-13T11:11:51.000000Z",
        eve_uptime=3,
        conn="1700000000.000000\tCabc\t10.0.0.5",
    )
    second = write_run(
        tmp_path / "b",
        opened="2026-08-13-11-11-51",
        started="2026-08-13T11:11:51.000000Z",
        eve_uptime=3,
        conn="1700000000.000000\tCabc\t10.0.0.5",
    )
    (second / "zeek" / "packet_filter.log").write_text("completely different\n", encoding="utf-8")
    (second / "suricata" / "suricata.log").write_text("also different\n", encoding="utf-8")

    assert canonical.differences(first, second) == []


def test_the_exclusions_are_exactly_the_specs(tmp_path: Path):
    """Guards against the exclusion list quietly growing to make a failing gate pass.

    Every name here is one spec §10 justifies individually. A list that can be appended to
    without argument is a list that will be.
    """
    assert (
        frozenset({"zeek/packet_filter.log", "suricata/suricata.log"}) == canonical.EXCLUDED_FILES
    )


# --- eve.json, measured rather than assumed (step 10) --------------------------------------------
#
# Spec §10 justified excluding only the `stats` records on the grounds that "`alert` and `flow`
# records are byte-stable". The exclusion is right; that reason was not. Two consecutive runs of
# Suricata 8.0.6 over the benign canary disagree in two further ways, and Goal 2 failed on both
# before these rules existed.


def test_the_run_local_flow_id_is_dropped():
    """Measured: the same alert on the same packet carries a different `flow_id` each run.

        run one   "flow_id": 1464040180
        run two   "flow_id": 1271398021

    It is Suricata's internal key joining an alert to its flow record within one run. flabel
    never reads it — correlation is by 5-tuple and time (spec §9) — so keeping it would fail
    Goal 2 on every run over a value that says nothing about the capture.
    """
    first = eve({**ALERT, "flow_id": 1464040180})
    second = eve({**ALERT, "flow_id": 1271398021})

    assert canonical.canonical_eve_records(first) == canonical.canonical_eve_records(second)
    assert "flow_id" not in canonical.canonical_eve_records(first)[0]


def test_records_are_compared_as_a_multiset_not_in_file_order():
    """Measured: the canary's two `flow` records swap order between runs.

    A positional comparison reported four fields differing — `src_ip`, `src_port`, `dest_ip`,
    `flow.start` — when nothing had changed but the order Suricata emitted them in. Same
    reasoning spec §10 already applies to `labels` and `unmatched_detections`.
    """
    one = {**FLOW, "src_port": 49152}
    two = {**FLOW, "src_port": 49153}

    assert canonical.canonical_eve_records(eve(one, two)) == canonical.canonical_eve_records(
        eve(two, one)
    )


def test_sorting_does_not_hide_a_lost_record():
    """The direction that keeps the sort honest: a multiset still counts."""
    one = {**FLOW, "src_port": 49152}
    two = {**FLOW, "src_port": 49153}

    assert canonical.canonical_eve_records(eve(one, two)) != canonical.canonical_eve_records(
        eve(one)
    )


def test_sorting_does_not_hide_a_duplicated_record():
    """A run that emitted the same alert twice is a difference, not a reordering."""
    assert canonical.canonical_eve_records(eve(ALERT, ALERT)) != canonical.canonical_eve_records(
        eve(ALERT)
    )


def test_dropping_flow_id_does_not_drop_the_alert_identity():
    """`flow_id` goes; nothing that identifies what fired goes with it."""
    (record,) = canonical.canonical_eve_records(eve({**ALERT, "flow_id": 1}))

    assert '"signature_id": 9000001' in record
    assert '"src_ip": "10.0.0.5"' in record


def test_the_flow_reason_race_is_dropped():
    """Measured over 14 consecutive runs: 13 `shutdown`, 1 `timeout` (step 10).

    `flow.reason` records whether Suricata's flow manager timed a flow out before end-of-pcap or
    flushed it at shutdown — a race against wall-clock, not a fact about the capture. At roughly
    one run in fourteen it would have failed Goal 2 unreproducibly, which is the failure mode
    that gets a gate disabled rather than fixed.
    """
    timed_out = eve({**FLOW, "flow": {"pkts_toserver": 7, "reason": "timeout"}})
    shutdown = eve({**FLOW, "flow": {"pkts_toserver": 7, "reason": "shutdown"}})

    assert canonical.canonical_eve_records(timed_out) == canonical.canonical_eve_records(shutdown)


def test_the_rest_of_the_flow_record_still_compares():
    """Dropping one field must not become dropping the record.

    The packet and byte counts are what would catch Suricata genuinely seeing different traffic,
    and they stay.
    """
    seven = eve({**FLOW, "flow": {"pkts_toserver": 7, "reason": "shutdown"}})
    nine = eve({**FLOW, "flow": {"pkts_toserver": 9, "reason": "shutdown"}})

    assert canonical.canonical_eve_records(seven) != canonical.canonical_eve_records(nine)


# --- the measurement, re-taken against the real Zeek ------------------------------------------
#
# `REPORTER_RUN_A`/`REPORTER_RUN_B` above are transcribed from a measurement taken by hand. That
# is exactly the shape of defect an earlier round of this project found and rejected — a spec
# amendment resting on a number that lived only in a docstring, where nothing would notice if the
# tool's behaviour changed underneath it. So the premise is re-measured against the pinned Zeek on
# every CI run, the same way step 7's ICMP counterpart tables are.


@pytest.mark.requires_tools
def test_zeek_really_does_stamp_wall_clock_on_a_startup_reporter_message(tmp_path: Path):
    """The premise `canonical_reporter_records` rests on, taken from the engine itself.

    Two runs over one capture, with a message raised in `zeek_init`. If Zeek ever stops writing
    wall-clock time into `ts` for startup messages, dropping the column is no longer justified and
    this test says so by failing — rather than the rule quietly outliving its reason.

    `-e` is used to provoke the message because flabel's own invocation does not raise one on the
    canary. What is being measured is Zeek's behaviour, which is what the rule depends on.
    """
    import subprocess
    import time

    from flabel import zeek

    capture = Path(__file__).resolve().parent / "fixtures" / "benign.pcap"
    outputs = []
    for name in ("one", "two"):
        outdir = tmp_path / name
        outdir.mkdir()
        subprocess.run(
            [
                zeek.executable(),
                "-C",
                "-D",
                "-r",
                str(capture),
                "-e",
                'event zeek_init() { Reporter::warning("flabel canonicalizer premise"); }',
            ],
            cwd=outdir,
            capture_output=True,
            check=True,
            timeout=120,
        )
        outputs.append((outdir / "reporter.log").read_text(encoding="utf-8"))
        time.sleep(1.1)  # so two wall-clock readings cannot land in the same microsecond

    first, second = outputs
    assert "flabel canonicalizer premise" in first, "the probe message was not raised"

    assert canonical.canonical_records(first) != canonical.canonical_records(second), (
        "two runs' reporter.log records were identical after dropping # header lines. If Zeek "
        "no longer stamps wall-clock time on a zeek_init message, canonical_reporter_records "
        "should stop dropping the ts column — do not relax the rule without re-measuring."
    )
    assert canonical.canonical_reporter_records(first) == canonical.canonical_reporter_records(
        second
    ), "dropping the ts column did not make two runs comparable"


@pytest.mark.requires_tools
def test_a_packet_time_reporter_message_is_reproducible(tmp_path: Path):
    """The other half of the premise: only *startup* messages carry wall-clock.

    Without this, "drop the ts column" could be justified by a Zeek that stamped wall-clock on
    everything — in which case `reporter.log` would have no reproducible content at all and
    excluding the file, not the column, would be the right answer.
    """
    import subprocess

    from flabel import zeek

    capture = Path(__file__).resolve().parent / "fixtures" / "benign.pcap"
    outputs = []
    for name in ("one", "two"):
        outdir = tmp_path / name
        outdir.mkdir()
        subprocess.run(
            [
                zeek.executable(),
                "-C",
                "-D",
                "-r",
                str(capture),
                "-e",
                "event new_connection(c: connection) "
                '{ Reporter::warning(fmt("flabel packet-time %s", c$id$orig_h)); }',
            ],
            cwd=outdir,
            capture_output=True,
            check=True,
            timeout=120,
        )
        outputs.append((outdir / "reporter.log").read_text(encoding="utf-8"))

    first, second = outputs
    assert "flabel packet-time" in first
    assert canonical.canonical_records(first) == canonical.canonical_records(second), (
        "a message raised while reading packets was not reproducible across runs. The ts column "
        "would then carry no stable value at all, and reporter.log should be excluded outright "
        "rather than canonicalised."
    )


def test_an_interrupted_write_is_not_compared_as_an_artifact(tmp_path: Path):
    """A temporary left by a killed process must not read as a reproducibility failure (#70).

    `canonicalise` walks the directory with `rglob`, which *does* return dotfiles — so before this
    was fixed a leftover `.labels.json.partial` was canonicalised like any other file. Two runs
    where only one had been interrupted then differed on a file neither run meant to publish,
    reporting a crash as a Goal 2 failure and naming the wrong cause.

    The first draft of `cli._write_atomic`'s docstring asserted the gate already ignored it. It did
    not — measured, then fixed. This is the assertion that makes the claim true.
    """
    first, second = tmp_path / "a", tmp_path / "b"
    for rundir in (first, second):
        rundir.mkdir()
        (rundir / "labels.json").write_text('{"schema_version": 1}', encoding="utf-8")

    assert canonical.differences(first, second) == []

    (first / ".labels.json.partial").write_text('{"schema_ver', encoding="utf-8")

    assert ".labels.json.partial" not in canonical.canonicalise(first)
    assert canonical.differences(first, second) == [], (
        "an in-progress write was compared as though the run had published it"
    )
