"""The broad false-positive review: realistic traffic, run end to end (issue #75).

`benign.pcap` is the *narrow* review — 14 synthetic packets whose correct label count is zero by
construction. This is the *broad* one: seventeen real protocol captures from suricata-verify,
covering HTTP/1.x, HTTP/2, FTP, DNS, MQTT, DCERPC, Kerberos and SMB.

**Why both.** Measured 2026-08-13: 23 of these captures against a real nine-feed snapshot produced
100 labels from `pawpatrules` on traffic that is benign by construction, while `benign.pcap`
produced zero against the same snapshot — correctly, because it contains none of the protocols
involved. One synthetic capture cannot review 85,431 rules spanning every protocol. That is #75,
and this corpus is what would have caught it on day one.

**What runs where.** These tests use the offline snapshot the rest of the suite uses, because spec
§2.2 forbids the test suite contacting rule feeds. So what they prove here is that the *pipeline*
invents nothing and survives real traffic. The corpus against the real ruleset — the review that
found #75 — belongs in `.github/workflows/feeds.yml` alongside Goal 5's real form.

Until this landed, the entire suite ran the pipeline over exactly one 14-packet synthetic capture.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from gates import ANY_IP_PROTOCOL, MISSES_CANARY, build_snapshot, offline, only_run_dir

from flabel import cli
from flabel.errors import EXIT_SUCCESS

CORPUS = Path(__file__).resolve().parents[1] / "fixtures" / "benign-corpus"

#: Sorted so a failure names the same capture on every machine.
CAPTURES = sorted(CORPUS.glob("*.pcap"))

pytestmark = pytest.mark.requires_tools


@pytest.fixture(scope="module", params=CAPTURES, ids=lambda p: p.stem)
def corpus_run(request, tmp_path_factory) -> tuple[Path, Path]:
    """One pipeline run per capture, shared by every assertion about it.

    Module-scoped on purpose. Each assertion below is a separate question about the same run, and
    giving them a fixture each would launch Zeek and Suricata three times per capture — 51 runs
    instead of 17, tripling the suite's wall-clock for no additional coverage. Suricata alone
    spends most of a run loading rules.

    Returns the capture and its run directory, so a failure still names which capture it was.
    """
    capture = request.param
    output = tmp_path_factory.mktemp(f"corpus-{capture.stem}") / "out"
    snapshot = tmp_path_factory.mktemp(f"rules-{capture.stem}") / "rules"
    build_snapshot(snapshot, {"et/open": list(MISSES_CANARY)})

    assert cli.main(offline(capture, snapshot, output)) == EXIT_SUCCESS, (
        f"{capture.name} did not complete a labelling run"
    )
    return capture, only_run_dir(output)


@pytest.fixture(scope="module", params=CAPTURES, ids=lambda p: p.stem)
def loud_corpus_run(request, tmp_path_factory) -> tuple[Path, Path]:
    """The same captures against a snapshot that actually fires, so tuples get compared (#87).

    A second module-scoped run per capture, and the cost is deliberate. `corpus_run` above uses
    `MISSES_CANARY` — three rules needing UDP/53 with literal `flabel-test`, ICMPv4 echo or
    ICMPv6 echo — and the corpus carries none of those. Measured: **0 detections across all 17
    captures**, which made the correlation assertion below `0 == 0` and blind to exactly the
    class of defect #84 turned out to be.

    `ANY_IP_PROTOCOL` is `alert ip any any -> any any`: it fires on every flow in every capture,
    so Suricata's 5-tuple meets Zeek's for real across HTTP/1.x, HTTP/2, FTP, DNS, MQTT, DCERPC,
    Kerberos and SMB — the protocols `benign.pcap` cannot reach.
    """
    capture = request.param
    output = tmp_path_factory.mktemp(f"loud-{capture.stem}") / "out"
    snapshot = tmp_path_factory.mktemp(f"loudrules-{capture.stem}") / "rules"
    build_snapshot(snapshot, {"et/open": [ANY_IP_PROTOCOL]})

    assert cli.main(offline(capture, snapshot, output)) == EXIT_SUCCESS, (
        f"{capture.name} did not complete a labelling run against the loud ruleset"
    )
    return capture, only_run_dir(output)


def test_the_corpus_is_actually_present():
    """A corpus that silently emptied would make every test below vacuously pass.

    `CAPTURES` is a glob, so a directory that failed to check out — or a `.gitignore` change that
    stopped tracking `.pcap` under `tests/fixtures/**` — would turn the parametrised tests into
    zero test cases and a green run.
    """
    assert len(CAPTURES) >= 15, f"expected the full corpus, found {[p.name for p in CAPTURES]}"
    assert (CORPUS / "README.md").is_file(), "the corpus must carry its provenance and licence"


def test_no_label_is_invented_on_ordinary_traffic(corpus_run: tuple[Path, Path]):
    """The broad Goal 5: a rule that should not match must not produce a verdict.

    Run against the offline snapshot, whose three rules cover UDP, ICMPv4 and ICMPv6 — none of
    which appear in this corpus. So the correct answer is zero for every capture, and a label
    here means the pipeline manufactured a verdict from traffic no rule matched.

    That is a stronger statement than it looks. Every other end-to-end test in this suite runs
    over one synthetic capture built to be uneventful; these are real protocol exchanges with
    retransmits, odd encodings, segmentation and authentication, and the pipeline has to stay
    quiet across all of them.
    """
    capture, rundir = corpus_run

    document = json.loads((rundir / "labels.json").read_text(encoding="utf-8"))
    assert document["labels"] == [], (
        f"{capture.name} produced {len(document['labels'])} label(s) against a ruleset that "
        f"cannot match it. Read the sources before touching this fixture."
    )


def test_every_capture_produces_a_complete_run_directory(corpus_run: tuple[Path, Path]):
    """Robustness across real traffic, which one synthetic fixture cannot establish.

    Ingest sniffs and normalizes, Zeek parses, Suricata reads, correlation joins on a 5-tuple
    whose spelling the two tools disagree about in three separate ways (spec §8). Each of those
    was measured against `benign.pcap` — two plain TCP flows. This is the first time any of it
    meets HTTP/2, Kerberos, MQTT or SMB.
    """
    _, rundir = corpus_run

    assert (rundir / "labels.json").is_file()
    assert (rundir / "run.json").is_file()
    assert (rundir / "NOTICE").is_file()


def test_no_detection_goes_unreported(loud_corpus_run: tuple[Path, Path]):
    """Spec §2.5 across the corpus: whatever happened, the run block says what.

    The unmatched gate is the specific risk. Correlation joins Suricata's 5-tuple to Zeek's, and
    §8 records four ways they disagree — protocol case, ICMP ports, IPv6 address form, and the
    transports Zeek cannot name — each found by measurement rather than inference. A protocol this
    corpus carries and `benign.pcap` does not could expose a fifth, and it would surface as
    detections that cannot be placed.

    **Runs against the loud ruleset, and asserts detections exist before asserting none were
    lost** (#87). Until 2026-08-14 this used `corpus_run`, whose snapshot cannot match anything in
    this corpus: measured 0 detections in all 17 captures, so `unmatched == 0` was `0 == 0` and no
    tuple was ever compared. The docstring claimed the stronger property for weeks. The
    `detections > 0` assertion is the half that stops it quietly reverting.
    """
    capture, rundir = loud_corpus_run

    run = json.loads((rundir / "run.json").read_text(encoding="utf-8"))["run"]
    counts = run["counts"]

    assert counts["detections"] > 0, (
        f"{capture.name}: the loud ruleset produced no detection, so this test compared no "
        f"tuples. That is the #87 failure returning — fix the fixture, not the assertion."
    )
    assert counts["unmatched"] == 0, (
        f"{capture.name}: {counts['unmatched']} of {counts['detections']} detections could not "
        f"be attached to a flow. If the tuples disagree on a protocol benign.pcap does not "
        f"carry, that is a correlation defect, not a fixture problem."
    )
    assert counts["flows"] is not None
    assert run["loss_conditions"]["detection_uncorrelatable"] is False
