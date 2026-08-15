"""Suricata invocation and eve.json parsing (docs/spec.md §8, PLAN.md step 6).

Suricata is invoked for real here — the testing line is *tools real, network stubbed*
(spec §2), and a mock would encode our assumptions about the very tool behaviour that needs
verifying. Those tests carry ``@pytest.mark.requires_tools``. Nothing in this file makes a
network call or contacts a PANW device.

The rules are synthesized — ``tests/fixtures/rules/synthetic.rules``, whose header explains
what each one is for and why only one of them uses ``$HOME_NET`` — so that every expectation
here is *known-correct* rather than empirical.

Snapshots are built with step 4's own ``write_snapshot``, not hand-assembled. An earlier
version of this file wrote the layout itself, which meant its snapshot fixtures agreed with
this module's reader by construction and could not have caught a disagreement with the real
writer. Everything about reading and verifying a snapshot — the content hash, the manifest,
the sid index — is now `rules/snapshot.py`'s, and is tested there.

Captures beyond the benign canary (TLS for JA4, UDP and ICMP for the tuple) are generated into
``tmp_path`` rather than committed: ``tests/fixtures/`` has a deliberately narrow
``.gitignore`` exception, and a capture that regenerates byte-for-byte does not need to be in
git.
"""

from __future__ import annotations

import importlib.util
import ipaddress
import json
import re
import struct
import time
from collections.abc import Mapping, Sequence
from pathlib import Path

import pytest

from flabel import suricata
from flabel.errors import SnapshotError, ToolError
from flabel.models import SourceAdmission
from flabel.rules.admit import negates_home_net
from flabel.rules.snapshot import load_snapshot, snapshot_id_for, write_snapshot

FIXTURES = Path(__file__).resolve().parent / "fixtures"
BENIGN = FIXTURES / "benign.pcap"
SYNTHETIC_RULES = FIXTURES / "rules" / "synthetic.rules"

#: SIDs in ``synthetic.rules``; see that file for what each one matches.
HTTP_SID = 9000001
JA4_SID = 9000002
IDENTIFY_SID = 9000003
UNLOADABLE_SID = 9000004
HOME_NET_SID = 9000005
DNS_SID = 9000006
ICMP_SID = 9000007
ICMP6_SID = 9000008
HOME_NET_NEGATED_SID = 9000009

#: A well-formed id that is not the hash of anything, for injecting an inconsistent snapshot.
WRONG_SNAPSHOT_ID = "0123456789abcdef"

#: Step 4's SID→source attribution file, which step 6 reads instead of re-deriving from `raw/`.
SID_INDEX = "sid_index.json"

#: The alert timestamps the HTTP rule must carry, one per canary flow: ``make_canary.BASE_TS``
#: + 0.05s, and the same 10s later. Each flow runs one packet every 0.01s and the request is its
#: 4th; Suricata raises the alert on the 6th (``pcap_cnt`` 6), when the stream has been
#: reassembled — i.e. on the packet Suricata was looking at, not the one carrying the bytes.
#: Asserted as absolute epoch values because correlation joins them against Zeek's epoch ``ts``
#: (spec §9).
#:
#: Two of them because **both** canary flows are cleartext HTTP to port 80. Flow 2 used to go to
#: 443, which made the fixture itself anomalous — see `make_canary.py`'s `FLOWS`.
HTTP_ALERT_TS = 1700000000.05
HTTP_ALERT_TS_2 = 1700000010.05

SEMVER = re.compile(r"\d+\.\d+\.\d+")


# --- fixture generators -------------------------------------------------------------------


def _load_canary() -> object:
    """Load ``make_canary.py`` as a module for its packet-building helpers.

    Imported rather than re-implemented: its IP/TCP checksum code is already verified
    against Zeek and Suricata, and a capture with a wrong checksum is exactly the kind of
    fixture that fails in a way no assertion explains. It is a fixture generator, not
    library code, hence the explicit file load.
    """
    spec = importlib.util.spec_from_file_location("flabel_make_canary", FIXTURES / "make_canary.py")
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


CANARY = _load_canary()

TLS_CLIENT = "10.0.0.7"
TLS_SERVER = "10.0.0.202"
TLS_SPORT = 49200
TLS_BASE_TS = 1700000100.0


def _extension(kind: int, body: bytes) -> bytes:
    return struct.pack("!HH", kind, len(body)) + body


def _client_hello() -> bytes:
    """A TLS 1.3 ClientHello whose JA4_a segment is ``t13d0405h2``.

    Fixed content — including the 32 "random" bytes — so the JA4 value is identical on every
    run: TCP, TLS 1.3 (from ``supported_versions``), SNI present, 4 ciphers, 5 extensions,
    first ALPN ``h2``. That is what ``synthetic.rules`` sid 9000002 matches on.
    """
    host = b"flabel.test"
    server_name = _extension(0x0000, struct.pack("!HBH", len(host) + 3, 0, len(host)) + host)
    supported_groups = _extension(0x000A, struct.pack("!HH", 2, 0x001D))
    signature_algorithms = _extension(0x000D, struct.pack("!HHHH", 6, 0x0403, 0x0804, 0x0401))
    alpn_body = b"\x02h2"
    alpn = _extension(0x0010, struct.pack("!H", len(alpn_body)) + alpn_body)
    supported_versions = _extension(0x002B, struct.pack("!BHH", 4, 0x0304, 0x0303))
    extensions = server_name + supported_groups + signature_algorithms + alpn + supported_versions

    ciphers = struct.pack("!HHHH", 0x1301, 0x1302, 0x1303, 0xC02F)
    body = (
        struct.pack("!H", 0x0303)
        + bytes(range(32))
        + b"\x00"  # no session id
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"  # compression: null only
        + struct.pack("!H", len(extensions))
        + extensions
    )
    handshake = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + struct.pack("!H", len(handshake)) + handshake


def write_tls_capture(path: Path) -> None:
    """One TCP flow to port 443 carrying the ClientHello above, byte-deterministic."""
    hello = _client_hello()
    client_seq, server_seq = 2000, 7000
    steps = [
        (TLS_CLIENT, TLS_SERVER, TLS_SPORT, 443, client_seq, 0, CANARY.SYN, b""),
        (
            TLS_SERVER,
            TLS_CLIENT,
            443,
            TLS_SPORT,
            server_seq,
            client_seq + 1,
            CANARY.SYN | CANARY.ACK,
            b"",
        ),
        (TLS_CLIENT, TLS_SERVER, TLS_SPORT, 443, client_seq + 1, server_seq + 1, CANARY.ACK, b""),
        (
            TLS_CLIENT,
            TLS_SERVER,
            TLS_SPORT,
            443,
            client_seq + 1,
            server_seq + 1,
            CANARY.PSH | CANARY.ACK,
            hello,
        ),
        (
            TLS_SERVER,
            TLS_CLIENT,
            443,
            TLS_SPORT,
            server_seq + 1,
            client_seq + 1 + len(hello),
            CANARY.ACK,
            b"",
        ),
        (
            TLS_CLIENT,
            TLS_SERVER,
            TLS_SPORT,
            443,
            client_seq + 1 + len(hello),
            server_seq + 1,
            CANARY.FIN | CANARY.ACK,
            b"",
        ),
        (
            TLS_SERVER,
            TLS_CLIENT,
            443,
            TLS_SPORT,
            server_seq + 1,
            client_seq + 2 + len(hello),
            CANARY.FIN | CANARY.ACK,
            b"",
        ),
    ]

    packets = []
    for index, (src, dst, sport, dport, seq, ack, flags, payload) in enumerate(steps):
        segment = CANARY.tcp(sport, dport, seq, ack, flags, src, dst, payload)
        frame = CANARY.ethernet(CANARY.ipv4(src, dst, segment, ident=500 + index))
        packets.append((TLS_BASE_TS + index * 0.01, frame))
    CANARY.write_pcap(str(path), packets)


UDP_CLIENT = "10.0.0.9"
UDP_SERVER = "10.0.0.204"
UDP_SPORT = 53124
ICMP_CLIENT = "10.0.0.8"
ICMP_SERVER = "10.0.0.203"
ICMP6_CLIENT = "fd00::a1"
ICMP6_SERVER = "fd00::a2"
MIXED_BASE_TS = 1700000200.0


def _udp(sport: int, dport: int, payload: bytes, src: str, dst: str) -> bytes:
    length = 8 + len(payload)
    blank = struct.pack("!HHHH", sport, dport, length, 0) + payload
    pseudo = CANARY._packed_ip(src) + CANARY._packed_ip(dst) + struct.pack("!BBH", 0, 17, length)
    return struct.pack("!HHHH", sport, dport, length, CANARY.checksum(pseudo + blank)) + payload


def _dns_query(name: bytes = b"flabel-test.invalid") -> bytes:
    labels = b"".join(bytes([len(part)]) + part for part in name.split(b".")) + b"\x00"
    return struct.pack("!HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0) + labels + struct.pack("!HH", 1, 1)


def _icmp4(kind: int, code: int) -> bytes:
    blank = struct.pack("!BBHHH", kind, code, 0, 1, 1) + b"flabel"
    return struct.pack("!BBHHH", kind, code, CANARY.checksum(blank), 1, 1) + b"flabel"


def _icmp6(kind: int, code: int, src: bytes, dst: bytes) -> bytes:
    body = struct.pack("!BBHHH", kind, code, 0, 1, 1) + b"flabel"
    pseudo = src + dst + struct.pack("!IBBBB", len(body), 0, 0, 0, 58)
    checksum = CANARY.checksum(pseudo + body)
    return struct.pack("!BBHHH", kind, code, checksum, 1, 1) + b"flabel"


def _ipv6(src: bytes, dst: bytes, payload: bytes, next_header: int) -> bytes:
    return struct.pack("!IHBB", 0x60000000, len(payload), next_header, 64) + src + dst + payload


def write_mixed_capture(path: Path) -> None:
    """A UDP DNS query plus ICMPv4 and ICMPv6 echoes: the protocols the canary lacks.

    Generated rather than committed, and generated *here* rather than added to
    `make_canary.py`, which the benign canary's "zero labels" guarantee depends on staying
    exactly as it is.
    """
    v6_src = ipaddress.ip_address(ICMP6_CLIENT).packed
    v6_dst = ipaddress.ip_address(ICMP6_SERVER).packed
    query = _dns_query()

    frames = [
        CANARY.ethernet(
            CANARY.ipv4(
                UDP_CLIENT,
                UDP_SERVER,
                _udp(UDP_SPORT, 53, query, UDP_CLIENT, UDP_SERVER),
                proto=17,
                ident=800,
            )
        ),
        CANARY.ethernet(CANARY.ipv4(ICMP_CLIENT, ICMP_SERVER, _icmp4(8, 0), proto=1, ident=801)),
        CANARY.ethernet(CANARY.ipv4(ICMP_SERVER, ICMP_CLIENT, _icmp4(0, 0), proto=1, ident=802)),
        _ETHER6 + _ipv6(v6_src, v6_dst, _icmp6(128, 0, v6_src, v6_dst), 58),
        _ETHER6 + _ipv6(v6_dst, v6_src, _icmp6(129, 0, v6_dst, v6_src), 58),
    ]
    CANARY.write_pcap(
        str(path), [(MIXED_BASE_TS + index * 0.01, frame) for index, frame in enumerate(frames)]
    )


#: An Ethernet header with the IPv6 ethertype; `make_canary.ethernet` hardcodes IPv4's.
_ETHER6 = CANARY.SRC_MAC + CANARY.DST_MAC + b"\x86\xdd"


def rule_lines() -> dict[int, str]:
    """The synthetic rules, keyed by SID."""
    lines = {}
    for line in SYNTHETIC_RULES.read_text(encoding="utf-8").splitlines():
        if not line.startswith("alert"):
            continue
        match = re.search(r"\bsid:(\d+);", line)
        assert match is not None, f"synthetic rule has no sid: {line}"
        lines[int(match.group(1))] = line
    return lines


RULES = rule_lines()


def make_snapshot(
    root: Path,
    contents: Mapping[str, Sequence[int]],
    classes: Mapping[str, str] | None = None,
    *,
    data: Mapping[str, Mapping[str, bytes]] | None = None,
) -> Path:
    """A real snapshot, written by step 4's `write_snapshot`, from `contents` (source → SIDs).

    Written by the real writer rather than assembled here on purpose: a hand-built fixture would
    agree with this module's reader by construction, which is exactly the disagreement worth
    catching. The returned path is the snapshot directory, named by its own id.
    """
    classes = classes or {}
    admitted = {name: [RULES[sid] for sid in sorted(contents[name])] for name in sorted(contents)}
    admissions = [
        SourceAdmission(
            name=name,
            url=f"https://example.invalid/{name}.rules",
            licence="MIT",
            source_class=classes.get(name, "signature"),
            admission_basis="wholesale",
            rules_fetched=len(rules),
            rules_admitted=len(rules),
            rules_excluded_no_confidence=0,
            rules_excluded_low_confidence=0,
            rules_excluded_low_severity=0,
            rules_excluded_commented=0,
            ja4_rules_admitted=sum("ja4.hash" in rule for rule in rules),
            ja3_rules_admitted=0,
            fetched_at="2026-08-12T00:00:00.000000Z",
        )
        for name, rules in admitted.items()
    ]
    root = root / "rules"
    manifest = write_snapshot(
        root, admitted, admissions, data=data, created_at="2026-08-12T00:00:00.000000Z"
    )
    return root / manifest.snapshot_id


def reseal(snapshot: Path) -> Path:
    """Rewrite `manifest.json` so its id matches content a test has just edited.

    A snapshot's id is a hash of its content, and `load_snapshot` re-checks it — so a test that
    injects a *content* fault has to re-seal, or it only ever proves the hash check works (which
    `test_snapshot.py` already does). The directory is renamed to the new id, because
    `load_snapshot` also requires the two to agree.
    """
    document = json.loads((snapshot / "manifest.json").read_text())
    components = {
        path.relative_to(snapshot).as_posix(): path.read_bytes()
        for path in sorted(snapshot.rglob("*"))
        if path.is_file() and not path.match("manifest.json") and "raw" not in path.parts
    }
    document["snapshot_id"] = snapshot_id_for(components)
    (snapshot / "manifest.json").write_text(json.dumps(document, indent=2))
    resealed = snapshot.parent / document["snapshot_id"]
    snapshot.rename(resealed)
    return resealed


def set_sid_index(snapshot: Path, sources: Mapping[str, Sequence[int]], schema: int = 1) -> Path:
    """Overwrite the attribution file and re-seal, so only the attribution is under test."""
    (snapshot / SID_INDEX).write_text(
        json.dumps({"schema": schema, "sources": {name: list(sources[name]) for name in sources}})
    )
    return reseal(snapshot)


# --- the invocation itself -----------------------------------------------------------------


def test_argv_loads_only_the_snapshot_ruleset():
    """The flags of spec §8, asserted as a contract rather than trusted to a comment.

    ``-S`` *replaces* the ruleset; ``-s`` would *add* to whatever the system config already
    loads. Getting that wrong is invisible in the output — labels would silently carry SIDs
    from rules that are in no snapshot, i.e. a verdict whose origin cannot be traced
    (spec §13). Same reasoning as step 5's regression test on Zeek's ``-D``.
    """
    # Resolved, not literal: `build_argv` absolutises every path, and on macOS `/tmp` is a
    # symlink to `/private/tmp`, so the expectation has to be resolved the same way.
    capture, snapshot, outdir = (
        Path("/tmp/cap.pcap").resolve(),
        Path("/snap").resolve(),
        Path("/out").resolve(),
    )
    argv = suricata.build_argv(capture, snapshot, outdir)

    assert argv[0] == "suricata"
    assert argv[argv.index("-r") + 1] == str(capture)
    assert argv[argv.index("-l") + 1] == str(outdir)
    assert argv[argv.index("-S") + 1] == str(snapshot / "rules.rules")
    assert "-s" not in argv, "-s adds to the system ruleset; only -S replaces it"
    assert "--rule-reload" not in argv
    assert argv[argv.index("--runmode") + 1] == "single"
    assert "--set" in argv
    assert "app-layer.protocols.tls.ja3-fingerprints=yes" in argv
    assert "app-layer.protocols.tls.ja4-fingerprints=yes" in argv


def test_argv_uses_flabels_own_config_not_the_machines():
    """``-c``, and the two config files it names, are part of the contract.

    Without ``-c`` the operator's `/etc/suricata/suricata.yaml` decides whether an abuse.ch
    ``$HOME_NET -> $EXTERNAL_NET`` rule can fire, what `classtype` text lands in provenance, and
    whether capture payloads are written to disk. `default-rule-path` is pinned to the snapshot
    so a rule's own relative paths (``dataset:``) cannot reach outside it.
    """
    argv = suricata.build_argv(Path("/tmp/cap.pcap"), Path("/snap"), Path("/out"))
    settings = {argv[index + 1] for index, value in enumerate(argv) if value == "--set"}

    config = Path(argv[argv.index("-c") + 1])
    assert config.name == "suricata.yaml"
    assert config.is_absolute() and config.exists(), "the config must ship as package data"
    assert f"classification-file={config.parent / 'classification.config'}" in settings
    assert not any(setting.startswith("reference-config-file=") for setting in settings), (
        "reference.config was dropped: measured, its absence changes the rule load by 0 rules"
    )
    assert f"default-rule-path={Path('/snap').resolve()}" in settings


def test_argv_paths_are_absolute_whatever_the_working_directory(tmp_path, monkeypatch):
    """A relative snapshot path must not reach the tool.

    Measured on 8.0.6: a relative ``-S`` is resolved against the working directory
    (``default-rule-path`` is *not* prepended, though the docs read as though it might be). Spec
    §12's default ``--rules-dir ./.flabel/rules`` is relative, so this is the ordinary case, and
    an argv that only works from one directory is not a reproducible failure report either.
    """
    monkeypatch.chdir(tmp_path)
    (tmp_path / "snap").mkdir()

    argv = suricata.build_argv(Path("cap.pcap"), Path("snap"), Path("out"))

    for flag in ("-r", "-S", "-l"):
        value = Path(argv[argv.index(flag) + 1])
        assert value.is_absolute(), f"{flag} was given the relative path {value}"
        assert str(value).startswith(str(tmp_path.resolve()))


def test_the_vendored_config_is_hashed_for_the_run_block():
    """One digest over every config file, so a run can say which configuration produced it.

    `HOME_NET`, the classtype descriptions and the eve output selection all change what a label
    says, so "same input, same output" is only meaningful against a known config (Goal 2).
    """
    digest = suricata.config_sha256()

    assert re.fullmatch(r"[0-9a-f]{64}", digest)
    names = [path.name for path in suricata.config_files()]
    assert names == ["suricata.yaml", "classification.config"]
    assert all(path.exists() for path in suricata.config_files())
    assert suricata.config_sha256() == digest, "the digest must not depend on read order"


@pytest.mark.requires_tools
def test_the_vendored_config_makes_a_home_net_rule_fire(tmp_path):
    """The point of `-c`, proved rather than asserted.

    `synthetic.rules` sid 9000005 is written the way the abuse.ch feeds write their C2 rules —
    ``$HOME_NET any -> $EXTERNAL_NET $HTTP_PORTS``. The benign canary is RFC 1918 on both ends,
    so under Suricata's stock config (`EXTERNAL_NET: "!$HOME_NET"`) that rule can match nothing
    at all. Measured: stock config → 0 alerts, flabel's config → 2, one per canary flow. Every
    abuse.ch label on an internal capture depends on this.
    """
    snapshot = make_snapshot(tmp_path, {"abuse.ch/feodotracker": [HOME_NET_SID]})

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert info.tool_failures == ()
    assert [detection.sid for detection in detections] == [HOME_NET_SID, HOME_NET_SID], (
        "a $HOME_NET -> $EXTERNAL_NET rule did not fire on an internal-to-internal capture, "
        "which is what HOME_NET: any in flabel's own suricata.yaml exists to prevent"
    )


@pytest.mark.requires_tools
def test_the_engine_accepts_flabels_config_files_without_complaint(tmp_path):
    """Suricata must parse our own config files cleanly, line for line.

    This is a regression test for a real mistake: an earlier version of
    `classification.config` put the measured rule count in a trailing `# comment` on each
    `config classification:` line, and Suricata rejected **every one of them** with "Invalid
    Classtype" — while still exiting 0, still loading every rule, and still producing correct
    labels, because `classtype` is read from the rule text. The file was entirely inert and
    nothing else would have noticed.
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})

    suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    log = (tmp_path / "out" / "suricata.log").read_text()
    complaints = [line for line in log.splitlines() if "Error" in line or "Invalid" in line]
    assert complaints == [], f"the engine rejected part of flabel's own config: {complaints}"
    assert "unknown classtype" not in log, (
        "classification.config is missing a classtype the fixtures use; regenerate it from a "
        "snapshot (see the file's header)"
    )


@pytest.mark.requires_tools
def test_synthetic_rule_yields_one_fully_populated_detection_per_flow(tmp_path):
    """A rule matching the benign canary parses into a fully-populated `Detection` per flow.

    Two, not one: both canary flows are cleartext HTTP to port 80, so a port-80 rule fires on
    each. Returned in eve.json order, which is capture order — flow 1 then flow 2.
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert info.tool_failures == ()
    assert len(detections) == 2
    detection = detections[0]

    assert detection.source == "et/open"
    assert detection.tier == 2
    assert (detection.sid, detection.rev) == (HTTP_SID, 3)
    # The classtype the *rule* declares, read from the hashed snapshot — not eve.json's
    # `alert.category`, which is only a description looked up in a config file. See
    # `rule_classtypes`; this changed what a label carries, from "A Network Trojan was
    # detected" to the classtype itself.
    assert detection.classtype == "trojan-activity"
    assert detection.threat == "FLABEL TEST synthetic HTTP request"
    assert detection.app_proto == "http"
    assert detection.ts == pytest.approx(HTTP_ALERT_TS)
    assert (detection.src_ip, detection.src_port) == ("10.0.0.5", 49152)
    assert (detection.dst_ip, detection.dst_port) == ("10.0.0.200", 80)
    # Lowercase, because Zeek's conn.log writes `tcp` and correlation matches the two
    # 5-tuples field by field. Suricata reports `TCP`.
    assert detection.proto == "tcp"
    assert detection.metadata == (
        "confidence High",
        "created_at 2026_08_12",
        "signature_severity Major",
    )

    # The second flow's detection differs only in endpoint and timing — same rule, same
    # provenance — which is what makes it a second *label* rather than a duplicate.
    second = detections[1]
    assert (second.sid, second.source, second.classtype) == (HTTP_SID, "et/open", "trojan-activity")
    assert (second.src_ip, second.src_port) == ("10.0.0.6", 49153)
    assert (second.dst_ip, second.dst_port) == ("10.0.0.201", 80)
    assert second.ts == pytest.approx(HTTP_ALERT_TS_2)

    assert info.snapshot_id == snapshot.name, "the id is the directory name"
    assert info.alerts_total == 2
    assert info.identify_alerts_suppressed == 0
    assert info.rules_loaded == 1, "only the snapshot's one rule may load — no ambient ruleset"
    assert (info.rules_failed, info.rules_skipped) == (0, 0)
    assert info.warnings == (), "a ruleset that loaded in full has nothing to warn about"
    # The configuration is part of what makes a run reproducible: `HOME_NET` decides whether a
    # whole class of rule can fire at all, so the run block records which config was in force.
    assert info.config_sha256 == suricata.config_sha256()
    assert SEMVER.fullmatch(info.version), f"unparsed version {info.version!r}"

    # eve.json is a mixed stream — flow, http, fileinfo and stats records share it with
    # alerts. If the event_type filter were dropped, `alerts_total` would count those too.
    events = {
        json.loads(line)["event_type"]
        for line in (tmp_path / "out" / "eve.json").read_text().splitlines()
        if line.strip()
    }
    assert events > {"alert"}, f"eve.json held only alerts, so the filter proves nothing: {events}"


@pytest.mark.requires_tools
def test_ja4_rule_matches_a_tls_fixture(tmp_path):
    """A `ja4.hash` rule can produce a detection at all (US-14).

    ET Open 8.0 was measured to contain **zero** ``ja4.hash`` rules, so no real feed
    exercises this path. Without this test the JA4 labelling capability is unevidenced —
    the pipeline could ship unable to act on a JA4 rule and every other test would pass.
    """
    capture = tmp_path / "tls.pcap"
    write_tls_capture(capture)
    snapshot = make_snapshot(tmp_path, {"et/open": [JA4_SID]})

    detections, info = suricata.run_suricata(capture, snapshot, tmp_path / "out")

    assert info.tool_failures == ()
    assert len(detections) == 1, "the JA4 fingerprint rule did not match the ClientHello"
    detection = detections[0]
    assert detection.sid == JA4_SID
    assert detection.app_proto == "tls"
    assert (detection.src_ip, detection.src_port) == (TLS_CLIENT, TLS_SPORT)
    assert (detection.dst_ip, detection.dst_port) == (TLS_SERVER, 443)
    assert detection.ts == pytest.approx(TLS_BASE_TS + 0.03, abs=0.05)


@pytest.fixture
def half_hour_timezone(monkeypatch):
    """Run the test — and the Suricata it spawns — in a +05:30 timezone."""
    monkeypatch.setenv("TZ", "Asia/Kolkata")
    time.tzset()
    yield
    monkeypatch.undo()
    time.tzset()


@pytest.mark.requires_tools
def test_alert_timestamps_do_not_depend_on_the_local_timezone(tmp_path, half_hour_timezone):
    """`Detection.ts` is an absolute epoch value, whatever timezone the machine is in.

    Suricata writes eve timestamps in **local time with an offset**
    (``2023-11-15T03:43:20.050000+0530`` here). CI runs in UTC and a laptop does not, so an
    implementation that read the wall-clock part and ignored the offset would produce
    different timestamps for the same capture on different machines — a reproducibility break
    (Goal 2) that no other test in this file would notice, because they all run in one zone.
    A half-hour zone is used so an hours-only bug cannot pass either.
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})

    detections, _ = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert detections[0].ts == pytest.approx(HTTP_ALERT_TS)
    eve = (tmp_path / "out" / "eve.json").read_text()
    assert "+0530" in eve, "the fixture did not take effect, so nothing was proved"


@pytest.mark.requires_tools
def test_the_run_directory_holds_no_capture_content(tmp_path):
    """flabel processes other people's traffic; the run directory must not become a copy of it.

    Stock Suricata configurations commonly enable `file-store`, `pcap-log` or eve `payload`, any
    of which writes capture bytes to disk. flabel's own config disables all of them, and this
    asserts the *result* rather than trusting the YAML — it is also the list spec §10 needs for
    its reproducibility exclusions: `eve.json` (whose `stats` records are wall-clock) and
    `suricata.log` (wall-clock throughout, never reproducible).
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})
    outdir = tmp_path / "out"

    suricata.run_suricata(BENIGN, snapshot, outdir)

    assert sorted(path.name for path in outdir.iterdir()) == ["eve.json", "suricata.log"]
    records = [json.loads(line) for line in (outdir / "eve.json").read_text().splitlines() if line]
    assert {record["event_type"] for record in records} <= {"alert", "flow", "stats"}
    for record in records:
        assert "payload" not in record and "payload_printable" not in record
        assert "packet" not in record


@pytest.mark.requires_tools
def test_a_udp_detection_carries_the_tuple_zeek_will_have(tmp_path):
    """UDP, which the benign canary has none of and ET Open's DNS rules are full of.

    The values asserted are the ones Zeek writes for the same fixture (measured:
    ``10.0.0.9 53124 -> 10.0.0.204 53 udp``), because correlation compares the two field by
    field. Without this, nothing in step 6 evidences that a DNS detection can be matched at all.
    """
    capture = tmp_path / "mixed.pcap"
    write_mixed_capture(capture)
    snapshot = make_snapshot(tmp_path, {"et/open": [DNS_SID]})

    detections, info = suricata.run_suricata(capture, snapshot, tmp_path / "out")

    assert info.tool_failures == ()
    assert len(detections) == 1
    detection = detections[0]
    assert detection.proto == "udp"
    assert (detection.src_ip, detection.src_port) == (UDP_CLIENT, UDP_SPORT)
    assert (detection.dst_ip, detection.dst_port) == (UDP_SERVER, 53)
    assert detection.app_proto == "dns"


@pytest.mark.requires_tools
def test_icmp_detections_mirror_zeeks_port_columns(tmp_path):
    """ICMP has no ports, and `(0, 0)` would make every ICMP detection uncorrelatable.

    Zeek writes the ICMP type in `id.orig_p` and the counterpart type in `id.resp_p`; Suricata's
    alert record has `icmp_type`/`icmp_code` and no ports at all. Measured on this fixture —
    Zeek: ``icmp 8 -> 0`` for the v4 echo and ``icmp 128 -> 129`` for the v6 one; Suricata:
    ``icmp_type 8/128, icmp_code 0``. ET Open ships plenty of ICMP rules, and spec §9 fails the
    **whole run** above 1% unmatched, so three uncorrelatable ICMP alerts in 150 detections would
    be enough to lose every label in the run.

    The v6 case also pins the protocol name: Suricata says `IPv6-ICMP`, Zeek says `icmp`, and
    lowercasing alone would leave the two unable to ever match.
    """
    capture = tmp_path / "mixed.pcap"
    write_mixed_capture(capture)
    snapshot = make_snapshot(tmp_path, {"et/open": [ICMP_SID, ICMP6_SID]})

    detections, info = suricata.run_suricata(capture, snapshot, tmp_path / "out")

    assert info.tool_failures == ()
    by_sid = {detection.sid: detection for detection in detections}
    assert set(by_sid) == {ICMP_SID, ICMP6_SID}

    v4 = by_sid[ICMP_SID]
    assert v4.proto == "icmp"
    assert (v4.src_ip, v4.src_port) == (ICMP_CLIENT, 8), "ICMP type belongs in the source port"
    assert (v4.dst_ip, v4.dst_port) == (ICMP_SERVER, 0), "ICMP code belongs in the dest port"

    v6 = by_sid[ICMP6_SID]
    assert v6.proto == "icmp", "Zeek writes `icmp` for ICMPv6; `ipv6-icmp` could never match"
    # Compressed, as Zeek writes it. Suricata writes the expanded form, and correlation compares
    # the strings — so an unnormalised address makes every IPv6 detection unmatchable.
    assert (v6.src_ip, v6.dst_ip) == (ICMP6_CLIENT, ICMP6_SERVER)
    assert v6.src_port == 128


@pytest.mark.requires_tools
def test_identify_source_alert_is_suppressed(tmp_path):
    """An `identify` source's rule fires and produces no detection (spec §2.8, US-16).

    The rule matches; suppression happens on the *source class*, not on whether the rule was
    any good. Counted rather than dropped silently, because absence is never a signal
    (spec §2.5).
    """
    snapshot = make_snapshot(
        tmp_path, {"oisf/trafficid": [IDENTIFY_SID]}, {"oisf/trafficid": "identify"}
    )

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert info.tool_failures == ()
    assert detections == [], "an identify-class source may never produce a label"
    assert info.alerts_total == 2, "the rule must genuinely have fired for this to prove anything"
    assert info.identify_alerts_suppressed == 2, "one per canary flow, and none of them a label"


@pytest.mark.requires_tools
def test_suppression_is_per_source_not_per_run(tmp_path):
    """One snapshot, two sources: the labelling one survives, the `identify` one does not.

    This is what makes SID→source resolution load-bearing. Both rules match the same flow,
    so a resolver that attributed either alert to the wrong source would either lose a real
    detection or emit one it must never emit.
    """
    snapshot = make_snapshot(
        tmp_path,
        {"et/open": [HTTP_SID], "oisf/trafficid": [IDENTIFY_SID]},
        {"oisf/trafficid": "identify"},
    )

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert info.tool_failures == ()
    assert [(d.source, d.sid) for d in detections] == [("et/open", HTTP_SID)] * 2
    assert info.rules_loaded == 2
    # Two rules × two canary flows: four alerts, of which the identify source's two are dropped.
    assert info.alerts_total == 4
    assert info.identify_alerts_suppressed == 2
    assert len(detections) == info.alerts_total - info.identify_alerts_suppressed


@pytest.mark.requires_tools
def test_a_capture_that_matches_nothing_is_an_empty_result_not_a_failure(tmp_path):
    """The case every failure path above exists to be distinguishable *from*.

    Rules loaded, capture read, nothing matched: no detections, no tool failure, and a
    non-zero `rules_loaded` to show the run genuinely looked. Without this pinned, a future
    "fail on zero alerts" would look reasonable and would break the ordinary case — and the
    benign canary (which must produce zero labels and still pass) depends on it.
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [JA4_SID]})

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert detections == []
    assert info.tool_failures == ()
    assert info.alerts_total == 0
    assert info.identify_alerts_suppressed == 0
    assert info.rules_loaded == 1


def test_attribution_comes_from_the_sid_index_not_from_raw_rule_text(tmp_path):
    """`sid_index.json` is the authority, and `raw/` is not read at all.

    Step 4 writes the map explicitly, so step 6 does not re-derive it: deriving source names from
    `raw/<source>.rules` paths invented an unwritten contract about multi-file feeds (ET Open is
    a tarball of many `.rules` files), and `raw/` is not covered by `snapshot_id`, so it could be
    edited without detection. A `raw/` tree that contradicts the index must change nothing.
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})
    decoy = snapshot / "raw" / "somebody-elses-feed.rules"
    decoy.parent.mkdir(parents=True, exist_ok=True)
    decoy.write_text(RULES[HTTP_SID] + "\n" + RULES[IDENTIFY_SID] + "\n")

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert [(d.source, d.sid) for d in detections] == [("et/open", HTTP_SID)] * 2
    assert info.rules_loaded == 1, "only the admitted rule may load, never stray raw text"


@pytest.mark.requires_tools
def test_two_runs_produce_the_same_alert_set(tmp_path):
    """Goal 2 as a whole-pass check: same input, same detections, same counts.

    Honest about its limits — with two rules over 14 packets, Suricata would very likely be
    deterministic without `--runmode single` too, so deleting that flag would not fail here.
    The flag itself is pinned by `test_argv_loads_only_the_snapshot_ruleset`; this test guards
    everything downstream of it, including the parse and the ordering of the returned list.
    """
    snapshot = make_snapshot(
        tmp_path,
        {"et/open": [HTTP_SID], "oisf/trafficid": [IDENTIFY_SID]},
        {"oisf/trafficid": "identify"},
    )

    first, first_info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "one")
    second, second_info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "two")

    assert first == second
    assert (first_info.alerts_total, first_info.identify_alerts_suppressed) == (
        second_info.alerts_total,
        second_info.identify_alerts_suppressed,
    )


# --- loss conditions (spec §11) ------------------------------------------------------------


def test_missing_binary_records_a_tool_failure(tmp_path, monkeypatch):
    """A Suricata that cannot be run at all is reported, not raised.

    Deliberately *not* marked ``requires_tools``: it works by emptying ``PATH``, so counting
    it toward "a tool test ran" would let a toolchain-less CI run look green (conftest.py).
    """
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert detections == []
    assert len(info.tool_failures) == 1
    failure = info.tool_failures[0]
    assert failure.tool == "suricata"
    assert failure.exit_code is None
    assert "suricata" in failure.message
    assert info.snapshot_id == snapshot.name, "provenance survives a tool failure"


@pytest.mark.requires_tools
def test_nonzero_exit_records_a_tool_failure(tmp_path):
    """Suricata exiting non-zero yields a `ToolFailure` and no detections."""
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})

    detections, info = suricata.run_suricata(tmp_path / "absent.pcap", snapshot, tmp_path / "out")

    assert detections == []
    assert len(info.tool_failures) == 1
    failure = info.tool_failures[0]
    assert failure.tool == "suricata"
    assert failure.exit_code == 1
    assert "-S" in failure.argv, "the failing argv is recorded so the failure is reproducible"


@pytest.mark.requires_tools
def test_a_ruleset_the_engine_rejects_is_a_tool_failure(tmp_path):
    """Zero rules loaded is a failure, not an empty result.

    Suricata rejects a rule with an unknown keyword, then loads nothing, warns, and **exits
    0** (verified on 8.0.6). Nothing else in the run distinguishes that from a capture with
    no malicious traffic in it, which is exactly the shape spec §2.5 forbids.
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [UNLOADABLE_SID]})

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert detections == []
    assert len(info.tool_failures) == 1
    assert info.tool_failures[0].exit_code == 0, "the point is that Suricata called this success"
    assert "loaded none" in info.tool_failures[0].message
    assert "1 failed" in info.tool_failures[0].message, "the engine's own count is reported"


@pytest.mark.requires_tools
def test_a_partial_rule_load_is_reported_and_not_fatal(tmp_path):
    """Some rules loaded, one rejected: the loss that actually happens with real feeds.

    A snapshot of two rules where one uses an unknown keyword loads *one*, alerts normally, and
    exits 0 — so the run looks complete while the labels the rejected rule would have produced
    are simply absent. 26 pawpatrules rules were measured failing to load against Suricata 8, so
    this is the ordinary case, not the exotic one.

    **This stage no longer fails the run over it** (Craig, 2026-08-12 — issue #46). It used to,
    on the conservative reading of "record it, warn above zero, fail above a threshold". At full
    scale the shortfall is *zero* — 85,431 admitted, 85,431 loaded — because the rules this
    engine cannot compile are excluded at admission, so no nonzero value was ever observed and
    any threshold would have been invented. An unconditional failure is a threshold of zero
    chosen by default, which is the same invention with the number hidden.

    So this stage reports and `cli.py` asks the operator. What must survive here is the
    *evidence*: the engine's own counts, and a warning carrying them into the run block. The
    detections are kept rather than discarded — they are real alerts from rules that really
    loaded, and the operator decides whether a ruleset this incomplete is worth labelling from.
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID, UNLOADABLE_SID]})

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert info.tool_failures == (), "a shortfall is a reported loss, not a tool failure (#46)"
    assert info.rules_loaded == 1
    assert info.rules_failed == 1
    assert detections, "the rules that did load still examined the capture"

    # The count and the share, in one sentence, so the prompt and the run block cannot round
    # the same fact two ways.
    (warning,) = info.warnings
    assert "1 of 2 rules" in warning
    assert "50.00%" in warning


@pytest.mark.requires_tools
def test_the_engine_really_does_reject_a_rule_that_negates_home_net(tmp_path):
    """The measurement `rules/admit.py` rests on, taken against the real engine.

    `negates_home_net` excludes rules written `... -> ![...,$HOME_NET] ...` at admission, and its
    whole justification is that flabel's `HOME_NET: any` makes them unloadable. If that were ever
    untrue — a Suricata release resolving the negation differently, a change to flabel's config —
    the exclusion would be deleting rules for no reason, and only a real invocation can say.

    Asserted through the engine's own load counts rather than by grepping `suricata.log`,
    because the count is what the rest of the pipeline reads. Since #46 a shortfall no longer
    fails the run, so the cost of *not* excluding these rules at admission is no longer "every
    label in the run" — it is a prompt on every run against a real snapshot, which an operator
    would learn to answer without reading. That is a weaker consequence and the same conclusion:
    a rule the engine can never load does not belong in a snapshot.
    """
    snapshot = make_snapshot(tmp_path, {"pawpatrules": [HTTP_SID, HOME_NET_NEGATED_SID]})

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert info.rules_loaded == 1, "the engine refused the rule that negates a HOME_NET of any"
    assert info.rules_failed == 1
    assert info.warnings, "a rule that never loaded is never silent (spec §2.5)"
    assert detections, "the loadable rule still fired"
    # And the other half: admission would never have handed this rule over in the first place.
    assert negates_home_net(RULES[HOME_NET_NEGATED_SID])
    assert not negates_home_net(RULES[HTTP_SID])


def test_a_run_whose_rule_count_cannot_be_determined_fails(tmp_path):
    """ "We could not tell" is a third state, and it is not the same as zero.

    Both channels the count comes from — the eve stats record and `suricata.log` — are decided by
    configuration. If neither reports, the alert set cannot be attested against the snapshot at
    all, so it is not evidence. Kept distinct from the zero case, which has a different message
    and a different cause.
    """
    failure = suricata._check_ruleset_loaded(None, expected=3, argv=["suricata"], exit_code=0)

    assert failure is not None
    assert "no rule-load count" in failure.message

    agreed = suricata._check_ruleset_loaded((3, 0, 0), expected=3, argv=["suricata"], exit_code=0)
    assert agreed is None, "a ruleset that loaded in full is not a failure"


def test_a_clean_load_says_nothing():
    """Spec §9's habit: silence means nothing was lost, so a warning always means something was."""
    assert suricata._load_warnings(3, 0, 0, 3) == ()


def test_a_shortfall_reports_the_count_and_the_share():
    """ "N rules failed" alone does not tell an operator whether to care (#46).

    26 of 85,431 is a curiosity; 26 of 40 is a broken snapshot. The percentage is what makes the
    count answerable, and it is composed here — not at the prompt — so the sentence the operator
    reads is the sentence the run block records rather than two roundings of one fact.
    """
    (warning,) = suricata._load_warnings(85_405, 26, 0, 85_431)
    assert "26 of 85431 rules" in warning
    assert "0.03%" in warning
    assert "26 failed" in warning

    (small,) = suricata._load_warnings(14, 26, 0, 40)
    assert "65.00%" in small, "the same 26 rules, and a completely different decision"


def test_rejected_rules_alongside_a_reconciling_load_are_still_a_warning():
    """The engine says it loaded everything *and* that it rejected rules. Both cannot be whole.

    A distinct shape from a shortfall: nothing is provably missing, because the count that
    reconciles accounts for every admitted rule — but the two numbers contradict each other, so
    the run's rule coverage is unverified rather than verified-incomplete. Not fatal, not silent
    (spec §2.5).

    Tested directly because no engine produces the contradiction on demand, and the alternative
    to testing it here is not testing it.
    """
    (warning,) = suricata._load_warnings(3, 2, 1, 3)
    assert "2 rules failed" in warning and "1 rules skipped" in warning
    assert "unverified" in warning

    assert suricata._load_warnings(3, 0, 4, 3) != (), "skipped alone is still a contradiction"


def test_a_failed_run_still_reports_the_config_it_attempted(tmp_path, monkeypatch):
    """A failure is only diagnosable against the configuration that produced it.

    `HOME_NET` and the eve output selection decide what *could* have fired, so a run that dies
    without saying which config was in force leaves the reader unable to tell a tool fault from
    a configuration that made the rules inert. Injected through the environment — an empty PATH,
    so the real binary is genuinely absent (spec §11's fault injection).
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert detections == []
    assert len(info.tool_failures) == 1
    assert info.config_sha256 == suricata.config_sha256()
    assert info.snapshot_id == snapshot.name, "and which ruleset it attempted"


# --- eve.json parsing, unit-level -----------------------------------------------------------
#
# These reach for module-private helpers deliberately. Each covers a branch that only a
# malformed or hostile eve.json reaches, and no combination of real Suricata runs can produce
# one on demand — the alternative to testing them directly is not testing them.


def eve_file(path: Path, records: Sequence[object]) -> Path:
    """Write `records` as an eve.json-shaped stream of one JSON object per line."""
    path.write_text("".join(json.dumps(record) + "\n" for record in records))
    return path


def test_a_timestamp_without_an_offset_is_rejected(tmp_path):
    """A naive timestamp would be read as *local* time and shift silently by hours.

    `datetime.timestamp()` does that without erroring, so the same capture would yield
    different `ts` values on a UTC machine and a PDT one — the reproducibility break that
    `test_alert_timestamps_do_not_depend_on_the_local_timezone` proves does not happen when the
    offset is present.
    """
    with pytest.raises(ToolError, match="no UTC offset"):
        suricata._epoch("2023-11-14T14:13:20.050000", tmp_path / "eve.json", 1)


def test_an_unparseable_timestamp_is_rejected(tmp_path):
    with pytest.raises(ToolError, match="unparseable timestamp"):
        suricata._epoch("last tuesday", tmp_path / "eve.json", 1)


def test_a_malformed_eve_line_is_never_skipped(tmp_path):
    """A dropped record is a missing label, so an unreadable one fails the run."""
    path = tmp_path / "eve.json"
    path.write_text('{"event_type":"flow"}\n{"event_type":"alert"\n')

    with pytest.raises(ToolError, match="not valid JSON"):
        suricata._read_eve(path, {}, {}, {})


def test_undecodable_bytes_become_a_flabel_error(tmp_path):
    """eve.json carries capture-derived strings, so invalid UTF-8 is a thing it can contain.

    It must surface as a `FlabelError` that `cli.py` can map to an exit code, not as a bare
    `UnicodeDecodeError` traceback.
    """
    path = tmp_path / "eve.json"
    path.write_bytes(b'{"event_type":"http","hostname":"\xff\xfe"}\n')

    with pytest.raises(ToolError, match="not valid UTF-8"):
        suricata._read_eve(path, {}, {}, {})


def test_an_alert_without_a_signature_is_rejected(tmp_path):
    """`alert.signature` becomes `SourceEntry.threat`, which every label must carry."""
    path = eve_file(
        tmp_path / "eve.json",
        [{"event_type": "alert", "alert": {"signature_id": HTTP_SID, "rev": 1}}],
    )

    with pytest.raises(ToolError, match="alert.signature"):
        suricata._read_eve(path, {HTTP_SID: "et/open"}, {}, {})


def test_an_alert_on_an_unattributable_sid_is_rejected(tmp_path):
    """Unreachable with `-S`, and still checked: the alternative is an invented origin."""
    path = eve_file(
        tmp_path / "eve.json",
        [{"event_type": "alert", "alert": {"signature_id": 4242, "signature": "x", "rev": 1}}],
    )

    with pytest.raises(SnapshotError, match="4242"):
        suricata._read_eve(path, {HTTP_SID: "et/open"}, {}, {})


def test_a_decoy_sid_in_rule_content_is_not_read_as_the_rule_sid():
    """A rule whose `content:` contains ``sid:1;`` must still be attributed to its own SID.

    Otherwise every label from that rule names a different rule — and the SID it names may
    belong to a source with a different `source_class`.
    """
    rule = (
        'alert tcp any any -> any any (msg:"decoy"; content:"sid:1;"; '
        'pcre:"/sid:2;/"; classtype:trojan-activity; sid:9000123; rev:4;)'
    )

    assert suricata.rule_classtypes(rule, {9000123: "et/open"}, Path("/snap")) == {
        9000123: "trojan-activity"
    }


def test_disabled_and_blank_rule_lines_are_not_rules():
    """ET Open ships 19,479 `#alert` rules; none can fire, so none may be attributed.

    A snapshot of nothing but comments is also refused: Suricata would load it cleanly and label
    nothing, which is indistinguishable from a capture with nothing in it.
    """
    text = "\n".join(["", "   ", "# a comment", f"#{RULES[HTTP_SID]}"])

    with pytest.raises(SnapshotError, match="no rules"):
        suricata.rule_classtypes(text, {}, Path("/snap"))


def test_all_three_rule_counts_are_read_from_the_log(tmp_path):
    """The fallback path, which no real run exercises while eve stats are on by default.

    All three counts come off one line. Reading only the loaded number — as this did at first —
    leaves the interesting one, `rules failed`, on the floor.
    """
    log = tmp_path / "suricata.log"
    log.write_text(
        "Info: detect: 3 rule files processed. 51752 rules successfully loaded, "
        "26 rules failed, 3 rules skipped\n"
    )

    assert suricata._rules_loaded_from_log(log) == (51752, 26, 3)
    assert suricata._rules_loaded_from_log(tmp_path / "absent.log") is None


def test_a_stats_record_reporting_zero_loaded_is_not_mistaken_for_silence():
    """Zero is an answer — every rule failed — and must not read as "stats said nothing"."""
    record = {"stats": {"detect": {"engines": [{"id": 0, "rules_loaded": 0, "rules_failed": 4}]}}}

    assert suricata._rules_loaded_from_stats(record) == (0, 4, 0)
    assert suricata._rules_loaded_from_stats({"stats": {"detect": {}}}) is None
    assert suricata._rules_loaded_from_stats({"stats": "not a dict"}) is None


def test_a_rule_with_no_classtype_carries_none():
    """10,949 of the 85,545 rules in the measured snapshot declare no classtype at all."""
    rule = 'alert tcp any any -> any any (msg:"bare"; content:"x"; sid:9000200; rev:1;)'

    assert suricata.rule_classtypes(rule, {9000200: "et/open"}, Path("/snap")) == {}


@pytest.mark.requires_tools
def test_classtype_does_not_depend_on_the_classification_config(tmp_path):
    """A label's classtype survives a classtype flabel's own config does not define.

    This is the payoff of reading it from the rule text. `alert.category` is a *description*
    looked up in `classification.config`; for a classtype absent from that file Suricata warns
    once and reports an **empty** category (measured on 8.0.6), so a label would silently lose its
    classtype. flabel's config lists only the 31 classtypes the nine feeds use today, so this is
    what happens the day a feed adds the 32nd.
    """
    invented = RULES[HTTP_SID].replace("classtype:trojan-activity;", "classtype:flabel-invented;")
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})
    (snapshot / "rules.rules").write_text(invented + "\n")
    snapshot = reseal(snapshot)

    detections, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert info.tool_failures == (), "an unknown classtype only warns; it must not fail the run"
    assert [detection.classtype for detection in detections] == ["flabel-invented"] * 2
    eve = (tmp_path / "out" / "eve.json").read_text().replace(" ", "")
    assert '"category":""' in eve, (
        "eve.json reported an empty category, which is why classtype is not taken from it"
    )


def test_the_rule_path_is_the_directory_holding_the_dataset_files(tmp_path):
    """`dataset: ... load <file>` resolves against the rule path, so it must be that directory.

    Measured against the live feeds: `default-rule-path=<snapshot>` leaves 26 rules failing to
    load, `<snapshot>/data/pawpatrules` loads all 85,545 with none failing. Derived from the rules
    rather than hardcoded to the one feed that ships datasets today.
    """
    snapshot = make_snapshot(
        tmp_path,
        {"pawpatrules": [HTTP_SID]},
        data={"pawpatrules": {"pawpatrules_tor.lst": b"1.2.3.4\n"}},
    )
    rules = (
        'alert ip any any -> any any (msg:"x"; dataset:isset,tor,type string,load '
        "pawpatrules_tor.lst; sid:9000300;)"
    )

    assert suricata.rule_path(snapshot, rules) == snapshot / "data" / "pawpatrules"
    # No datasets at all: the snapshot root is a harmless value, and the argv still records one.
    assert suricata.rule_path(snapshot, RULES[HTTP_SID]) == snapshot


def test_dataset_files_from_two_sources_cannot_both_resolve(tmp_path):
    """`default-rule-path` takes exactly one path, and that is a real ceiling.

    Only `pawpatrules` ships datasets today. If a second dataset-bearing feed is ever admitted,
    one of the two sets cannot resolve and those rules fail to load — so this refuses rather than
    picking a winner and losing coverage quietly. The per-source layout is not the thing to fix:
    `et/open` and `stamus/lateral` both ship a file called `LICENSE`, so a flat directory would
    have them overwrite each other. Merging the data directories belongs to step 4.
    """
    snapshot = make_snapshot(
        tmp_path,
        {"pawpatrules": [HTTP_SID], "et/open": [JA4_SID]},
        data={
            "pawpatrules": {"pawpatrules_tor.lst": b"1.2.3.4\n"},
            "et/open": {"compromised-ips.txt": b"5.6.7.8\n"},
        },
    )
    rules = (
        'alert ip any any -> any any (msg:"a"; dataset:isset,tor,type string,load '
        "pawpatrules_tor.lst; sid:9000301;)\n"
        'alert ip any any -> any any (msg:"b"; dataset:isset,bad,type string,load '
        "compromised-ips.txt; sid:9000302;)"
    )

    with pytest.raises(SnapshotError, match="more than one directory"):
        suricata.rule_path(snapshot, rules)


def test_a_dataset_file_the_snapshot_lacks_is_a_hard_failure(tmp_path):
    """A rule whose data file is absent could never match, so the snapshot is incomplete."""
    snapshot = make_snapshot(tmp_path, {"pawpatrules": [HTTP_SID]})
    rules = (
        'alert ip any any -> any any (msg:"x"; dataset:isset,tor,type string,load '
        "absent.lst; sid:9000303;)"
    )

    with pytest.raises(SnapshotError, match="absent.lst"):
        suricata.rule_path(snapshot, rules)


def test_metadata_absent_or_malformed_is_empty_rather_than_an_error():
    """A rule with no `metadata:` is ordinary; only a *label* needs every field."""
    assert suricata._metadata(None) == ()
    assert suricata._metadata("confidence High") == ()
    assert suricata._metadata({"confidence": ["High"], "tag": "single"}) == (
        "confidence High",
        "tag single",
    )


# --- the snapshot, as this module reads it --------------------------------------------------
#
# Verifying a snapshot — the content hash, the manifest's shape and types, the sid index's schema
# — belongs to `rules/snapshot.py` and is tested in `test_snapshot.py`. What is tested here is
# only what this module adds: that a loader failure reaches the caller rather than being
# swallowed, and the cross-check between the rules that can fire and the attribution for them.


def test_a_snapshot_failure_reaches_the_caller(tmp_path):
    """A snapshot problem is a hard failure, never a run with no labels.

    The loader raises; this asserts `run_suricata` does not catch it and return an empty result,
    which would look exactly like a capture with nothing in it.
    """
    with pytest.raises(SnapshotError):
        suricata.run_suricata(BENIGN, tmp_path / "rules" / "0123456789abcdef", tmp_path / "out")


def test_an_admitted_sid_no_source_claims_is_a_hard_failure(tmp_path):
    """A rule that could fire but could not be attributed fails the run up front.

    `rules.rules` decides what can fire and `sid_index.json` decides what a firing rule can be
    attributed to, so a sid in the first and not the second is a label with no traceable origin
    (spec §13). Step 4 will not write such a snapshot; this is the reader refusing to trust that.
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID, JA4_SID]})
    snapshot = set_sid_index(snapshot, {"et/open": [HTTP_SID]})

    with pytest.raises(SnapshotError, match=str(JA4_SID)):
        suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")


def test_an_attributed_sid_that_is_not_in_the_ruleset_is_a_hard_failure(tmp_path):
    """The other direction: the index describes a rule the ruleset does not contain.

    Then the two files describe different rulesets and neither can be trusted to say what ran.
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})
    snapshot = set_sid_index(snapshot, {"et/open": [HTTP_SID, 9999998]})

    with pytest.raises(SnapshotError, match="9999998"):
        suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")


def test_an_existing_eve_log_is_never_appended_to(tmp_path):
    """Suricata appends to ``eve.json``; a stale one would inject a previous run's alerts.

    Spec §13: never overwrite or modify a previous run directory.
    """
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})
    outdir = tmp_path / "out"
    outdir.mkdir()
    (outdir / "eve.json").write_text("")

    with pytest.raises(ToolError, match="eve.json"):
        suricata.run_suricata(BENIGN, snapshot, outdir)


# --- a failed pass must not publish counts it never took (issue #86, PLAN 13e) --------------


def test_a_failed_pass_reports_null_counts_not_zeros(tmp_path, monkeypatch):
    """The producer side of #86, which nothing tested — reverting the fix left CI green.

    `_failed()` used to return `rules_loaded=0, rules_failed=0, rules_skipped=0`, so `run.json`
    published a measurement of zero for a run where the engine may have loaded all 85,000 rules,
    and `loss_conditions.rules_failed_or_skipped` then read `false` off the back of it. Spec §10:
    "every field whose stage did not run is `null` — not zero, not an empty list."

    The two tests added with the fix assert that `build_run_block` *renders* `None` as `null` —
    they test the reader. This asserts the producer, which is where the zeros came from. Verified
    by sabotage: restoring the zeros makes this fail and nothing else.

    Not marked `requires_tools` for the reason the sibling above gives: it works by emptying
    `PATH`, so counting it toward "a tool test ran" would let a toolchain-less CI look green.
    """
    monkeypatch.setenv("PATH", str(tmp_path / "empty"))
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})

    _, info = suricata.run_suricata(BENIGN, snapshot, tmp_path / "out")

    assert info.tool_failures, "precondition: this is the failure path"
    assert info.rules_loaded is None, "a load count that was never taken is null, not zero"
    assert info.rules_failed is None
    assert info.rules_skipped is None
    assert info.snapshot_id == snapshot.name, "and provenance still survives"


def test_a_count_measured_before_the_failure_is_handed_on_not_discarded(tmp_path):
    """The second half of #86, tested on `_failed` directly — and here is why.

    `_read_eve` runs *before* `_check_ruleset_loaded`, so a pass that measured alerts and then
    failed the load check already holds those numbers. It used to discard them and report `0`.

    **Measured while writing this: the end-to-end path is much narrower than the fix implied.**
    A load-check failure means either `rules_loaded == 0` — in which case nothing could have
    fired, so the suppression count is genuinely zero — or `counts is None`, meaning neither the
    eve stats nor `suricata.log` yielded a load count while rules did load and did fire. Only the
    second reaches this code with a non-zero count, and it needs Suricata to stop reporting its
    load count in both places at once, which no committed fixture can arrange.

    So the threading is right and worth keeping — it costs nothing and it is correct if that
    branch is ever taken — but it is guarded here rather than end to end, and the reachability is
    recorded instead of implied. My commit message called this the worse of #86's two wrongs; on
    the evidence the null-counts half is the one that was actually reachable.
    """
    failure = suricata._failure(("suricata", "-r", "x.pcap"), 0, "no load count anywhere")
    snapshot = make_snapshot(tmp_path, {"et/open": [HTTP_SID]})
    _, manifest, _ = load_snapshot(snapshot.parent, snapshot.name)

    info = suricata._failed(
        manifest, failure, version="8.0.6", alerts_total=57, identify_alerts_suppressed=40
    )

    assert info.identify_alerts_suppressed == 40, "a measured count must survive a later failure"
    assert info.alerts_total == 57
    assert info.rules_loaded is None, "and what was never established stays null"
    assert info.rules_failed is None and info.rules_skipped is None
