"""Zeek invocation and parsing (spec §8, PLAN step 5).

Zeek is invoked **for real** here — no mocks, no golden files. The whole point of these tests
is to verify what Zeek actually does with a capture, and a mock would encode our assumptions
about that instead of checking them (`docs/spec.md` §2). Those tests carry
`@pytest.mark.requires_tools` and skip cleanly when the toolchain is absent.

The two tests that do *not* invoke Zeek are the fault injections from spec §11: a missing
binary and a killed process. Both point `FLABEL_ZEEK` at something that is not Zeek, which is
process-boundary fault injection rather than a substitute for Zeek's analysis — there is no
way to make the real binary vanish or be OOM-killed on demand, and "the run reports what was
lost" is exactly the behaviour that must not be taken on trust.

No test here makes a network call.

**The JA4 assertion is verified in CI only.** `zeek/foxio/ja4` is installed in the toolchain
container but not on a Homebrew laptop, where `zkg` ships without its Python dependencies
(`docs/dev-setup.md`). The test skips with that reason when the package cannot be loaded, and
fails rather than skips under `--strict-toolchain`, which is how CI runs.
"""

from __future__ import annotations

import importlib.util
import struct
import subprocess
from pathlib import Path

import pytest

from flabel import zeek
from flabel.errors import ToolError
from flabel.models import Flow, ZeekRunInfo

FIXTURES = Path(__file__).parent / "fixtures"
BENIGN = FIXTURES / "benign.pcap"

#: The two flows `make_canary.py` synthesizes, as (src_ip, src_port, dst_ip, dst_port, proto).
BENIGN_TUPLES = {
    ("10.0.0.5", 49152, "10.0.0.200", 80, "tcp"),
    ("10.0.0.6", 49153, "10.0.0.201", 443, "tcp"),
}

#: Fixed timestamps from the canary generator, so a wrong `ts` cannot pass unnoticed.
BENIGN_FIRST_TS = {1700000000.0, 1700000010.0}

TLS_SERVER_NAME = "example.test"
TLS_TUPLE = ("10.0.0.7", 49200, "10.0.0.202", 443)


# --- fixtures -----------------------------------------------------------------------------


def _canary_module():
    """`tests/fixtures/make_canary.py`, loaded by path.

    Its packet builders are reused for the TLS capture below rather than reimplemented: the
    checksum and header code is the part that is easy to get subtly wrong, and a fixture Zeek
    silently discards for a bad checksum would make this suite lie. `tests/fixtures` is not a
    package, hence the loader rather than an import.
    """
    path = FIXTURES / "make_canary.py"
    spec = importlib.util.spec_from_file_location("flabel_test_make_canary", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _tsv_fields(log: Path) -> list[str]:
    """The `#fields` names of a Zeek TSV log, for a failure message that diagnoses itself."""
    if not log.exists():
        return []
    for line in log.read_text().splitlines():
        if line.startswith("#fields"):
            return line.split("\t")[1:]
    return []


def _tls_record(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + b"\x03\x03" + struct.pack("!H", len(body)) + body


def _tls_handshake(kind: int, body: bytes) -> bytes:
    return bytes([kind]) + len(body).to_bytes(3, "big") + body


def _client_hello(host: str = TLS_SERVER_NAME) -> bytes:
    """A TLS 1.3 ClientHello with SNI, cipher suites, groups and signature algorithms.

    Those four are what a JA4 fingerprint is computed from, so a ClientHello stripped to the
    bare minimum would produce a JA4 that says nothing.
    """
    name = host.encode()
    server_name = b"\x00" + struct.pack("!H", len(name)) + name
    sni = b"\x00\x00" + struct.pack("!H", len(server_name) + 2)
    sni += struct.pack("!H", len(server_name)) + server_name
    groups = b"\x00\x0a" + struct.pack("!HH", 6, 4) + b"\x00\x1d\x00\x17"
    sigalgs = b"\x00\x0d" + struct.pack("!HH", 6, 4) + b"\x04\x03\x08\x04"
    versions = b"\x00\x2b" + struct.pack("!H", 3) + b"\x02\x03\x04"
    extensions = sni + groups + sigalgs + versions
    ciphers = b"\x13\x01\x13\x02\xc0\x2f\xc0\x30"
    body = (
        b"\x03\x03"
        + bytes(range(32))
        + b"\x00"
        + struct.pack("!H", len(ciphers))
        + ciphers
        + b"\x01\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return _tls_record(0x16, _tls_handshake(0x01, body))


def _server_hello() -> bytes:
    """A matching ServerHello, so Zeek reports a cipher and (with the package) a JA4S."""
    extensions = b"\x00\x2b" + struct.pack("!H", 2) + b"\x03\x04"
    extensions += b"\x00\x33" + struct.pack("!H", 4) + b"\x00\x1d\x00\x00"
    body = (
        b"\x03\x03"
        + bytes(range(32, 64))
        + b"\x00"
        + b"\x13\x01"
        + b"\x00"
        + struct.pack("!H", len(extensions))
        + extensions
    )
    return _tls_record(0x16, _tls_handshake(0x02, body))


@pytest.fixture(scope="session")
def tls_capture(tmp_path_factory: pytest.TempPathFactory) -> Path:
    """A synthesized TLS handshake on port 443, built at test time rather than committed.

    Synthesized for the same reason the benign canary is (`tests/fixtures/README.md`): the
    expected `server_name` and the presence of a JA4 are then known-correct rather than
    empirical. Built into a temporary directory rather than checked in, because the repository
    is public and its `tests/fixtures/**` exception is deliberately narrow — nothing here needs
    to be a committed artifact.
    """
    canary = _canary_module()
    client, sport, server, dport = TLS_TUPLE
    hello, response = _client_hello(), _server_hello()
    client_seq, server_seq = 2000, 9000
    steps = [
        (client, server, sport, dport, client_seq, 0, canary.SYN, b""),
        (server, client, dport, sport, server_seq, client_seq + 1, canary.SYN | canary.ACK, b""),
        (client, server, sport, dport, client_seq + 1, server_seq + 1, canary.ACK, b""),
        (
            client,
            server,
            sport,
            dport,
            client_seq + 1,
            server_seq + 1,
            canary.PSH | canary.ACK,
            hello,
        ),
        (
            server,
            client,
            dport,
            sport,
            server_seq + 1,
            client_seq + 1 + len(hello),
            canary.PSH | canary.ACK,
            response,
        ),
        (
            client,
            server,
            sport,
            dport,
            client_seq + 1 + len(hello),
            server_seq + 1 + len(response),
            canary.FIN | canary.ACK,
            b"",
        ),
        (
            server,
            client,
            dport,
            sport,
            server_seq + 1 + len(response),
            client_seq + 2 + len(hello),
            canary.FIN | canary.ACK,
            b"",
        ),
    ]

    packets = []
    for index, (src, dst, source_port, dest_port, seq, ack, flags, payload) in enumerate(steps):
        segment = canary.tcp(source_port, dest_port, seq, ack, flags, src, dst, payload)
        frame = canary.ethernet(canary.ipv4(src, dst, segment, ident=index))
        packets.append((1700000100.0 + index * 0.01, frame))

    path = tmp_path_factory.mktemp("tls") / "tls.pcap"
    canary.write_pcap(str(path), packets)
    return path


@pytest.fixture
def fake_zeek(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """Point `FLABEL_ZEEK` at a stub that answers the probes and then does something awful.

    Spec §11's fault injection for `tool_failures[]`. The stub reports a plausible version and
    accepts `--parse-only` so that the *analysis* invocation is the one that fails — which is
    the path that has to record a failure.
    """

    def install(analysis_body: str) -> Path:
        script = tmp_path / "fake-zeek"
        script.write_text(
            "#!/bin/sh\n"
            'case "$1" in\n'
            '  --version) echo "zeek version 9.9.9"; exit 0 ;;\n'
            "  --parse-only) exit 0 ;;\n"
            "esac\n"
            f"{analysis_body}\n"
        )
        script.chmod(0o755)
        monkeypatch.setenv(zeek.ZEEK_ENV, str(script))
        return script

    return install


# --- the invocation contract, without a toolchain -------------------------------------------


def test_argv_carries_the_mandatory_flags():
    """`-D` and `-C` are in the argv, checkable without running anything.

    The behavioural proof is `test_two_runs_produce_identical_uids`; this is the same
    invariant stated where a reviewer of a one-line argv edit will see it fail. Spec §13 lists
    invoking Zeek without `-D` as a never-do.
    """
    argv = zeek.zeek_argv(Path("/captures/x.pcap"), load_ja4=False, binary="zeek")

    assert argv[0] == "zeek"
    assert "-D" in argv, "Zeek without -D produces different uids every run (spec §2.3)"
    assert "-C" in argv, "checksum offload would otherwise discard the traffic being labelled"
    assert argv[argv.index("-r") + 1] == "/captures/x.pcap"
    assert argv[-1].endswith("json-logs.zeek")


def test_argv_loads_the_ja4_package_only_when_it_is_available():
    """JA4 is loaded explicitly, and its absence must not become a fatal `@load`."""
    with_ja4 = zeek.zeek_argv(Path("x.pcap"), load_ja4=True, binary="zeek")
    without = zeek.zeek_argv(Path("x.pcap"), load_ja4=False, binary="zeek")

    assert "ja4" in with_ja4
    assert "ja4" not in without
    # The script must still be last: Zeek loads script arguments in order, and json-logs.zeek
    # adds a filter to SSL::LOG, whose ja4 fields only exist once the package is loaded.
    assert with_ja4[-1].endswith("json-logs.zeek")


def test_the_json_filter_script_ships_inside_the_package():
    """Package data, resolvable from an editable install — not a repo-root file.

    Root-level `data/` reaches a wheel only via a hatch `force-include`, which an editable
    install (`uv sync`) has not got, so a root-level script would resolve in CI's wheel and
    fail here. PLAN said `data/json-logs.zeek`; step 2 corrected the location.
    """
    path = zeek.script_path()

    assert path.is_file(), f"{path} is missing — package data must live under src/flabel/data/"
    assert path.parent.name == "data"
    script = path.read_text()
    assert script.count("Log::add_filter") == 2, "one JSON filter each for conn and ssl"
    assert "Conn::LOG" in script and "SSL::LOG" in script
    assert '["use_json"] = "T"' in script
    # Epoch timestamps: an ISO-8601 `ts` would need a timezone-aware parse to become a float,
    # and `Flow.ts_first` is a float.
    assert "JSON::TS_EPOCH" in script


def test_executable_comes_from_the_environment(monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv(zeek.ZEEK_ENV, raising=False)
    assert zeek.executable() == "zeek"

    monkeypatch.setenv(zeek.ZEEK_ENV, "/opt/other/zeek")
    assert zeek.executable() == "/opt/other/zeek"


def test_a_missing_binary_is_recorded_as_a_tool_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    """Spec §11: "point at a non-existent binary" → `tool_failures[]`, not a stray OSError."""
    monkeypatch.setenv(zeek.ZEEK_ENV, str(tmp_path / "no-such-zeek"))

    with pytest.raises(ToolError) as caught:
        zeek.run_zeek(BENIGN, tmp_path / "zeek")

    info = caught.value.run_info
    assert isinstance(info, ZeekRunInfo)
    assert len(info.tool_failures) == 1
    failure = info.tool_failures[0]
    assert failure.tool == "zeek"
    assert failure.exit_code is None, "a binary that never ran has no exit code"
    assert "no-such-zeek" in failure.message
    assert info.version == zeek.UNKNOWN_VERSION


def test_a_killed_process_is_recorded_as_a_tool_failure(tmp_path: Path, fake_zeek):
    """An OOM kill arrives as SIGKILL, and must be reported as a loss, not a traceback."""
    fake_zeek("kill -9 $$")

    with pytest.raises(ToolError) as caught:
        zeek.run_zeek(BENIGN, tmp_path / "zeek")

    failure = caught.value.run_info.tool_failures[0]
    assert failure.exit_code == -9
    assert "signal 9" in failure.message
    assert "OOM" in failure.message, "the likely cause belongs in the message a human reads"
    assert caught.value.run_info.version == "9.9.9"


def test_a_silent_tool_that_writes_no_logs_is_a_failure(tmp_path: Path, fake_zeek):
    """Exit 0 with no `conn_json.log` must fail, not report zero flows.

    Zero flows and "the JSON filter never ran" would otherwise be indistinguishable, which is
    precisely what spec §2.5 forbids.
    """
    fake_zeek("exit 0")

    with pytest.raises(ToolError) as caught:
        zeek.run_zeek(BENIGN, tmp_path / "zeek")

    failure = caught.value.run_info.tool_failures[0]
    assert failure.exit_code == 0
    assert "conn_json.log" in failure.message


def test_malformed_json_output_is_a_failure_not_an_empty_flow_table(tmp_path: Path, fake_zeek):
    """A truncated or non-JSON `conn_json.log` must not silently yield no flows."""
    fake_zeek('printf "not json\\n" > conn_json.log\nexit 0')

    with pytest.raises(ToolError) as caught:
        zeek.run_zeek(BENIGN, tmp_path / "zeek")

    assert "not JSON" in caught.value.run_info.tool_failures[0].message


def test_a_conn_log_missing_a_field_is_a_failure(tmp_path: Path, fake_zeek):
    """A JSON object that is not a conn record must be rejected, not partly believed."""
    fake_zeek('printf \'{"ts":1.0,"uid":"C1"}\\n\' > conn_json.log\nexit 0')

    with pytest.raises(ToolError) as caught:
        zeek.run_zeek(BENIGN, tmp_path / "zeek")

    message = caught.value.run_info.tool_failures[0].message
    assert "id.orig_h" in message and "proto" in message


def test_reproducible_logs_excludes_the_wall_clock_log():
    """`packet_filter.log` can never match across runs, so it is never compared."""
    info = ZeekRunInfo(
        version="8.0.4",
        flags=("-C", "-D"),
        log_dir=Path("/run/zeek"),
        retained_logs=("conn.log", "http.log", "packet_filter.log"),
    )

    assert zeek.reproducible_logs(info) == ("conn.log", "http.log")
    assert "packet_filter.log" in info.retained_logs, "it is retained, just not compared"


# --- the real toolchain ---------------------------------------------------------------------


@pytest.mark.requires_tools
def test_benign_capture_yields_exactly_two_flows(tmp_path: Path):
    """The canary's two synthesized TCP conversations, and nothing else."""
    flows, info = zeek.run_zeek(BENIGN, tmp_path / "zeek")

    assert len(flows) == 2, f"expected two flows, got {sorted(flows)}"
    assert all(isinstance(flow, Flow) for flow in flows.values())
    assert {
        (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port, flow.proto)
        for flow in flows.values()
    } == BENIGN_TUPLES
    assert all(uid == flow.uid for uid, flow in flows.items()), "the dict is keyed by uid"

    assert {flow.ts_first for flow in flows.values()} == BENIGN_FIRST_TS
    for flow in flows.values():
        # The generator spaces each flow's seven packets 10ms apart, so ts_last is later than
        # ts_first — the property correlation's time window depends on.
        assert flow.ts_last > flow.ts_first
        assert flow.ts_last == pytest.approx(flow.ts_first + 0.06, abs=0.005)
        # No TLS handshake in this capture, so no fingerprint. Absent, not empty.
        assert (flow.ja4, flow.ja4s, flow.server_name) == (None, None, None)

    assert info.version.startswith("8.")
    assert "-D" in info.flags
    assert info.log_dir == tmp_path / "zeek"
    assert info.tool_failures == ()


@pytest.mark.requires_tools
def test_two_runs_produce_identical_uids(tmp_path: Path):
    """**The determinism gate.** Two real invocations, one capture, the same uids.

    This is the regression test for the spike-3 finding recorded in `docs/prd.md` §6.2 and
    `tests/fixtures/README.md`: on Zeek 8.0.4 without `-D`, two runs over identical input
    produced entirely different uids — verified again while building this step. Since the uid
    is the join key for every label, that would make labels from two runs unjoinable and
    Goal 2 unreachable, so it fails if `-D` is ever dropped from the argv.
    """
    first, first_info = zeek.run_zeek(BENIGN, tmp_path / "one")
    second, second_info = zeek.run_zeek(BENIGN, tmp_path / "two")

    assert sorted(first) == sorted(second), "uids differ between runs — was -D dropped?"
    assert first == second, "the whole flow table must be identical, not just its keys"
    assert "-D" in first_info.flags and "-D" in second_info.flags


@pytest.mark.requires_tools
def test_packet_filter_log_is_retained_but_never_reproducible(tmp_path: Path):
    """It stamps wall-clock time, so it differs across runs while `conn.log` does not.

    Both halves matter: the exclusion is only justified if the log really is unstable, and it
    is only *safe* if the logs that carry analytic content are stable once it is set aside.
    """
    _, first = zeek.run_zeek(BENIGN, tmp_path / "one")
    _, second = zeek.run_zeek(BENIGN, tmp_path / "two")

    assert "packet_filter.log" in first.retained_logs
    assert "packet_filter.log" not in zeek.reproducible_logs(first)

    stamp = [(info.log_dir / "packet_filter.log").read_text() for info in (first, second)]
    assert stamp[0] != stamp[1], (
        "packet_filter.log was identical across two runs. If Zeek stopped stamping wall-clock "
        "time, the exclusion in NON_REPRODUCIBLE_LOGS is no longer needed — check before "
        "relaxing it."
    )

    # Zeek's TSV logs carry `#open`/`#close` wall-clock header lines of their own, so the
    # comparison is over records. Reproducibility of the *content* is what Goal 2 needs.
    for name in zeek.reproducible_logs(first):
        records = [
            [line for line in (info.log_dir / name).read_text().splitlines() if line[:1] != "#"]
            for info in (first, second)
        ]
        assert records[0] == records[1], f"{name} is not reproducible across runs"


@pytest.mark.requires_tools
def test_json_logs_are_stripped_from_the_retained_output(tmp_path: Path):
    """One representation of each log survives: the TSV one."""
    outdir = tmp_path / "zeek"
    _, info = zeek.run_zeek(BENIGN, outdir)

    assert not [name for name in info.retained_logs if name.endswith("_json.log")]
    for name in zeek.JSON_LOGS:
        assert not (outdir / name).exists(), f"{name} is parse input, not a retained artifact"

    # The TSV logs are still there, including `http.log`, which flabel never parses — "retain
    # all other logs unparsed" (spec §8). A superset rather than an exact set: which logs Zeek
    # writes depends on its version and on the loaded packages, and pinning the full list here
    # would turn a harmless extra log in the CI container into a step-5 failure.
    assert set(info.retained_logs) >= {"conn.log", "http.log", "packet_filter.log"}
    assert set(info.retained_logs) == {path.name for path in outdir.glob("*.log")}
    assert (outdir / "conn.log").read_text().startswith("#separator")


@pytest.mark.requires_tools
def test_a_real_non_zero_exit_is_recorded_as_a_tool_failure(tmp_path: Path):
    """Real Zeek, real failure: a capture it cannot open exits 1 and is reported, not raised raw.

    Ingest guarantees the file exists by the time the pipeline gets here, so this is the
    genuine tool-failure path exercised without inventing a fake binary.
    """
    with pytest.raises(ToolError) as caught:
        zeek.run_zeek(tmp_path / "absent.pcap", tmp_path / "zeek")

    failure = caught.value.run_info.tool_failures[0]
    assert failure.tool == "zeek"
    assert failure.exit_code == 1
    assert "absent.pcap" in failure.message, "Zeek's own diagnosis belongs in the record"
    assert "-D" in failure.argv


@pytest.mark.requires_tools
def test_tls_fields_are_joined_onto_the_flow_on_uid(tls_capture: Path, tmp_path: Path):
    """`ssl_json.log` enriches the matching flow and leaves every other flow alone."""
    flows, info = zeek.run_zeek(tls_capture, tmp_path / "zeek")

    assert len(flows) == 1
    flow = next(iter(flows.values()))
    assert (flow.src_ip, flow.src_port, flow.dst_ip, flow.dst_port) == TLS_TUPLE
    assert flow.server_name == TLS_SERVER_NAME, "SNI is joined from ssl.log on uid"
    assert "ssl.log" in info.retained_logs
    assert "ssl_json.log" not in info.retained_logs


@pytest.mark.requires_tools
def test_a_tls_flow_carries_a_ja4(tls_capture: Path, tmp_path: Path, strict_toolchain: bool):
    """A TLS handshake yields a populated `ja4` — **asserted in CI only.**

    JA4 is computed by Zeek and the Zeek-computed value is the single authority for what a
    label carries (`docs/prd.md` §9), so this is the test that the capability exists at all.
    It needs `zeek/foxio/ja4`, which the CI container installs and a Homebrew laptop does not
    (`docs/dev-setup.md`), so it skips locally and fails under `--strict-toolchain` — the same
    treatment `test_toolchain.py` gives the package, checked the same way.
    """
    probe = subprocess.run(
        [zeek.executable(), "--parse-only", "-e", "@load ja4"],
        capture_output=True,
        text=True,
    )
    if probe.returncode != 0 and not strict_toolchain:
        pytest.skip("zeek/foxio/ja4 is not installed — see docs/dev-setup.md")
    assert probe.returncode == 0, (
        f"Zeek cannot load the ja4 package, so no label can carry a JA4:\n{probe.stderr}"
    )

    flows, info = zeek.run_zeek(tls_capture, tmp_path / "zeek")
    flow = next(iter(flows.values()))

    assert "ja4" in info.flags, "the package must be loaded explicitly; local.zeek is not read"
    # The failure message names ssl.log's actual fields, because the one way this can fail in
    # CI while passing every local test is the package logging its fingerprint under a key
    # other than `ja4` — and that diagnosis should not need a second CI run to obtain.
    assert flow.ja4, (
        f"a TLS flow must carry a ja4, got {flow.ja4!r}. ssl.log fields were: "
        f"{_tsv_fields(info.log_dir / 'ssl.log')}"
    )
    # JA4 is `q` + protocol/version/SNI/counts + two truncated hashes, e.g.
    # `t13d1516h2_8daaf6152771_02713d6af862`. Only the shape is asserted: the exact value is
    # the ja4 package's business, and pinning it here would make a package bump fail in the
    # wrong place (`test_toolchain.py` owns the version pin).
    assert flow.ja4.count("_") == 2, f"not a JA4 fingerprint: {flow.ja4!r}"
    assert flow.ja4.startswith("t13"), f"expected a TLS 1.3 TCP fingerprint, got {flow.ja4!r}"
