"""Fetching rule feeds (docs/spec.md §2.2, §5).

`rules/fetch.py` is the only module in the package allowed to touch the network, and
`test_architecture.py` enforces that by name. **Nothing here contacts a rule-feed endpoint**:
the fetch is split into a transport (`Fetcher`) and a payload decoder, so every shape the nine
feeds publish — plain `.rules`, gzip, a tarball of one rules file, a tarball of three — is
exercised against bytes built in the test.

The transport itself is covered by injecting a fake opener, which is the only way to assert
the HTTPS-only and size-cap behaviour without a socket.
"""

from __future__ import annotations

import gzip
import io
import tarfile
from pathlib import Path

import pytest

from flabel.errors import ConfigError
from flabel.models import SourceSpec
from flabel.rules.fetch import HttpsFetcher, LocalFetcher, extract_rule_text, fetch_rule_text

FIXTURES = Path(__file__).parent / "fixtures" / "rules"

PLAIN = FIXTURES / "ioc_wholesale.rules"
URL = "https://example.invalid/feed.tar.gz"


def spec_for(url: str = URL, name: str = "abuse.ch/feodotracker") -> SourceSpec:
    return SourceSpec(
        name=name,
        url=url,
        licence="CC0-1.0",
        source_class="ioc-dest",
        admission_basis="wholesale",
    )


def tarball(members: dict[str, bytes], order: list[str] | None = None) -> bytes:
    """A `.tar.gz` payload, written in `order` so member order can differ from name order."""
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name in order or sorted(members):
            data = members[name]
            info = tarfile.TarInfo(name)
            info.size = len(data)
            archive.addfile(info, io.BytesIO(data))
    return buffer.getvalue()


# --- payload shapes ------------------------------------------------------------------------


def test_a_plain_rules_feed_is_returned_unchanged():
    """`the-hunters-ledger/open` and `oisf/trafficid` publish uncompressed rule text."""
    text = PLAIN.read_text(encoding="utf-8")

    assert extract_rule_text(text.encode("utf-8"), URL) == text


def test_gzip_is_detected_by_magic_bytes_not_by_url():
    """The same rule ingest.py follows: sniff the bytes, never trust the name (spec §8).

    A feed that starts gzipping its plain `.rules` URL — or stops — must keep working.
    """
    text = PLAIN.read_text(encoding="utf-8")
    payload = gzip.compress(text.encode("utf-8"))

    assert extract_rule_text(payload, "https://example.invalid/feed.rules") == text


def test_a_tarball_of_one_rules_file_is_unwrapped():
    text = PLAIN.read_text(encoding="utf-8")
    payload = tarball({"rules/emerging.rules": text.encode("utf-8")})

    assert extract_rule_text(payload, URL) == text


def test_a_tarball_of_three_rules_files_is_concatenated_in_member_name_order():
    """The `malsilo/win-malware` shape: one tarball, three rules files (spec §5).

    Concatenating in *name* order rather than archive order is what keeps the snapshot id
    stable — tar member order is an artifact of how upstream built the archive.
    """
    parts = {
        "malsilo/malsilo.rules-dns.rules": b"alert dns any any -> any any (sid:3;)\n",
        "malsilo/malsilo.rules-http.rules": b"alert http any any -> any any (sid:1;)\n",
        "malsilo/malsilo.rules-ip.rules": b"alert ip any any -> any any (sid:2;)\n",
    }
    forward = extract_rule_text(tarball(parts), URL)
    reversed_archive = extract_rule_text(tarball(parts, order=sorted(parts, reverse=True)), URL)

    assert forward.splitlines() == [
        "alert dns any any -> any any (sid:3;)",
        "alert http any any -> any any (sid:1;)",
        "alert ip any any -> any any (sid:2;)",
    ]
    assert forward == reversed_archive


def test_non_rules_members_are_ignored():
    """ET Open ships `classification.config`, `LICENSE` and `*.txt` beside its 60 rules files.

    Feeding those to Suricata as rules would fail the load; counting their lines would corrupt
    every admission count.
    """
    payload = tarball(
        {
            "rules/BSD-License.txt": b"Copyright...\n",
            "rules/classification.config": b"config classification: not-suspicious,x,3\n",
            "rules/compromised-ips.txt": b"198.51.100.1\n",
            "rules/emerging-malware.rules": b"alert ip any any -> any any (sid:9;)\n",
        }
    )

    assert extract_rule_text(payload, URL) == "alert ip any any -> any any (sid:9;)\n"


def test_directories_and_non_regular_members_are_skipped():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        directory = tarfile.TarInfo("rules.rules")  # a *directory* named like a rules file
        directory.type = tarfile.DIRTYPE
        archive.addfile(directory)
        link = tarfile.TarInfo("link.rules")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        archive.addfile(link)
        data = b"alert ip any any -> any any (sid:4;)\n"
        info = tarfile.TarInfo("real.rules")
        info.size = len(data)
        archive.addfile(info, io.BytesIO(data))

    assert extract_rule_text(buffer.getvalue(), URL) == "alert ip any any -> any any (sid:4;)\n"


def test_archive_members_never_reach_the_filesystem(tmp_path: Path, monkeypatch):
    """Members are read in memory, so a hostile member name cannot write anywhere.

    `tarfile.extractall` would honour `../`; `extractfile` cannot. Asserted rather than
    assumed, because rule feeds are third-party archives.
    """
    monkeypatch.chdir(tmp_path)
    payload = tarball({"../escaped.rules": b"alert ip any any -> any any (sid:5;)\n"})

    extract_rule_text(payload, URL)

    assert list(tmp_path.iterdir()) == []
    assert not (tmp_path.parent / "escaped.rules").exists()


# --- payloads that must not be treated as rules --------------------------------------------


def test_a_tarball_with_no_rules_file_is_a_hard_failure():
    """A feed whose shape changed must stop the run, not contribute zero rules silently."""
    payload = tarball({"rules/classification.config": b"config classification: x,y,3\n"})

    with pytest.raises(ConfigError, match="no .rules"):
        extract_rule_text(payload, URL)


def test_an_empty_payload_is_a_hard_failure():
    with pytest.raises(ConfigError, match="empty"):
        extract_rule_text(b"", URL)


def test_a_corrupt_archive_is_a_hard_failure():
    with pytest.raises(ConfigError):
        extract_rule_text(b"\x1f\x8b\x08\x00 not really gzip", URL)


def test_rule_text_that_is_not_utf8_is_a_hard_failure():
    """Decoding with replacement characters would hand Suricata a silently altered rule."""
    with pytest.raises(ConfigError, match="UTF-8"):
        extract_rule_text(b'alert ip any any -> any any (msg:"\xff\xfe"; sid:6;)\n', URL)


# --- the local transport, which is what the rest of the suite uses --------------------------


def test_the_local_fetcher_reads_a_registered_fixture():
    fetcher = LocalFetcher({URL: PLAIN})
    spec = spec_for()

    assert fetch_rule_text(spec, fetcher) == PLAIN.read_text(encoding="utf-8")


def test_the_local_fetcher_refuses_an_unregistered_url():
    """A missing mapping must fail, never fall through to the network.

    This is what makes "no test contacts a rule feed" structural: a test that forgot to
    register a URL fails loudly instead of quietly dialling out.
    """
    with pytest.raises(ConfigError, match="not registered"):
        fetch_rule_text(spec_for(), LocalFetcher({}))


def test_the_local_fetcher_accepts_a_tarball_on_disk(tmp_path: Path):
    archive = tmp_path / "feed.tar.gz"
    archive.write_bytes(tarball({"rules/x.rules": b"alert ip any any -> any any (sid:7;)\n"}))

    text = fetch_rule_text(spec_for(), LocalFetcher({URL: archive}))

    assert text == "alert ip any any -> any any (sid:7;)\n"


# --- the network transport, exercised without a socket --------------------------------------


class FakeResponse:
    def __init__(self, body: bytes, url: str):
        self._stream = io.BytesIO(body)
        self._url = url

    def read(self, amount: int | None = None) -> bytes:
        return self._stream.read(amount)

    def geturl(self) -> str:
        return self._url

    def __enter__(self) -> FakeResponse:
        return self

    def __exit__(self, *_: object) -> None:
        self._stream.close()


def test_the_https_fetcher_rejects_a_non_https_url_before_opening_anything():
    """Rules are the trust root of every label; over http they are forgeable in transit."""
    calls: list[str] = []

    def opener(request, timeout=None):  # pragma: no cover - must never run
        calls.append(request.full_url)
        raise AssertionError("a non-HTTPS url must not be opened")

    fetcher = HttpsFetcher(opener=opener)
    for url in ("http://example.invalid/f.rules", "file:///etc/passwd", "ftp://x/y.rules"):
        with pytest.raises(ConfigError, match="HTTPS"):
            fetcher.read(url)
    assert calls == []


def test_the_https_fetcher_rejects_a_redirect_that_leaves_https():
    """urllib follows redirects itself, so the check has to look at where it ended up."""
    fetcher = HttpsFetcher(
        opener=lambda request, timeout=None: FakeResponse(b"rules", "http://downgraded.invalid/f")
    )

    with pytest.raises(ConfigError, match="HTTPS"):
        fetcher.read("https://example.invalid/f.rules")


def test_the_https_fetcher_caps_the_payload_size():
    """An unbounded read of a third-party URL is an out-of-memory waiting to happen."""
    fetcher = HttpsFetcher(
        max_bytes=8,
        opener=lambda request, timeout=None: FakeResponse(b"x" * 64, "https://example.invalid/f"),
    )

    with pytest.raises(ConfigError, match="too large"):
        fetcher.read("https://example.invalid/f.rules")


def test_the_https_fetcher_returns_the_body_and_identifies_itself():
    seen: list[tuple[str, str | None, float | None]] = []

    def opener(request, timeout=None):
        seen.append((request.full_url, request.get_header("User-agent"), timeout))
        return FakeResponse(b"alert ip any any -> any any (sid:8;)\n", request.full_url)

    fetcher = HttpsFetcher(timeout=12.5, opener=opener)
    body = fetcher.read("https://example.invalid/f.rules")

    assert body == b"alert ip any any -> any any (sid:8;)\n"
    url, agent, timeout = seen[0]
    assert url == "https://example.invalid/f.rules"
    assert agent is not None and agent.startswith("flabel/")
    assert timeout == 12.5


def test_fetch_rule_text_uses_the_spec_url():
    """The URL comes from the registry, so a run cannot fetch from somewhere unrecorded."""
    seen: list[str] = []

    class Recorder:
        def read(self, url: str) -> bytes:
            seen.append(url)
            return b"alert ip any any -> any any (sid:10;)\n"

    fetch_rule_text(spec_for(url="https://feed.invalid/a.rules"), Recorder())

    assert seen == ["https://feed.invalid/a.rules"]
