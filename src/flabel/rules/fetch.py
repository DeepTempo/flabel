"""Fetching rule feeds — the only network I/O in the package (docs/spec.md §2.2, §5).

`test_architecture.py` enforces that by name: no other module may import `urllib`, `socket`,
`http` or `ssl`. That is what makes "a labelling run performs no network I/O" structural
rather than a promise, since a labelling run never calls into this module at all — only
`flabel rules update` does.

The work splits in two, and the split is what makes the rest of the suite testable:

* a **transport** (`Fetcher`) that turns a URL into bytes. `HttpsFetcher` is the real one;
  `LocalFetcher` maps URLs to files on disk, which is how every test — and an air-gapped
  operator with a mirrored copy of the feeds — gets rule text without a socket.
* a **decoder** (`extract_rule_text`) that turns those bytes into rule text. The nine feeds
  ship in three shapes: plain `.rules` text (2), a `.tar.gz` holding one rules file (6), and
  `malsilo/win-malware`'s tarball of three. The shape is decided by the payload's magic bytes,
  never by the URL, exactly as `ingest.py` decides a capture's format (spec §8).

What this module deliberately does not do is decide anything about a rule. Admission is
`admit.py`'s job and is pure, so the question "would this rule have been labelled?" is always
answerable without a network.
"""

from __future__ import annotations

import gzip
import io
import tarfile
import urllib.request
import zlib
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol

import flabel
from flabel.errors import ConfigError
from flabel.models import SourceSpec

#: Only members whose name ends in this are read from an archive. ET Open's tarball also
#: carries `classification.config`, `gen-msg.map`, `BSD-License.txt` and `compromised-ips.txt`
#: — feeding those to Suricata as rules would fail the load, and counting their lines would
#: corrupt every admission count in the manifest.
RULES_SUFFIX = ".rules"

GZIP_MAGIC = b"\x1f\x8b"

#: Payload ceiling for one feed. ET Open is ~5.5 MB compressed; 256 MB is four orders of
#: magnitude of headroom and still bounds an unattended `rules update` against a URL that
#: turns into an endless stream.
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024

DEFAULT_TIMEOUT_SECONDS = 60.0


class Fetcher(Protocol):
    """Anything that can turn a feed URL into bytes.

    A Protocol rather than a base class so a test can pass any object with a `read`, and so
    the network implementation is one substitutable piece rather than the default path
    everything else has to work around.
    """

    def read(self, url: str) -> bytes: ...


class HttpsFetcher:
    """The real transport: HTTPS only, size-capped, no redirect off HTTPS.

    `opener` is injected so the URL policy above can be tested without a socket. It defaults
    to `urllib.request.urlopen`, whose default TLS context verifies certificates — which is
    the point of insisting on HTTPS in the first place.
    """

    def __init__(
        self,
        timeout: float = DEFAULT_TIMEOUT_SECONDS,
        max_bytes: int = MAX_PAYLOAD_BYTES,
        opener: Callable[..., object] | None = None,
    ) -> None:
        self.timeout = timeout
        self.max_bytes = max_bytes
        self._opener = urllib.request.urlopen if opener is None else opener

    def read(self, url: str) -> bytes:
        _require_https(url, "requested")
        request = urllib.request.Request(
            url,
            headers={"User-Agent": f"flabel/{flabel.__version__}"},
        )
        try:
            with self._opener(request, timeout=self.timeout) as response:  # type: ignore[attr-defined]
                # Every label traces back to a rule fetched from a URL. A redirect that lands
                # on http:// would make that rule forgeable in transit while the registry
                # still recorded an https:// origin, so the *final* URL is checked too.
                _require_https(response.geturl(), "redirected to")
                # One byte over the cap, so the difference between "exactly at the limit" and
                # "truncated silently" is visible.
                payload = response.read(self.max_bytes + 1)
        except OSError as exc:
            # `urllib.error.URLError` (and so `HTTPError`) is an OSError, as are socket
            # timeouts and connection resets. One clause covers every way the transport fails.
            raise ConfigError(f"could not fetch {url}: {exc}") from exc

        if len(payload) > self.max_bytes:
            raise ConfigError(
                f"{url} returned more than {self.max_bytes} bytes, which is too large for a "
                f"rule feed. Raise HttpsFetcher(max_bytes=...) only if the feed really grew."
            )
        return payload


class LocalFetcher:
    """A transport that reads pre-registered files instead of URLs.

    Two users: the test suite, where no rule-feed endpoint may ever be contacted (spec §2's
    testing line), and an operator mirroring the feeds by hand into an air-gapped network.

    An unregistered URL is an error rather than a fall-through to the network, so a test that
    forgot to register a feed fails loudly instead of quietly dialling out.
    """

    def __init__(self, payloads: Mapping[str, Path]) -> None:
        self._payloads = dict(payloads)

    def read(self, url: str) -> bytes:
        try:
            path = self._payloads[url]
        except KeyError:
            raise ConfigError(
                f"{url} is not registered with this LocalFetcher (known: "
                f"{sorted(self._payloads)}). A rule feed is never fetched from the network "
                f"here — register the local payload instead."
            ) from None
        try:
            return Path(path).read_bytes()
        except OSError as exc:
            raise ConfigError(f"could not read local rule payload {path}: {exc}") from exc


def fetch_rule_text(spec: SourceSpec, fetcher: Fetcher | None = None) -> str:
    """The rule text of one source, as published.

    The URL comes from the registry entry, never from a caller, so no run can fetch rules from
    somewhere its own output does not record (`SourceAdmission.url`).
    """
    transport = HttpsFetcher() if fetcher is None else fetcher
    return extract_rule_text(transport.read(spec.url), spec.url)


def extract_rule_text(payload: bytes, origin: str) -> str:
    """Rule text from a fetched payload, whatever shape the feed publishes.

    `origin` appears in failure messages only; the decision is made from the bytes.

    Every failure here is hard. A feed whose shape changed — an HTML error page, a tarball
    with no rules file, a truncated download — would otherwise contribute zero rules to the
    snapshot, and a zero is indistinguishable from a feed that legitimately matched nothing
    (spec §2.5).
    """
    if not payload:
        raise ConfigError(f"{origin} returned an empty payload")

    if payload.startswith(GZIP_MAGIC):
        try:
            decompressed = gzip.decompress(payload)
        except (OSError, EOFError, zlib.error) as exc:
            # `BadGzipFile` is an OSError (a bad *header*), but a corrupt deflate stream
            # surfaces as `zlib.error`, and a truncated one as `EOFError`. All three mean the
            # same thing to us: this payload is not the ruleset it claimed to be.
            raise ConfigError(f"{origin} is not readable gzip: {exc}") from exc
    else:
        decompressed = payload

    if _is_tar(decompressed):
        return _rules_from_tar(decompressed, origin)
    return _decode(decompressed, origin)


def _is_tar(data: bytes) -> bool:
    """Whether `data` is a tar archive, by content.

    `tarfile.is_tarfile` reads the header rather than trusting a name, which is what lets a
    feed switch between `feed.rules.gz` and `feed.tar.gz` without a code change.
    """
    try:
        return tarfile.is_tarfile(io.BytesIO(data))
    except (OSError, tarfile.TarError):
        return False


def _rules_from_tar(data: bytes, origin: str) -> str:
    """Concatenate every `*.rules` member, in member-*name* order.

    Name order, not archive order: tar member order is an artifact of how upstream built the
    archive, and `malsilo/win-malware` ships three rules files in one tarball. If archive
    order reached the snapshot, an upstream rebuild that changed nothing would still change
    the snapshot id.

    Members are read with `extractfile`, so nothing is ever written to the filesystem and a
    hostile member name (`../../authorized_keys`) has nothing to traverse. Only regular files
    are read: a symlink member named `*.rules` is skipped rather than followed.
    """
    parts: list[str] = []
    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            members = sorted(
                (member for member in archive.getmembers() if _is_rules_member(member)),
                key=lambda member: member.name,
            )
            for member in members:
                handle = archive.extractfile(member)
                if handle is None:  # pragma: no cover - defensive; isfile() already filtered
                    continue
                with handle:
                    parts.append(_decode(handle.read(), f"{origin}:{member.name}"))
    except tarfile.TarError as exc:
        raise ConfigError(f"{origin} is not a readable tar archive: {exc}") from exc

    if not parts:
        raise ConfigError(
            f"{origin} is an archive with no {RULES_SUFFIX} member. The feed's shape has "
            f"changed; admitting zero rules from it would look like a ruleset that matched "
            f"nothing."
        )
    return "".join(_ending_in_newline(part) for part in parts)


def _is_rules_member(member: tarfile.TarInfo) -> bool:
    return member.isfile() and member.name.endswith(RULES_SUFFIX)


def _decode(data: bytes, origin: str) -> str:
    """Strict UTF-8. Replacement characters would hand Suricata a silently altered rule."""
    try:
        return data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ConfigError(
            f"{origin} is not valid UTF-8 ({exc}). Rule text is not decoded with replacement "
            f"characters, because that would change the rule Suricata loads."
        ) from exc


def _ending_in_newline(text: str) -> str:
    """So the last rule of one archive member cannot fuse with the first of the next."""
    if not text or text.endswith("\n"):
        return text
    return text + "\n"


def _require_https(url: str, what: str) -> None:
    if not url.startswith("https://"):
        raise ConfigError(
            f"{what} URL {url!r} is not HTTPS. Rules are the trust root of every label: over "
            f"http:// they are forgeable in transit, and file:// would make an arbitrary local "
            f"file into label evidence."
        )
