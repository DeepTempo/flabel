"""Fetching rule feeds — the only network I/O in the package (docs/spec.md §2.2, §5).

`test_architecture.py` enforces that by name: no other module may import `urllib`, `socket`,
`http` or `ssl`. That is what makes "a labelling run performs no network I/O" structural
rather than a promise, since a labelling run never calls into this module at all — only
`flabel rules update` does.

The work splits in two, and the split is what makes the rest of the suite testable:

* a **transport** (`Fetcher`) that turns a URL into bytes. `HttpsFetcher` is the real one;
  `LocalFetcher` maps URLs to files on disk, which is how every test — and an air-gapped
  operator with a mirrored copy of the feeds — gets rule text without a socket.
* a **decoder** (`extract_feed`) that turns those bytes into rule text plus companion data
  files. The nine feeds ship in three shapes: plain `.rules` text (2), a `.tar.gz` holding one
  rules file (6), and `malsilo/win-malware`'s tarball of three. The shape is decided by the
  payload's magic bytes, never by the URL, exactly as `ingest.py` decides a capture's format.

**Companion data files are part of a ruleset, not noise.** `pawpatrules` ships 18 `.lst` files
that 26 of its rules read with `dataset:`, and a rule whose dataset is missing does not fail
loudly — it simply never matches. Every non-`.rules` member is therefore kept and travels into
the snapshot, where `snapshot_id` covers it.

Every size limit here exists because a rule feed is a third-party URL: the wire bytes are
capped, the gzip output is capped separately (a 1000:1 ratio is easy to build deliberately),
and each archive member is capped again.

What this module deliberately does not do is decide anything about a rule. Admission is
`admit.py`'s job and is pure, so the question "would this rule have been labelled?" is always
answerable without a network.
"""

from __future__ import annotations

import gzip
import http.client
import io
import tarfile
import urllib.parse
import urllib.request
import zlib
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Protocol

import flabel
from flabel.errors import ConfigError
from flabel.models import SourceSpec

#: Members read as rules. Everything else in the archive is kept as companion data.
RULES_SUFFIX = ".rules"

GZIP_MAGIC = b"\x1f\x8b"

#: Payload ceiling on the wire. ET Open is ~5.5 MB compressed; 256 MB is four orders of
#: magnitude of headroom and still bounds an unattended `rules update` against a URL that
#: turns into an endless stream.
MAX_PAYLOAD_BYTES = 256 * 1024 * 1024

#: Ceiling *after* decompression, and on the total extracted from an archive. The wire cap
#: cannot bound this: gzip reaches ~1000:1 on repetitive text, so 256 MB of wire bytes could be
#: hundreds of gigabytes of rules. ET Open's 5.5 MB expands to ~43 MB.
MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024

#: Ceiling for one archive member. `pawpatrules`' largest is a few hundred KB.
MAX_MEMBER_BYTES = 64 * 1024 * 1024

DEFAULT_TIMEOUT_SECONDS = 60.0


class Fetcher(Protocol):
    """Anything that can turn a feed URL into bytes.

    A Protocol rather than a base class so a test can pass any object with a `read`, and so
    the network implementation is one substitutable piece rather than the default path
    everything else has to work around.
    """

    def read(self, url: str) -> bytes: ...


class HttpsFetcher:
    """The real transport: HTTPS only, size-capped, and no redirect off the requested host.

    `opener` is injected so the URL policy can be tested without a socket. It defaults to
    `urllib.request.urlopen`, whose default TLS context verifies certificates — which is the
    point of insisting on HTTPS in the first place.
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
                # urllib follows redirects itself, so where it *ended up* is what has to be
                # checked — scheme and host both. `SourceAdmission.url` records the registry's
                # URL on every label, so a fetch that silently landed on another host would
                # make that field a false statement about where the rules came from.
                final = response.geturl()
                _require_https(final, "redirected")
                _require_same_host(url, final)
                # One byte over the cap, so "exactly at the limit" and "truncated silently"
                # are distinguishable.
                payload = response.read(self.max_bytes + 1)
        except (OSError, http.client.HTTPException) as exc:
            # `urllib.error.URLError` (and so `HTTPError`) is an OSError, as are socket
            # timeouts and connection resets. `http.client.IncompleteRead` — a truncated
            # download, which large feeds do produce — is an HTTPException and is *not* an
            # OSError, so without it a common transport failure escapes as a traceback.
            raise ConfigError(f"could not fetch {url}: {exc!r}") from exc

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

    def __init__(self, payloads: Mapping[str, Path], max_bytes: int = MAX_PAYLOAD_BYTES) -> None:
        self._payloads = dict(payloads)
        self.max_bytes = max_bytes

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
            with Path(path).open("rb") as handle:
                # Capped like the network transport: a mirror directory is as untrusted as the
                # feed it mirrors, and an operator can point this at anything.
                payload = handle.read(self.max_bytes + 1)
        except OSError as exc:
            raise ConfigError(f"could not read local rule payload {path}: {exc}") from exc
        if len(payload) > self.max_bytes:
            raise ConfigError(f"{path} is larger than {self.max_bytes} bytes")
        return payload


def fetch_feed(spec: SourceSpec, fetcher: Fetcher | None = None) -> tuple[str, dict[str, bytes]]:
    """The rule text and companion data files of one source, as published.

    The URL comes from the registry entry, never from a caller, so no run can fetch rules from
    somewhere its own output does not record (`SourceAdmission.url`).
    """
    transport = HttpsFetcher() if fetcher is None else fetcher
    return extract_feed(transport.read(spec.url), spec.url)


def fetch_rule_text(spec: SourceSpec, fetcher: Fetcher | None = None) -> str:
    """Just the rule text, for callers with no use for companion data."""
    return fetch_feed(spec, fetcher)[0]


def extract_rule_text(payload: bytes, origin: str) -> str:
    """Just the rule text of a payload. See `extract_feed`."""
    return extract_feed(payload, origin)[0]


def extract_feed(payload: bytes, origin: str) -> tuple[str, dict[str, bytes]]:
    """Rule text and companion data files from a fetched payload, whatever the shape.

    `origin` appears in failure messages only; the decision is made from the bytes.

    Companion data files are keyed by **basename**, because that is how rules reference them:
    `pawpatrules` ships `rules/pawpatrules_tor.lst` in its archive and loads it as
    `dataset:isset,pawpatrules_tor,type string,load pawpatrules_tor.lst`.

    Every failure here is hard. A feed whose shape changed — an HTML error page, a tarball with
    no rules file, a truncated download — would otherwise contribute zero rules to the snapshot,
    and a zero is indistinguishable from a feed that legitimately matched nothing (spec §2.5).
    """
    if not payload:
        raise ConfigError(f"{origin} returned an empty payload")

    decompressed = _decompress(payload, origin) if payload.startswith(GZIP_MAGIC) else payload

    if _is_tar(decompressed):
        return _feed_from_tar(decompressed, origin)
    return _decode(decompressed, origin), {}


def _decompress(payload: bytes, origin: str) -> bytes:
    """Decompress gzip, bounded.

    `gzip.decompress` is unbounded and so cannot be used on a third-party payload: the wire cap
    says nothing about the output size, and a ~1000:1 ratio is easy to produce deliberately.
    """
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(payload)) as stream:
            decompressed = stream.read(MAX_DECOMPRESSED_BYTES + 1)
    except (OSError, EOFError, zlib.error) as exc:
        # `BadGzipFile` is an OSError (a bad *header*), a corrupt deflate stream surfaces as
        # `zlib.error`, and a truncated one as `EOFError`. All three mean the same thing here:
        # this payload is not the ruleset it claimed to be.
        raise ConfigError(f"{origin} is not readable gzip: {exc}") from exc

    if len(decompressed) > MAX_DECOMPRESSED_BYTES:
        raise ConfigError(
            f"{origin} decompresses to more than {MAX_DECOMPRESSED_BYTES} bytes. Either the "
            f"feed grew by orders of magnitude or the payload is a decompression bomb."
        )
    return decompressed


def _is_tar(data: bytes) -> bool:
    """Whether `data` is a tar archive, by content.

    `tarfile.is_tarfile` reads the header rather than trusting a name, which is what lets a
    feed switch between `feed.rules.gz` and `feed.tar.gz` without a code change.
    """
    try:
        return tarfile.is_tarfile(io.BytesIO(data))
    except (OSError, tarfile.TarError):
        return False


def _feed_from_tar(data: bytes, origin: str) -> tuple[str, dict[str, bytes]]:
    """Split an archive into concatenated rule text and companion data files.

    Rules are concatenated in member-*name* order, not archive order: tar member order is an
    artifact of how upstream built the archive, and `malsilo/win-malware` ships three rules
    files in one tarball. If archive order reached the snapshot, an upstream rebuild that
    changed nothing would still change the snapshot id.

    Members are read with `extractfile`, so nothing is ever written to the filesystem and a
    hostile member name (`../../authorized_keys`) has nothing to traverse. Only regular files
    are read: a symlink member named `*.rules` is skipped rather than followed.
    """
    rules: list[str] = []
    data_files: dict[str, bytes] = {}
    extracted = 0

    try:
        with tarfile.open(fileobj=io.BytesIO(data)) as archive:
            members = sorted(
                (member for member in archive.getmembers() if member.isfile()),
                key=lambda member: member.name,
            )
            for member in members:
                content = _read_member(archive, member, origin)
                extracted += len(content)
                if extracted > MAX_DECOMPRESSED_BYTES:
                    raise ConfigError(
                        f"{origin} extracts to more than {MAX_DECOMPRESSED_BYTES} bytes in "
                        f"total across its members"
                    )
                if member.name.endswith(RULES_SUFFIX):
                    rules.append(_decode(content, f"{origin}:{member.name}"))
                    continue
                name = member.name.rsplit("/", 1)[-1]
                if name in data_files:
                    # Two members with the same basename in different directories. Data files
                    # are keyed by basename because that is how `dataset:` loads them, so one
                    # would overwrite the other and 26 pawpatrules rules would silently read
                    # the wrong list.
                    raise ConfigError(
                        f"{origin} ships more than one member named {name!r}; companion data "
                        f"files are referenced by basename and cannot be disambiguated."
                    )
                data_files[name] = content
    except tarfile.TarError as exc:
        raise ConfigError(f"{origin} is not a readable tar archive: {exc}") from exc

    if not rules:
        raise ConfigError(
            f"{origin} is an archive with no {RULES_SUFFIX} member. The feed's shape has "
            f"changed; admitting zero rules from it would look like a ruleset that matched "
            f"nothing."
        )
    return "".join(_ending_in_newline(part) for part in rules), data_files


def _read_member(archive: tarfile.TarFile, member: tarfile.TarInfo, origin: str) -> bytes:
    if member.size > MAX_MEMBER_BYTES:
        raise ConfigError(
            f"{origin}:{member.name} declares {member.size} bytes, over the "
            f"{MAX_MEMBER_BYTES}-byte member limit"
        )
    handle = archive.extractfile(member)
    if handle is None:  # pragma: no cover - defensive; isfile() already filtered
        return b""
    with handle:
        # Bounded even though the header was checked: a tar header is a claim, not a fact.
        content = handle.read(MAX_MEMBER_BYTES + 1)
    if len(content) > MAX_MEMBER_BYTES:
        raise ConfigError(f"{origin}:{member.name} is larger than its header claimed")
    return content


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


def _require_same_host(requested: str, final: str) -> None:
    """Reject a redirect that leaves the host the registry named.

    Measured 2026-08-12: none of the nine feeds redirects at all, so this costs nothing today.
    A redirect *within* a host is allowed — the path may move — because the host is what
    `SourceAdmission.url` is a claim about.
    """
    wanted = urllib.parse.urlsplit(requested).netloc.casefold()
    got = urllib.parse.urlsplit(final).netloc.casefold()
    if wanted != got:
        raise ConfigError(
            f"{requested} redirected to another host ({got}). The registry URL is recorded on "
            f"every label as the origin of its rules, so a cross-host redirect is refused "
            f"rather than followed silently: point the registry at {final!r} if that host is "
            f"the intended source."
        )
