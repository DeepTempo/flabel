"""The PANW NGFW as a Tier 1 detection source (Phase 2).

Suricata reads a file; the firewall watches a wire and is then *asked* what it saw. So this
module is a client, and it is the first thing in flabel that talks to a device.

**This module breaks spec §2.2's "a labelling run performs no network I/O", deliberately and
with Craig's agreement (2026-08-17).** The guarantee was written when every mode read files, and
it now belongs to the mode that can keep it: `--offline` performs no network I/O, and the
default path contacts the device. That is what `--offline` always meant, and the flag name
predates this module by a phase. `tests/test_architecture.py` records the same decision, so
`panw.py` is the second and last permitted network module, alongside `rules/fetch.py`.

Tests never contact a device (PRD §5, `[LAB]` criteria only). Everything here that decides what
a *label* says — the tuple spelling, the admission gate, the provenance mapping — is a pure
function over parsed XML, so it is tested against recorded responses rather than a firewall.

**Why the query is bounded by wall clock and the join is not.** A threat log carries the time
the firewall saw the packet, which is replay time, not capture time. That timestamp is good for
exactly one thing: selecting the logs belonging to this replay. It is *not* how a detection
finds its flow — `correlate._place` matches the 5-tuple, and consults a clock only to separate a
tuple that occurs more than once in one capture. Measured 2026-08-17 on a real capture: all 13
tier-1 detections placed on tuple alone, 0 ambiguous, 0 unmatched. PRD §5 says the same thing
from the other direction, which is why sub-second clock sync was never required.

So the window is padded rather than tight. A tight window would drop a detection because a
firewall's clock differs by a second, and losing a real label to a clock skew is a much worse
error than including a log that the tuple then declines to match.
"""

from __future__ import annotations

import calendar
import time
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from collections.abc import Iterator, Mapping, Sequence
from dataclasses import dataclass

from flabel.errors import ToolError
from flabel.models import Detection, Direction, ToolFailure

#: The firewall is Tier 1 — a lower tier is a *higher*-trust observation, and `Label.best_tier`
#: is the minimum across a flow's sources. `suricata.TIER` is 2 and says the same from its side.
TIER = 1

#: Seconds of slack added either side of the replay window when selecting logs. Generous on
#: purpose: see the module header. Both hosts are NTP-synced to one source, so this is not
#: covering for a broken clock — it is covering for the second-granularity of `receive_time`
#: and for a session logged slightly after the packet that tripped it.
WINDOW_PAD_SECONDS = 120

#: PAN-OS returns logs a page at a time and caps a page at 5000 entries.
PAGE_SIZE = 5000

#: A log query is a job: submit, poll, retrieve. These bound the poll rather than the request.
JOB_POLL_SECONDS = 2
JOB_TIMEOUT_SECONDS = 600
HTTP_TIMEOUT_SECONDS = 120

#: **flabel applies no severity gate to tier 1** (Craig, 2026-08-17).
#:
#: The admission decision for tier 1 lives on the firewall, in its threat exceptions, and is
#: curated there before a run happens. An earlier version of this module excluded
#: `informational` on the tier-2 argument from issue #75 — that a protocol-conformance
#: observation is not an attack. That reasoning is still right *about Suricata*, where flabel
#: owns the ruleset; it is wrong here, where it would silently overrule an exception the operator
#: deliberately configured, and drop a detection they had already decided to keep.
#:
#: What replaces it is not "trust us" but a recorded basis: every tier-1 entry carries
#: `admission_basis: "device-policy"` and a `ruleset` naming both the content version and the
#: device's config version. A consumer can therefore see that the gate lived on the device, and
#: identify exactly which policy revision it was.
#:
#: The subtype gate below stays, because it is structural rather than a quality judgment.
SEVERITY_GATE = None

#: Threat-log subtypes that assert a *threat*, and the only ones that may become labels.
#:
#: Structural, not a judgment about quality: PAN-OS files `url`, `data` and `file` events in the
#: threat log too, and those carry a category name where a signature name belongs. Admitting one
#: would publish a label whose `threat` reads "search-engines" and whose `sid` identifies a URL
#: category — a well-formed label about nothing. This is not the operator's exceptions being
#: second-guessed; it is the difference between a signature match and a different kind of record
#: that happens to share a log.
LABELLING_SUBTYPES = frozenset({"vulnerability", "spyware", "virus", "wildfire-virus"})

#: PAN-OS protocol spellings that differ from Zeek's `conn.log`. Same job as
#: `suricata.PROTO_ALIASES` and the same rule: Zeek's `transport_proto` has only tcp/udp/icmp/
#: unknown_transport, so anything else must agree with Zeek or go unmatched. PAN-OS writes
#: lowercase names already, so this table exists for the cases where it does not.
PROTO_ALIASES = {"ipv6-icmp": "icmp", "icmpv6": "icmp"}


@dataclass(frozen=True)
class DeviceInfo:
    """What the device is, for the run block's `tools` section.

    `threat_version` is load-bearing, not decoration: it is the tier-1 equivalent of a ruleset
    snapshot id, and a label that cannot name the signature set that produced it is exactly the
    unattributable verdict this project refuses to ship. The base VM-Series image ships
    Applications-only content, where this field reads `0` and *no* threat can ever fire — a run
    against that device would look clean and be blind.
    """

    hostname: str
    serial: str
    sw_version: str
    app_version: str
    threat_version: str
    model: str

    @property
    def has_threat_content(self) -> bool:
        """Whether a threat signature set is installed at all."""
        return bool(self.threat_version) and self.threat_version.strip() not in {"0", ""}


@dataclass(frozen=True)
class ThreatQuery:
    """The window a tier-1 run asked the device for, recorded as an input to the run.

    Recorded for the reason spec §10 records the unmatched threshold: it is a knob, and a
    consumer cannot otherwise tell a run that asked for the right window from one that asked for
    the wrong one and found nothing.
    """

    start_wall: float
    end_wall: float
    pad_seconds: int = WINDOW_PAD_SECONDS

    def _stamp(self, value: float) -> str:
        """PAN-OS log-query time format, in **UTC**.

        `receive_time` is written in the device's configured zone and this filter is compared
        against it as *text*, so the two only agree if both sides use the same zone. UTC is that
        zone, and `fl-ngfw` is configured to it (`set deviceconfig system timezone UTC`).

        **Measured the hard way, 2026-08-17.** With `time.localtime` here, the replay host on UTC
        and the device on PDT, this query returned **0 entries for a window in which the device
        had written 13 threat logs** — the filter was seven hours off. NTP sync does not help:
        it agrees the two clocks on the same *instant*, and says nothing about the zone each one
        renders that instant in.

        That failure is why `verify_clock` exists. Zero rows is indistinguishable from a capture
        with nothing malicious in it, so a zone mismatch would quietly publish "nothing found"
        for every run — the exact class of silent under-report spec §11 gives a named field.
        """
        return time.strftime("%Y/%m/%d %H:%M:%S", time.gmtime(value))

    def filter_expression(self) -> str:
        start = self._stamp(self.start_wall - self.pad_seconds)
        end = self._stamp(self.end_wall + self.pad_seconds)
        return f"(receive_time geq '{start}') and (receive_time leq '{end}')"


class PanwDevice:
    """A firewall, reached over its XML API.

    Holds an API key rather than a password. PAN-OS keys are long-lived, so a run needs no
    password at all, and the credential that *can* be re-derived is the one that should not be
    left on the replaying host.
    """

    def __init__(self, host: str, api_key: str, *, verify: bool = False) -> None:
        self.host = host
        self._key = api_key
        # A lab firewall presents a self-signed certificate. Off by default and named in the
        # signature so that turning it on is a one-word change rather than a rewrite — and so
        # that this decision is visible in the run's own configuration rather than implied.
        self.verify = verify

    def _request(self, params: Mapping[str, str], what: str) -> ET.Element:
        """One API call, returning the parsed `<response>` element.

        Every failure — transport, HTTP, PAN-OS-level `status="error"`, unparseable body —
        becomes a `ToolError` carrying a `ToolFailure`, because spec §11 says a run reports what
        it lost and an operator reading `run.json` needs to know which call failed.
        """
        query = dict(params)
        query["key"] = self._key
        url = f"https://{self.host}/api/?{urllib.parse.urlencode(query)}"
        # The key is stripped from anything that could be published. A ToolFailure lands in
        # run.json, and a run artifact that carries a live firewall credential would be a
        # far worse defect than the failure it was describing.
        safe = url.replace(self._key, "<redacted>")

        context = None
        if not self.verify:
            import ssl  # noqa: PLC0415 - local so the import is visible where it is justified

            context = ssl._create_unverified_context()  # noqa: S323 - lab, self-signed

        try:
            with urllib.request.urlopen(url, timeout=HTTP_TIMEOUT_SECONDS, context=context) as r:
                body = r.read()
        except Exception as exc:  # noqa: BLE001 - urllib raises a wide family; all are the same failure
            raise ToolError(
                f"the firewall at {self.host} could not be reached while {what}: {exc}",
                failures=(
                    ToolFailure(tool="panw-api", argv=(safe,), exit_code=None, message=str(exc)),
                ),
            ) from exc

        try:
            root = ET.fromstring(body)
        except ET.ParseError as exc:
            raise ToolError(
                f"the firewall at {self.host} returned an unparseable response while {what}",
                failures=(
                    ToolFailure(tool="panw-api", argv=(safe,), exit_code=None, message=str(exc)),
                ),
            ) from exc

        if root.get("status") != "success":
            message = "".join(root.itertext()).strip() or "no message"
            raise ToolError(
                f"the firewall at {self.host} refused the request while {what}: {message}",
                failures=(
                    ToolFailure(tool="panw-api", argv=(safe,), exit_code=None, message=message),
                ),
            )
        return root

    def system_info(self) -> DeviceInfo:
        root = self._request(
            {"type": "op", "cmd": "<show><system><info/></system></show>"}, "reading system info"
        )
        return parse_system_info(root)

    def clear_sessions(self) -> None:
        """Force every open session closed, which flushes its session-end traffic log.

        today.md step 4, and it earns its place: a replayed capture frequently lacks clean
        FIN/RST, so sessions would otherwise sit until PAN-OS's TCP timeout (3600 s by default)
        and their logs would not exist when the query runs. This is also why session-*start*
        logging is not needed — measured and decided 2026-08-17.
        """
        self._request(
            {"type": "op", "cmd": "<clear><session><all/></session></clear>"}, "clearing sessions"
        )

    def threat_entries(self, query: ThreatQuery) -> tuple[ET.Element, ...]:
        """Every threat-log entry in the window, following PAN-OS's job-then-fetch protocol."""
        entries: list[ET.Element] = []
        skip = 0
        while True:
            page = self._threat_page(query, skip)
            entries.extend(page)
            if len(page) < PAGE_SIZE:
                return tuple(entries)
            skip += len(page)

    def _threat_page(self, query: ThreatQuery, skip: int) -> list[ET.Element]:
        submitted = self._request(
            {
                "type": "log",
                "log-type": "threat",
                "query": query.filter_expression(),
                "nlogs": str(PAGE_SIZE),
                "skip": str(skip),
                "dir": "forward",
            },
            "submitting the threat-log query",
        )
        job = submitted.findtext(".//job")
        if not job:
            raise ToolError(
                f"the firewall at {self.host} accepted the threat-log query without returning a "
                f"job id, so its results cannot be collected"
            )
        return self._collect(job.strip())

    def _collect(self, job: str) -> list[ET.Element]:
        deadline = time.monotonic() + JOB_TIMEOUT_SECONDS
        while True:
            root = self._request(
                {"type": "log", "action": "get", "job-id": job}, f"retrieving threat-log job {job}"
            )
            status = (root.findtext(".//job/status") or "").strip().upper()
            if status == "FIN":
                return list(root.findall(".//log/logs/entry"))
            if time.monotonic() > deadline:
                raise ToolError(
                    f"threat-log job {job} on {self.host} was still {status or 'unknown'} after "
                    f"{JOB_TIMEOUT_SECONDS}s; the run cannot report which logs it did not read"
                )
            time.sleep(JOB_POLL_SECONDS)

    def clock(self) -> float:
        """The device's own current time, as a POSIX timestamp.

        Read so that `verify_clock` can compare it against the replaying host's, because the
        query window is only meaningful if the two agree — see `ThreatQuery._stamp`.
        """
        root = self._request(
            {"type": "op", "cmd": "<show><clock/></show>"}, "reading the device clock"
        )
        return _clock_epoch("".join(root.itertext()).strip())

    def logs_written(self) -> Mapping[str, int]:
        """The device's own count of logs it has written, by type.

        The integrity check for tier 1, and it exists because the one failure this pipeline
        cannot otherwise see is a log the firewall wrote and we did not read. At `--multiplier
        1000` the device generates logs at roughly a thousand times real-world rate, so
        saturating its log path is a live possibility rather than a theoretical one. Comparing
        this delta against the number of entries retrieved turns silent loss into a reported
        loss condition.

        Note the counters are cumulative since boot, so only a before/after difference means
        anything. Measured 2026-08-17: `Vulnerability logs written` went 0 -> 13 across one
        replay, matching the 13 entries the query returned.
        """
        root = self._request(
            {"type": "op", "cmd": "<debug><log-receiver><statistics/></log-receiver></debug>"},
            "reading log counters",
        )
        counters: dict[str, int] = {}
        for line in "".join(root.itertext()).splitlines():
            if "logs written" not in line.casefold():
                continue
            label, _, value = line.rpartition(":")
            number = value.strip()
            if number.isdigit():
                counters[label.strip().casefold().replace(" logs written", "")] = int(number)
        return counters


def parse_system_info(root: ET.Element) -> DeviceInfo:
    """`<show><system><info/></system></show>` as a `DeviceInfo`."""

    def field(name: str) -> str:
        return (root.findtext(f".//{name}") or "").strip()

    return DeviceInfo(
        hostname=field("hostname"),
        serial=field("serial"),
        sw_version=field("sw-version"),
        app_version=field("app-version"),
        threat_version=field("threat-version"),
        model=field("model"),
    )


def _text(entry: ET.Element, name: str) -> str:
    return (entry.findtext(name) or "").strip()


def _port(entry: ET.Element, name: str) -> int:
    """A port column, or 0 where the protocol has none.

    0 rather than None because `Detection` types these as `int`, and because Zeek writes 0 in
    both port columns for a protocol it cannot name — so 0 is the value that *matches* what
    correlation will compare against, not a stand-in for missing.
    """
    raw = _text(entry, name)
    return int(raw) if raw.isdigit() else 0


def threat_id(entry: ET.Element) -> int | None:
    """The numeric signature id, which becomes `Detection.sid`.

    PAN-OS spells this two ways depending on version and field: a bare number in `<threatid>`,
    or `Name(12345)` with the id in parentheses. Both are read, and a `threatid` that yields no
    number returns None so the caller can report it rather than attribute the detection to
    signature 0 — a label naming the wrong signature is worse than a detection reported as
    unattributable.
    """
    raw = _text(entry, "threatid")
    if raw.isdigit():
        return int(raw)
    if "(" in raw and raw.rstrip().endswith(")"):
        inner = raw[raw.rfind("(") + 1 : -1].strip()
        if inner.isdigit():
            return int(inner)
    tid = _text(entry, "tid")
    return int(tid) if tid.isdigit() else None


def content_version(entry: ET.Element) -> str | None:
    """The signature set that produced this detection, read off the entry itself.

    `contentver` on a real response reads `AppThreat-9136-10199`. This is the tier-1 equivalent of
    a ruleset snapshot id, and taking it per-entry rather than from `show system info` matters for
    the same reason spec §9 insists the manifest handed to `correlate` is the one Suricata ran: a
    content update landing mid-run would otherwise have every label cite the version installed at
    the end, including the labels produced before it.
    """
    raw = _text(entry, "contentver")
    return raw or None


def session_id(entry: ET.Element) -> str | None:
    """The firewall's session id for this detection.

    Not published on a label — flabel's flow identity is Zeek's `uid` and a PAN-OS session id
    means nothing to a consumer. Read because it is what distinguishes a signature firing on
    several *separate* sessions that happen to share a 5-tuple from the same session logged
    repeatedly, and those are different facts about a capture.
    """
    return _text(entry, "sessionid") or None


def threat_name(entry: ET.Element) -> str:
    """The human-readable signature name, which becomes `SourceEntry.threat`.

    Stripped of the trailing `(id)` when PAN-OS bundles both into one field, because the id is
    published separately as `sid` and repeating it inside the name would make two fields that
    can disagree.
    """
    raw = _text(entry, "threatid")
    if raw.endswith(")") and "(" in raw:
        return raw[: raw.rfind("(")].strip() or raw
    return raw


def admits(entry: ET.Element) -> bool:
    """Whether this entry may assert `verdict: malicious`.

    One gate, and it is structural: the record must be a signature match on a threat. Severity is
    deliberately not consulted — see `SEVERITY_GATE` — because the quality decision for tier 1 is
    made on the device and re-making it here would discard detections the operator's threat
    exceptions had already admitted.
    """
    subtype = _text(entry, "subtype").casefold()
    return not (subtype and subtype not in LABELLING_SUBTYPES)


def ruleset_id(entry: ET.Element) -> str:
    """What produced this detection *and* what allowed it through, as one identifier.

    The tier-1 counterpart of a snapshot id, and it needs both halves. The content version names
    the signature set; the config version names the firewall configuration — including the threat
    exceptions that constitute tier 1's admission policy. With only the first, two labels from
    the same signatures under materially different exception sets would be indistinguishable, and
    the basis on which a detection was admitted would not be recoverable from the artifact.

    Measured shape: `AppThreat-9136-10199/config-2817`.
    """
    content = _text(entry, "contentver") or "unknown-content"
    config = _text(entry, "config_ver")
    return f"{content}/config-{config}" if config else content


def deduplicate(found: Sequence[Detection]) -> tuple[tuple[Detection, ...], int]:
    """One detection per (signature, 5-tuple), and how many were collapsed.

    **Measured 2026-08-17, and the numbers are the argument.** One replay produced 915 threat
    entries covering 5 distinct signatures over 380 distinct (signature, 5-tuple) pairs. The worst
    single pair appeared **143 times across just 2 firewall sessions** with `repeatcnt` of 1 on
    every one — so PAN-OS was not aggregating, it was logging one signature firing repeatedly
    inside a session.

    Without this, `correlate` would attach all 143 to one flow — it keeps repeated assertions
    deliberately (`test_a_rule_firing_twice_on_one_flow_keeps_both_assertions`) — and because
    `SourceEntry` carries no timestamp, session or count field, those 143 rows would be
    **byte-identical**. That is a 143x bloat of the labels a consumer reads, carrying no
    information at all.

    The count is not thrown away, because "this signature fired 798 times" is a real fact about a
    capture and dropping it silently is the failure mode this project is built to avoid. It is
    returned for the run block, where an input or a measurement belongs, rather than smuggled
    onto a label that has nowhere to put it.

    The earliest occurrence is the survivor. Its timestamp is the closest to the flow's own start,
    which is what `Flow.ts_first` holds and what a mapped timestamp is compared against when a
    5-tuple has to be told apart from another occurrence of itself.
    """
    best: dict[DetectionKey, Detection] = {}
    for d in found:
        key = detection_key(d)
        current = best.get(key)
        if current is None or d.ts < current.ts:
            best[key] = d
    kept = tuple(sorted(best.values(), key=lambda d: (d.ts, d.sid, d.src_ip, d.src_port)))
    return kept, len(found) - len(kept)


#: How a detection is identified for dedup and for looking its ruleset back up.
DetectionKey = tuple[int, str, int, str, int, str]


def detection_key(detection: Detection) -> DetectionKey:
    return (
        detection.sid,
        detection.src_ip,
        detection.src_port,
        detection.dst_ip,
        detection.dst_port,
        detection.proto,
    )


def detections(
    entries: Sequence[ET.Element],
) -> tuple[tuple[Detection, ...], tuple[str, ...], dict[DetectionKey, str]]:
    """Threat-log entries as tier-1 `Detection`s, the declines, and each one's ruleset id.

    Declines are returned rather than dropped, for spec §2.8's reason: a suppressed detection is
    counted, never silent. The caller puts the count in the run block so a consumer can see the
    gate acted and by how much.

    The ruleset mapping exists because `Detection` has no field for it — it describes what the
    *engine observed*, while the ruleset belongs to provenance — and tier 1 reads that identifier
    off each entry rather than once per run (`ruleset_id`). Keyed rather than positional so
    `deduplicate` can reorder and drop entries without the two lists silently drifting apart.
    """
    out: list[Detection] = []
    declined: list[str] = []
    rulesets: dict[DetectionKey, str] = {}
    for entry in entries:
        name = threat_name(entry) or "unnamed"
        if not admits(entry):
            declined.append(
                f"{name}: subtype={_text(entry, 'subtype') or 'none'} is not a signature match "
                f"on a threat"
            )
            continue
        sid = threat_id(entry)
        if sid is None:
            declined.append(f"{name}: no numeric threat id, so it cannot be attributed")
            continue
        detection = _detection(entry, sid, name)
        out.append(detection)
        rulesets.setdefault(detection_key(detection), ruleset_id(entry))
    return tuple(out), tuple(declined), rulesets


def _detection(entry: ET.Element, sid: int, name: str) -> Detection:
    proto = _text(entry, "proto").casefold()
    return Detection(
        # A single logical source, not the device hostname: a label must stay meaningful when
        # the same capture is replayed past a different firewall of the same kind. Which
        # *device* produced it is recorded once in the run block, where it belongs.
        source="panw/threat-prevention",
        tier=TIER,
        sid=sid,
        # PAN-OS does not version signatures individually the way a Suricata rule carries
        # `rev:`. 0 is the same convention `suricata.py` uses for a rule written without one —
        # matching the tool's own semantics rather than inventing a version. The signature set
        # *is* versioned, and that version is the content release recorded on the run.
        rev=0,
        # `thr_category`, NOT `category`. Measured 2026-08-17 against a real response: PAN-OS
        # uses `category` for the *URL* category, which reads `any` on every non-URL threat, and
        # files the threat category under `thr_category` (`info-leak`, `brute-force`,
        # `code-execution`). An earlier version of this module read `category` and published
        # `classtype: "any"` on all 915 detections of a run — well-formed, uniform, and
        # meaningless, in the field a tier-1 admission policy would gate on.
        classtype=_text(entry, "thr_category") or None,
        app_proto=_text(entry, "app") or None,
        threat=name,
        # Replay wall-clock, deliberately. Reading it back as capture time needs
        # `ReplayWindow`, which the caller holds; doing it here would bake a conversion into
        # the record and lose the raw observation.
        ts=_receive_epoch(entry),
        src_ip=_text(entry, "src"),
        src_port=_port(entry, "sport"),
        dst_ip=_text(entry, "dst"),
        dst_port=_port(entry, "dport"),
        proto=PROTO_ALIASES.get(proto, proto),
        direction=_direction(entry),
    )


def _direction(entry: ET.Element) -> Direction:
    """Which way PAN-OS says the offending traffic was going (issue #115's field).

    PAN-OS writes `client-to-server` / `server-to-client`; flabel's vocabulary is Suricata's
    `to_server` / `to_client`. Anything unrecognised becomes `unknown`, which states that the
    direction was not established rather than picking one — the defect #115 exists to prevent.
    """
    raw = _text(entry, "direction").casefold()
    if raw in {"client-to-server", "c2s", "to_server"}:
        return "to_server"
    if raw in {"server-to-client", "s2c", "to_client"}:
        return "to_client"
    return "unknown"


def _receive_epoch(entry: ET.Element) -> float:
    """`receive_time` as a POSIX timestamp.

    Parsed as device-local time, matching how the query filter is written. An unparseable
    value yields 0.0 rather than raising: the timestamp scopes the query and separates repeated
    tuples, so losing it costs a tie-break, while failing the run over it would throw away every
    label in the capture.
    """
    raw = _text(entry, "receive_time")
    for fmt in ("%Y/%m/%d %H:%M:%S", "%Y/%m/%d %H:%M:%S %Z"):
        try:
            return calendar.timegm(time.strptime(raw, fmt))
        except (ValueError, OverflowError):
            continue
    return 0.0


def iter_entries(xml_text: str) -> Iterator[ET.Element]:
    """Threat-log entries out of a recorded API response, for tests and for offline replay.

    The seam that keeps every labelling decision in this module testable without a firewall:
    `tests/test_panw.py` feeds it responses captured from the real device.
    """
    root = ET.fromstring(xml_text)
    yield from root.findall(".//log/logs/entry")


def api_key(host: str, user: str, password: str, *, verify: bool = False) -> str:
    """Exchange a password for a long-lived API key.

    Separate from `PanwDevice` because it is the one call that needs a password, and the point
    of the split is that a run never does. An operator does this once; the key is what the
    pipeline is given.
    """
    url = f"https://{host}/api/?type=keygen"
    data = urllib.parse.urlencode({"user": user, "password": password}).encode()
    context = None
    if not verify:
        import ssl  # noqa: PLC0415

        context = ssl._create_unverified_context()  # noqa: S323

    try:
        with urllib.request.urlopen(
            url, data=data, timeout=HTTP_TIMEOUT_SECONDS, context=context
        ) as r:
            root = ET.fromstring(r.read())
    except Exception as exc:  # noqa: BLE001
        raise ToolError(f"could not obtain an API key from {host}: {exc}") from exc

    key = root.findtext(".//key")
    if root.get("status") != "success" or not key:
        message = "".join(root.itertext()).strip() or "no message"
        raise ToolError(f"{host} declined to issue an API key: {message}")
    return key.strip()


#: How far the device's clock may sit from the replaying host's before the window is untrustworthy.
#:
#: Comfortably inside `WINDOW_PAD_SECONDS`, because the pad is what absorbs a small skew and this
#: is the point at which the pad can no longer be relied on. Measured after pointing both hosts
#: at `metadata.google.internal` and setting the device to UTC: 5 seconds apart. A timezone
#: mismatch shows up here as thousands.
MAX_CLOCK_SKEW_SECONDS = 30


def _clock_epoch(text: str) -> float:
    """PAN-OS `show clock` output as a POSIX timestamp.

    Its format is `Mon Aug 17 22:11:59 UTC 2026`. Parsed as UTC because the device is configured
    to UTC and `ThreatQuery` depends on that; a device in another zone yields a wrong instant
    here, which is precisely what `verify_clock` is meant to catch rather than paper over.
    """
    for line in reversed(text.splitlines()):
        candidate = line.strip()
        if not candidate:
            continue
        for fmt in ("%a %b %d %H:%M:%S %Z %Y", "%a %b %d %H:%M:%S %Y"):
            try:
                parsed = time.strptime(candidate, fmt)
            except ValueError:
                continue
            return calendar.timegm(parsed)
    raise ToolError(f"the device's clock could not be read from {text.strip()[:120]!r}")


def verify_clock(device_ts: float, local_ts: float) -> tuple[bool, str | None]:
    """Whether the device's clock is close enough for the query window to mean anything.

    Returns a warning rather than raising, and the caller decides — but it must not be ignored.
    A skew large enough to shift the window produces **zero rows**, which reads identically to a
    capture containing nothing malicious. That is the one output this project must never produce
    by accident (spec §13), so the condition is named and reported rather than inferred from an
    empty result.
    """
    skew = abs(device_ts - local_ts)
    if skew > MAX_CLOCK_SKEW_SECONDS:
        return False, (
            f"the firewall's clock is {skew:.0f}s from this host's, which is more than the "
            f"{MAX_CLOCK_SKEW_SECONDS}s the padded query window can absorb. A window that misses "
            f"the replay returns no threat logs, which is indistinguishable from a capture with "
            f"nothing malicious in it. Check that both hosts use one NTP source and that the "
            f"device's timezone is UTC."
        )
    return True, None


def counter_delta(before: Mapping[str, int], after: Mapping[str, int]) -> int:
    """How many threat logs the device says it wrote across the replay.

    Summed over the threat subtypes rather than read off one counter, because which counter
    moves depends on which profile fired — measured 2026-08-17, when `Vulnerability logs
    written` went to 13 while `Spyware`, `Attack` and `Anti-virus` all stayed at 0 and an
    earlier version of this check read the wrong name and concluded nothing had been logged.
    """
    names = ("vulnerability", "spyware", "anti-virus", "wildfire anti-virus", "spyware-dns")
    return sum(max(0, after.get(n, 0) - before.get(n, 0)) for n in names)


def loss(retrieved: int, written: int) -> tuple[bool, str | None]:
    """Whether the device wrote threat logs this run did not read.

    The tier-1 loss condition. `written` greater than `retrieved` means labels are missing and
    the output cannot claim to be complete; the reverse is not an error, because the padded
    window can legitimately include a log from before the replay began.
    """
    if written > retrieved:
        return True, (
            f"the firewall wrote {written} threat log(s) but only {retrieved} were retrieved, so "
            f"{written - retrieved} detection(s) are missing from this run"
        )
    return False, None


def declined_note(declined: Sequence[str]) -> str | None:
    """One run-block warning naming what the admission gate refused, or None if it refused none."""
    if not declined:
        return None
    return (
        f"{len(declined)} tier-1 detection(s) were not admitted as labels: "
        + "; ".join(declined[:10])
        + (" ..." if len(declined) > 10 else "")
    )


__all__ = [
    "LABELLING_SUBTYPES",
    "SEVERITY_GATE",
    "MAX_CLOCK_SKEW_SECONDS",
    "TIER",
    "DeviceInfo",
    "PanwDevice",
    "ThreatQuery",
    "admits",
    "api_key",
    "content_version",
    "counter_delta",
    "declined_note",
    "deduplicate",
    "detection_key",
    "detections",
    "iter_entries",
    "loss",
    "parse_system_info",
    "ruleset_id",
    "session_id",
    "threat_id",
    "threat_name",
    "verify_clock",
]
