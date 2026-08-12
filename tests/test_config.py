"""The source registry and its validation (spec §5).

The registry decides which feeds can assert a label and on what basis, so the authoritative
table from spec §5 is reproduced here as the expectation. If the shipped `sources.toml` and
this table ever disagree, that is the bug — a wrong `source_class` silently changes what a
label means, and `identify` getting it wrong would let a label be emitted that must never be.
"""

from __future__ import annotations

from collections import namedtuple

import pytest

from flabel.config import enabled_sources, load_sources
from flabel.errors import ConfigError

#: Spec §5's authoritative assignments, with the URL pinned too.
#:
#: The URL is here because `abuse.ch/sslbl-c2` and `sslbl/ssl-fp-blacklist` were two feeds from
#: one vendor with identical licence, class and basis — indistinguishable to every other check.
#: Swapping their URLs would have attributed real detections to the wrong feed with nothing in
#: the output to reveal it (spec §13: never emit a label whose origin can't be traced).
SourceRow = namedtuple("SourceRow", "licence source_class admission_basis url")

AUTHORITATIVE = {
    "et/open": SourceRow("MIT", "signature", "metadata-filter", "https://rules.emergingthreats.net/open/suricata-8.0/emerging.rules.tar.gz"),
    "stamus/lateral": SourceRow("GPL-3.0-only", "signature", "wholesale", "https://ti.stamus-networks.io/open/stamus-lateral-rules.tar.gz"),
    "malsilo/win-malware": SourceRow("MIT", "signature", "wholesale", "https://malsilo.gitlab.io/feeds/dumps/malsilo.rules.tar.gz"),
    "the-hunters-ledger/open": SourceRow("CC-BY-4.0", "signature", "wholesale", "https://the-hunters-ledger.com/feeds/suricata/hunters-ledger.rules"),
    "pawpatrules": SourceRow("CC-BY-SA-4.0", "signature", "wholesale", "https://rules.pawpatrules.fr/suricata/paw-patrules.tar.gz"),
    "abuse.ch/feodotracker": SourceRow("CC0-1.0", "ioc-dest", "wholesale", "https://feodotracker.abuse.ch/downloads/feodotracker.tar.gz"),
    "abuse.ch/sslbl-blacklist": SourceRow("CC0-1.0", "ioc-dest", "wholesale", "https://sslbl.abuse.ch/blacklist/sslblacklist_tls_cert.tar.gz"),
    "abuse.ch/urlhaus": SourceRow("CC0-1.0", "ioc-name", "wholesale", "https://urlhaus.abuse.ch/downloads/urlhaus_suricata.tar.gz"),
    "oisf/trafficid": SourceRow("MIT", "identify", "wholesale", "https://openinfosecfoundation.org/rules/trafficid/trafficid.rules"),
}

#: Spec §5: "Excluded entirely and absent from the registry".
EXCLUDED = (
    "tgreen/hunting",
    "etnetera/aggressive",
    "ptresearch/attackdetection",
    "ptrules/open",
    "sslbl/ja3-fingerprints",
    # Removed in step 2: deprecated by abuse.ch on 2025-01-03 and shipping zero rules.
    "abuse.ch/sslbl-c2",
    # Deprecated alias, renamed upstream to abuse.ch/sslbl-blacklist.
    "sslbl/ssl-fp-blacklist",
)


def write_registry(tmp_path, body: str):
    path = tmp_path / "sources.toml"
    path.write_text(body)
    return path


VALID_ENTRY = """
[[source]]
name             = "et/open"
url              = "https://example.invalid/emerging.rules.tar.gz"
licence          = "MIT"
source_class     = "signature"
admission_basis  = "metadata-filter"
"""


def test_the_packaged_registry_holds_exactly_the_admitted_sources():
    names = {spec.name for spec in load_sources()}
    assert names == set(AUTHORITATIVE)


def test_the_packaged_registry_matches_the_authoritative_table():
    for spec in load_sources():
        row = AUTHORITATIVE[spec.name]
        assert (spec.licence, spec.source_class, spec.admission_basis, spec.url) == row, spec.name


@pytest.mark.parametrize("name", EXCLUDED)
def test_excluded_sources_are_absent(name):
    """These were ruled out in research; their absence is a decision, not an oversight."""
    assert name not in {spec.name for spec in load_sources()}


def test_only_trafficid_is_barred_from_labelling():
    barred = {spec.name for spec in load_sources() if not spec.may_label}
    assert barred == {"oisf/trafficid"}


def test_only_urlhaus_labels_by_indicator_reference():
    references = {spec.name for spec in load_sources() if spec.label_basis == "indicator-reference"}
    assert references == {"abuse.ch/urlhaus"}


def test_every_shipped_source_has_a_stated_licence():
    """Rule text is reproduced in output, so a source with no licence cannot be shipped."""
    for spec in load_sources():
        assert spec.licence and spec.licence != "unstated", spec.name


def test_every_shipped_url_is_https():
    """A property of the shipped file. The loader guard is asserted separately below."""
    for spec in load_sources():
        assert spec.url.startswith("https://"), f"{spec.name}: {spec.url}"


@pytest.mark.parametrize(
    "url",
    [
        "http://rules.example.com/emerging.rules.tar.gz",
        "file:///etc/passwd",
        "ftp://rules.example.com/rules.tar.gz",
        "rules.example.com/rules.tar.gz",
    ],
)
def test_a_non_https_url_is_a_hard_failure(tmp_path, url):
    """Rules are the trust root of every label.

    Over `http://` they are forgeable in transit; `file://` would turn an arbitrary local
    file into label evidence. Neither may be merely discouraged.
    """
    path = write_registry(
        tmp_path, VALID_ENTRY.replace("https://example.invalid/emerging.rules.tar.gz", url)
    )
    with pytest.raises(ConfigError, match="HTTPS"):
        load_sources(path)


@pytest.mark.parametrize(
    "name",
    [
        "../../../../home/craig/.ssh/authorized_keys",
        "vendor/../../escape",
        "vendor/feed/extra",
        "Vendor/Feed",
        "vendor feed",
        "/absolute/feed",
    ],
)
def test_a_source_name_that_could_escape_a_directory_is_a_hard_failure(tmp_path, name):
    """The name becomes `raw/<source>.rules` in a snapshot (spec §7).

    Step 4 builds that path from this string, so traversal has to be impossible here rather
    than remembered there.
    """
    path = write_registry(tmp_path, VALID_ENTRY.replace('"et/open"', f'"{name}"'))
    with pytest.raises(ConfigError, match="source name"):
        load_sources(path)


@pytest.mark.parametrize("field", ["name", "url", "licence"])
def test_a_non_string_field_is_a_hard_failure(tmp_path, field):
    """A TOML integer reaching a `str` field would otherwise surface later, as a sort crash."""
    body = "\n".join(
        f"{field:16} = 123" if line.strip().startswith(field) else line
        for line in VALID_ENTRY.splitlines()
    )
    path = write_registry(tmp_path, body)
    with pytest.raises(ConfigError, match=field):
        load_sources(path)


def test_an_empty_licence_is_a_hard_failure(tmp_path):
    path = write_registry(tmp_path, VALID_ENTRY.replace('"MIT"', '"   "'))
    with pytest.raises(ConfigError, match="licence"):
        load_sources(path)


def test_a_single_source_table_names_the_actual_mistake(tmp_path):
    """`[source]` instead of `[[source]]` is the likely typo; say so, don't talk about types."""
    path = write_registry(tmp_path, VALID_ENTRY.replace("[[source]]", "[source]"))
    with pytest.raises(ConfigError, match=r"\[\[source\]\]"):
        load_sources(path)


def test_a_non_table_source_value_is_a_hard_failure(tmp_path):
    """`source = 5` must be a rejection, not a TypeError traceback."""
    path = write_registry(tmp_path, "source = 5\n")
    with pytest.raises(ConfigError):
        load_sources(path)


def test_a_byte_order_mark_does_not_break_parsing(tmp_path):
    """A registry saved by a Windows editor should load, not fail on an invisible character."""
    path = tmp_path / "sources.toml"
    path.write_bytes(b"\xef\xbb\xbf" + VALID_ENTRY.encode("utf-8"))
    (spec,) = load_sources(path)
    assert spec.name == "et/open"


def test_names_differing_only_in_case_are_a_hard_failure(tmp_path):
    """They would collide as `raw/<source>.rules` on a case-insensitive filesystem."""
    body = VALID_ENTRY + VALID_ENTRY.replace('"et/open"', '"ET/Open"').replace(
        "metadata-filter", "wholesale"
    )
    with pytest.raises(ConfigError, match="source name"):
        load_sources(write_registry(tmp_path, body))


def test_a_misspelled_key_reports_both_the_missing_and_the_unknown_field(tmp_path):
    """One typo causes two symptoms; reporting one sends the reader after the wrong thing."""
    path = write_registry(tmp_path, VALID_ENTRY.replace("licence  ", "license  "))
    with pytest.raises(ConfigError) as caught:
        load_sources(path)
    assert "missing licence" in str(caught.value)
    assert "license" in str(caught.value)


def test_enabled_sources_excludes_the_disabled_ones(tmp_path):
    """Callers should not have to remember to filter, or a switched-off feed still labels."""
    body = (
        VALID_ENTRY
        + VALID_ENTRY.replace('"et/open"', '"pawpatrules"')
        .replace("metadata-filter", "wholesale")
        .rstrip()
        + "\nenabled = false\n"
    )
    path = write_registry(tmp_path, body)

    assert {spec.name for spec in load_sources(path)} == {"et/open", "pawpatrules"}
    assert {spec.name for spec in enabled_sources(path)} == {"et/open"}


def test_unknown_source_class_is_a_hard_failure(tmp_path):
    path = write_registry(tmp_path, VALID_ENTRY.replace("signature", "signeture"))
    with pytest.raises(ConfigError, match="source_class"):
        load_sources(path)


def test_unknown_admission_basis_is_a_hard_failure(tmp_path):
    path = write_registry(tmp_path, VALID_ENTRY.replace("metadata-filter", "vibes"))
    with pytest.raises(ConfigError, match="admission_basis"):
        load_sources(path)


def test_metadata_filter_on_a_source_without_et_metadata_is_a_hard_failure(tmp_path):
    """`confidence`/`signature_severity` only exist in ET-derived rules.

    Filtering on metadata a source doesn't carry would silently admit nothing, which looks
    identical to a source that legitimately matched nothing.
    """
    path = write_registry(tmp_path, VALID_ENTRY.replace('"et/open"', '"pawpatrules"'))
    with pytest.raises(ConfigError, match="metadata"):
        load_sources(path)


def test_a_missing_required_field_is_a_hard_failure(tmp_path):
    path = write_registry(tmp_path, VALID_ENTRY.replace('licence          = "MIT"\n', ""))
    with pytest.raises(ConfigError, match="licence"):
        load_sources(path)


def test_an_unknown_field_is_a_hard_failure(tmp_path):
    """A typo'd key must not be silently ignored — it would read as a working setting."""
    path = write_registry(tmp_path, VALID_ENTRY + "\nenabledd = true\n")
    with pytest.raises(ConfigError, match="enabledd"):
        load_sources(path)


def test_a_duplicate_source_name_is_a_hard_failure(tmp_path):
    path = write_registry(tmp_path, VALID_ENTRY + VALID_ENTRY)
    with pytest.raises(ConfigError, match="duplicate"):
        load_sources(path)


def test_an_empty_registry_is_a_hard_failure(tmp_path):
    path = write_registry(tmp_path, "")
    with pytest.raises(ConfigError, match="no sources"):
        load_sources(path)


def test_a_missing_registry_file_is_a_hard_failure(tmp_path):
    with pytest.raises(ConfigError, match="not found"):
        load_sources(tmp_path / "absent.toml")


def test_malformed_toml_is_a_hard_failure(tmp_path):
    path = write_registry(tmp_path, "[[source]\nname = ")
    with pytest.raises(ConfigError, match="parse"):
        load_sources(path)


def test_disabled_sources_are_loaded_but_marked(tmp_path):
    """Disabling is recorded rather than erased, so provenance can say what was skipped."""
    path = write_registry(tmp_path, VALID_ENTRY + "enabled = false\n")
    (spec,) = load_sources(path)
    assert spec.enabled is False


def test_loaded_sources_are_sorted_by_name():
    """Deterministic order, so anything derived from the registry is reproducible."""
    names = [spec.name for spec in load_sources()]
    assert names == sorted(names)
