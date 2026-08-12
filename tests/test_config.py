"""The source registry and its validation (spec §5).

The registry decides which feeds can assert a label and on what basis, so the authoritative
table from spec §5 is reproduced here as the expectation. If the shipped `sources.toml` and
this table ever disagree, that is the bug — a wrong `source_class` silently changes what a
label means, and `identify` getting it wrong would let a label be emitted that must never be.
"""

from __future__ import annotations

import pytest

from flabel.config import load_sources
from flabel.errors import ConfigError

#: Spec §5, "Authoritative class assignments". name -> (licence, class, admission_basis)
AUTHORITATIVE = {
    "et/open": ("MIT", "signature", "metadata-filter"),
    "stamus/lateral": ("GPL-3.0-only", "signature", "wholesale"),
    "malsilo/win-malware": ("MIT", "signature", "wholesale"),
    "the-hunters-ledger/open": ("CC-BY-4.0", "signature", "wholesale"),
    "pawpatrules": ("CC-BY-SA-4.0", "signature", "wholesale"),
    "abuse.ch/feodotracker": ("CC0-1.0", "ioc-dest", "wholesale"),
    "abuse.ch/sslbl-c2": ("CC0-1.0", "ioc-dest", "wholesale"),
    "sslbl/ssl-fp-blacklist": ("CC0-1.0", "ioc-dest", "wholesale"),
    "abuse.ch/urlhaus": ("CC0-1.0", "ioc-name", "wholesale"),
    "oisf/trafficid": ("MIT", "identify", "wholesale"),
}

#: Spec §5: "Excluded entirely and absent from the registry".
EXCLUDED = (
    "tgreen/hunting",
    "etnetera/aggressive",
    "ptresearch/attackdetection",
    "ptrules/open",
    "sslbl/ja3-fingerprints",
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


def test_the_packaged_registry_holds_exactly_the_ten_admitted_sources():
    names = {spec.name for spec in load_sources()}
    assert names == set(AUTHORITATIVE)


def test_the_packaged_registry_matches_the_authoritative_table():
    for spec in load_sources():
        expected = AUTHORITATIVE[spec.name]
        assert (spec.licence, spec.source_class, spec.admission_basis) == expected, spec.name


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


def test_every_source_has_a_stated_licence():
    """Rule text is reproduced in output, so a source with no licence cannot be shipped."""
    for spec in load_sources():
        assert spec.licence and spec.licence != "unstated", spec.name


def test_every_url_is_https():
    """Rules become labels; fetching them over plaintext would make that trivially forgeable."""
    for spec in load_sources():
        assert spec.url.startswith("https://"), f"{spec.name}: {spec.url}"


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
