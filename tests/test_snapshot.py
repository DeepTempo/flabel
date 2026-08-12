"""Ruleset snapshots (docs/spec.md §7).

A snapshot is the unit of reproducibility: `snapshot_id = sha256(rules.rules)[:16]`, so the id
is a claim about content that anyone can re-check. These tests hold that claim to account —
same content means the same id whatever order the feeds arrived in, different content means a
different id, and a snapshot whose bytes no longer hash to its own name is a failure rather
than a fallback.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

import pytest

import flabel
from flabel.errors import SnapshotError
from flabel.models import SourceAdmission
from flabel.rules.snapshot import (
    MANIFEST_NAME,
    RULES_NAME,
    list_snapshots,
    load_snapshot,
    render_rules,
    write_snapshot,
)

CREATED_AT = "2026-08-12T12:00:00.000000Z"


def rule(sid: int) -> str:
    return f'alert ip any any -> any any (msg:"FLABEL TEST {sid}"; sid:{sid}; rev:1;)'


def admission(name: str, admitted: int, *, ja4: int = 0, ja3: int = 0) -> SourceAdmission:
    return SourceAdmission(
        name=name,
        url=f"https://example.invalid/{name}.rules",
        licence="CC0-1.0",
        source_class="ioc-dest",
        admission_basis="wholesale",
        rules_fetched=admitted,
        rules_admitted=admitted,
        rules_excluded_no_confidence=0,
        rules_excluded_low_confidence=0,
        rules_excluded_low_severity=0,
        rules_excluded_commented=0,
        ja4_rules_admitted=ja4,
        ja3_rules_admitted=ja3,
        fetched_at="2026-08-12T11:59:00.000000Z",
    )


def one_source(root: Path, sids: tuple[int, ...] = (1, 2), **kwargs) -> tuple[Path, object]:
    manifest = write_snapshot(
        root,
        {"a/one": [rule(sid) for sid in sids]},
        [admission("a/one", len(sids))],
        **kwargs,
    )
    return root / manifest.snapshot_id, manifest


# --- layout --------------------------------------------------------------------------------


def test_a_snapshot_is_a_directory_named_by_its_own_content_hash(tmp_path: Path):
    directory, manifest = one_source(tmp_path, created_at=CREATED_AT)

    rules_bytes = (directory / RULES_NAME).read_bytes()
    assert directory.name == manifest.snapshot_id
    assert manifest.snapshot_id == hashlib.sha256(rules_bytes).hexdigest()[:16]
    assert len(manifest.snapshot_id) == 16
    assert (directory / MANIFEST_NAME).is_file()


def test_the_raw_feed_is_kept_beside_the_filtered_rules_for_audit(tmp_path: Path):
    """Spec §7 keeps `raw/<source>.rules` as fetched: the filtered file alone cannot show
    what was dropped, and a label's provenance is only checkable against the input."""
    raw_text = f"# as fetched\n{rule(1)}\n#{rule(2)}\n"
    manifest = write_snapshot(
        tmp_path,
        {"abuse.ch/urlhaus": [rule(1)]},
        [admission("abuse.ch/urlhaus", 1)],
        raw={"abuse.ch/urlhaus": raw_text},
        created_at=CREATED_AT,
    )

    # The `/` in a source name becomes a directory, so the parent has to be created.
    written = tmp_path / manifest.snapshot_id / "raw" / "abuse.ch" / "urlhaus.rules"
    assert written.read_text(encoding="utf-8") == raw_text


def test_the_manifest_is_canonical_json_that_round_trips(tmp_path: Path):
    directory, manifest = one_source(tmp_path, created_at=CREATED_AT)
    text = (directory / MANIFEST_NAME).read_text(encoding="utf-8")

    assert text.endswith("\n")
    assert text.index('"created_at"') < text.index('"flabel_version"')  # sort_keys
    document = json.loads(text)
    assert document["snapshot_id"] == manifest.snapshot_id
    assert document["flabel_version"] == flabel.__version__
    assert document["created_at"] == CREATED_AT


def test_the_manifest_totals_are_the_sum_of_its_sources(tmp_path: Path):
    manifest = write_snapshot(
        tmp_path,
        {"a/one": [rule(1)], "b/two": [rule(2), rule(3)]},
        [admission("a/one", 1, ja4=1), admission("b/two", 2, ja4=0, ja3=2)],
        created_at=CREATED_AT,
    )

    assert (manifest.total_admitted, manifest.total_ja4_admitted) == (3, 1)
    assert [source.name for source in manifest.sources] == ["a/one", "b/two"]


# --- the id depends on content, and only on content -----------------------------------------


def test_identical_content_gives_the_identical_id(tmp_path: Path):
    first = one_source(tmp_path / "one")[1]
    second = one_source(tmp_path / "two")[1]

    assert first.snapshot_id == second.snapshot_id


def test_changed_content_gives_a_different_id(tmp_path: Path):
    first = one_source(tmp_path / "one", sids=(1, 2))[1]
    second = one_source(tmp_path / "two", sids=(1, 3))[1]

    assert first.snapshot_id != second.snapshot_id


def test_fetch_order_cannot_change_the_id(tmp_path: Path):
    """The reason `rules.rules` is sorted by (source, sid) at all (spec §7).

    Feeds are fetched over the network, so arrival order varies run to run. If it reached the
    file, two runs over identical rules would produce different snapshot ids and Goal 2 would
    be unachievable.
    """
    forward = write_snapshot(
        tmp_path / "forward",
        {"a/one": [rule(1), rule(9)], "b/two": [rule(2), rule(5)]},
        [admission("a/one", 2), admission("b/two", 2)],
        created_at=CREATED_AT,
    )
    scrambled = write_snapshot(
        tmp_path / "scrambled",
        {"b/two": [rule(5), rule(2)], "a/one": [rule(9), rule(1)]},
        [admission("b/two", 2), admission("a/one", 2)],
        created_at="2026-08-12T23:59:59.999999Z",
    )

    assert forward.snapshot_id == scrambled.snapshot_id


def test_rules_are_written_sorted_by_source_then_sid(tmp_path: Path):
    manifest = write_snapshot(
        tmp_path,
        {"b/two": [rule(5), rule(1)], "a/one": [rule(9), rule(2)]},
        [admission("b/two", 2), admission("a/one", 2)],
        created_at=CREATED_AT,
    )
    written = (tmp_path / manifest.snapshot_id / RULES_NAME).read_text(encoding="utf-8")

    assert [line.split("sid:")[1].split(";")[0] for line in written.splitlines()] == [
        "2",  # a/one
        "9",  # a/one
        "1",  # b/two
        "5",  # b/two
    ]
    assert written.endswith("\n")


def test_a_rule_with_no_sid_still_sorts_deterministically(tmp_path: Path):
    """Every wholesale feed is third-party text; a malformed rule must not make the id vary."""
    lines = ['alert ip any any -> any any (msg:"no sid";)', rule(4)]
    first = write_snapshot(
        tmp_path / "a", {"a/one": lines}, [admission("a/one", 2)], created_at=CREATED_AT
    )
    second = write_snapshot(
        tmp_path / "b",
        {"a/one": list(reversed(lines))},
        [admission("a/one", 2)],
        created_at=CREATED_AT,
    )

    assert first.snapshot_id == second.snapshot_id


def test_render_rules_is_the_bytes_the_id_is_taken_over():
    """Exposed separately so the hash input is inspectable rather than a side effect."""
    rendered = render_rules({"a/one": [rule(2), rule(1)]})

    assert rendered == f"{rule(1)}\n{rule(2)}\n".encode()


# --- immutability ---------------------------------------------------------------------------


def test_rewriting_identical_content_is_idempotent(tmp_path: Path):
    """Spec §7 calls snapshots immutable, so a re-fetch that changed nothing changes nothing.

    The stored manifest is returned as it stands — its `created_at` still records when this
    ruleset first existed, which is what a label pointing at the id needs to mean.
    """
    first = one_source(tmp_path, created_at=CREATED_AT)[1]
    second = one_source(tmp_path, created_at="2026-09-01T00:00:00.000000Z")[1]

    assert second == first
    assert [path.name for path in tmp_path.iterdir()] == [first.snapshot_id]


def test_a_snapshot_directory_whose_rules_were_edited_is_never_reused(tmp_path: Path):
    """The id is a hash of the file, so disagreement means the directory is not what it says.

    Checked on the *write* path too, not only on load: silently adopting the edited directory
    would attach a trusted id to rules nobody admitted.
    """
    directory, _ = one_source(tmp_path, created_at=CREATED_AT)
    (directory / RULES_NAME).write_text(f"{rule(99)}\n", encoding="utf-8")

    with pytest.raises(SnapshotError, match="modified"):
        one_source(tmp_path, created_at=CREATED_AT)


# --- consistency between the rules and the counts that describe them ------------------------


def test_a_source_with_rules_but_no_admission_is_rejected(tmp_path: Path):
    with pytest.raises(SnapshotError, match="b/two"):
        write_snapshot(tmp_path, {"a/one": [rule(1)], "b/two": [rule(2)]}, [admission("a/one", 1)])


def test_an_admission_with_no_rules_entry_is_rejected(tmp_path: Path):
    """A source counted in the manifest but absent from `rules.rules` would overstate the
    snapshot: `total_admitted` would promise coverage the file does not contain."""
    with pytest.raises(SnapshotError, match="b/two"):
        write_snapshot(
            tmp_path, {"a/one": [rule(1)]}, [admission("a/one", 1), admission("b/two", 1)]
        )


def test_an_admission_count_that_disagrees_with_the_rules_is_rejected(tmp_path: Path):
    with pytest.raises(SnapshotError, match="rules_admitted"):
        write_snapshot(tmp_path, {"a/one": [rule(1)]}, [admission("a/one", 7)])


def test_a_duplicate_admission_is_rejected(tmp_path: Path):
    with pytest.raises(SnapshotError, match="duplicate"):
        write_snapshot(
            tmp_path, {"a/one": [rule(1)]}, [admission("a/one", 1), admission("a/one", 1)]
        )


def test_a_snapshot_with_no_rules_at_all_is_rejected(tmp_path: Path):
    """An empty snapshot would load into Suricata cleanly and label nothing — the exact
    silent-failure shape spec §2.5 forbids."""
    with pytest.raises(SnapshotError, match="no rules"):
        write_snapshot(tmp_path, {}, [])


# --- loading --------------------------------------------------------------------------------


def test_load_snapshot_returns_the_directory_and_the_manifest(tmp_path: Path):
    directory, written = one_source(tmp_path, created_at=CREATED_AT)

    loaded_directory, loaded = load_snapshot(tmp_path, written.snapshot_id)

    assert loaded_directory == directory
    assert loaded == written
    assert isinstance(loaded.sources[0], SourceAdmission)


def test_load_snapshot_with_no_id_returns_the_newest(tmp_path: Path):
    older = one_source(tmp_path, sids=(1, 2), created_at="2026-08-01T00:00:00.000000Z")[1]
    newer = one_source(tmp_path, sids=(3, 4), created_at="2026-08-11T00:00:00.000000Z")[1]

    _, loaded = load_snapshot(tmp_path, None)

    assert loaded.snapshot_id == newer.snapshot_id != older.snapshot_id


def test_a_missing_snapshot_is_a_hard_failure(tmp_path: Path):
    """Never a fallback to another snapshot: labels are only reproducible against a known
    ruleset, so substituting a different one would break the guarantee the id exists for."""
    one_source(tmp_path, created_at=CREATED_AT)

    with pytest.raises(SnapshotError, match="deadbeefdeadbeef"):
        load_snapshot(tmp_path, "deadbeefdeadbeef")


@pytest.mark.parametrize(
    "requested",
    ["nonexistent", "../../etc", "ABCDEF0123456789", "abc"],
    ids=["spec-§11-fault-injection", "traversal", "uppercase", "too-short"],
)
def test_something_that_is_not_a_snapshot_id_is_rejected_without_being_joined(
    tmp_path: Path, requested: str
):
    """`--ruleset-snapshot` arrives from the command line and becomes a path component.

    Spec §11 injects exactly `--ruleset-snapshot nonexistent` and expects a hard failure; the
    shape check also means a typo is reported as a typo instead of as a missing snapshot.
    """
    one_source(tmp_path, created_at=CREATED_AT)

    with pytest.raises(SnapshotError, match="snapshot id"):
        load_snapshot(tmp_path, requested)


def test_an_empty_or_absent_rules_directory_is_a_hard_failure(tmp_path: Path):
    with pytest.raises(SnapshotError):
        load_snapshot(tmp_path, None)
    with pytest.raises(SnapshotError):
        load_snapshot(tmp_path / "never-created", None)


def test_a_snapshot_missing_its_rules_file_is_a_hard_failure(tmp_path: Path):
    directory, manifest = one_source(tmp_path, created_at=CREATED_AT)
    (directory / RULES_NAME).unlink()

    with pytest.raises(SnapshotError, match=RULES_NAME):
        load_snapshot(tmp_path, manifest.snapshot_id)


def test_a_tampered_snapshot_is_a_hard_failure_on_load(tmp_path: Path):
    """Self-verifying, as spec §7 says: the id is checked against the bytes on every load,
    so a rule added by hand after the fact cannot quietly produce labels."""
    directory, manifest = one_source(tmp_path, created_at=CREATED_AT)
    with (directory / RULES_NAME).open("a", encoding="utf-8") as handle:
        handle.write(f"{rule(1337)}\n")

    with pytest.raises(SnapshotError, match="modified"):
        load_snapshot(tmp_path, manifest.snapshot_id)


@pytest.mark.parametrize(
    "content",
    ["not json at all", "[]", "{}", '{"snapshot_id": "x", "surprise": 1}'],
    ids=["unparseable", "not-an-object", "empty-object", "unknown-field"],
)
def test_an_unreadable_manifest_is_a_hard_failure(tmp_path: Path, content: str):
    directory, manifest = one_source(tmp_path, created_at=CREATED_AT)
    (directory / MANIFEST_NAME).write_text(content, encoding="utf-8")

    with pytest.raises(SnapshotError):
        load_snapshot(tmp_path, manifest.snapshot_id)


def test_a_manifest_whose_counts_disagree_with_the_rules_is_a_hard_failure(tmp_path: Path):
    """The hash proves the rules were not edited; this proves the counts were not either.

    A run copies `total_admitted` straight into `labels.json`, so an edited manifest would
    misreport how much of the ruleset was in play for those labels.
    """
    directory, manifest = one_source(tmp_path, created_at=CREATED_AT)
    document = json.loads((directory / MANIFEST_NAME).read_text(encoding="utf-8"))
    document["total_admitted"] = 999
    (directory / MANIFEST_NAME).write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SnapshotError, match="total_admitted"):
        load_snapshot(tmp_path, manifest.snapshot_id)


def test_a_manifest_whose_id_disagrees_with_its_directory_is_a_hard_failure(tmp_path: Path):
    directory, manifest = one_source(tmp_path, created_at=CREATED_AT)
    document = json.loads((directory / MANIFEST_NAME).read_text(encoding="utf-8"))
    document["snapshot_id"] = "0" * 16
    (directory / MANIFEST_NAME).write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SnapshotError):
        load_snapshot(tmp_path, manifest.snapshot_id)


# --- listing --------------------------------------------------------------------------------


def test_list_snapshots_is_chronological(tmp_path: Path):
    older = one_source(tmp_path, sids=(1, 2), created_at="2026-08-01T00:00:00.000000Z")[1]
    newer = one_source(tmp_path, sids=(3, 4), created_at="2026-08-11T00:00:00.000000Z")[1]

    assert [entry.snapshot_id for entry in list_snapshots(tmp_path)] == [
        older.snapshot_id,
        newer.snapshot_id,
    ]


def test_list_snapshots_ignores_things_that_are_not_snapshots(tmp_path: Path):
    manifest = one_source(tmp_path, created_at=CREATED_AT)[1]
    (tmp_path / "scratch-dir").mkdir()
    (tmp_path / "notes.txt").write_text("hello", encoding="utf-8")

    assert [entry.snapshot_id for entry in list_snapshots(tmp_path)] == [manifest.snapshot_id]


def test_list_snapshots_on_an_absent_directory_is_empty_not_an_error(tmp_path: Path):
    """`flabel rules list` before the first `rules update` is a normal thing to run."""
    assert list_snapshots(tmp_path / "never-created") == []
