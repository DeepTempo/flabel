"""Ruleset snapshots (docs/spec.md §7).

A snapshot is the unit of reproducibility, and `snapshot_id` is a hash over its content that
anyone can recompute. These tests hold that claim to account — the same content means the same
id whatever order the feeds arrived in, different content (rules, sid index, *or* a companion
data file) means a different id, and a snapshot whose bytes no longer hash to its own name is a
failure rather than a fallback.

`recompute_id` below implements the documented digest independently of the module, so the id is
checked against the algorithm rather than against whatever the code happens to produce.
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
    DATA_DIR,
    MANIFEST_NAME,
    MANIFEST_VERSION,
    RULES_NAME,
    SID_INDEX_NAME,
    list_snapshots,
    load_sid_index,
    load_snapshot,
    render_rules,
    render_sid_index,
    write_snapshot,
)

CREATED_AT = "2026-08-12T12:00:00.000000Z"


def recompute_id(components: dict[str, bytes]) -> str:
    """The digest as `snapshot_id_for` documents it, written out again here.

    Deliberately a second implementation: if both are changed together the change was
    deliberate, and if only one is, the algorithm silently drifted.
    """
    digest = hashlib.sha256()
    for path in sorted(components):
        digest.update(path.encode("utf-8"))
        digest.update(b"\x00")
        digest.update(len(components[path]).to_bytes(8, "big"))
        digest.update(components[path])
    return digest.hexdigest()[:16]


def hashed_files(directory: Path) -> dict[str, bytes]:
    """Every file in a snapshot that the id covers — `raw/` excluded, by design."""
    components = {name: (directory / name).read_bytes() for name in (RULES_NAME, SID_INDEX_NAME)}
    for path in (
        sorted((directory / DATA_DIR).rglob("*")) if (directory / DATA_DIR).is_dir() else []
    ):
        if path.is_file():
            components[path.relative_to(directory).as_posix()] = path.read_bytes()
    return components


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

    assert directory.name == manifest.snapshot_id
    assert manifest.snapshot_id == recompute_id(hashed_files(directory))
    assert len(manifest.snapshot_id) == 16
    assert (directory / MANIFEST_NAME).is_file()
    assert (directory / SID_INDEX_NAME).is_file()


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


# --- the sid index: which source raised sid N ------------------------------------------------


def test_the_snapshot_records_which_source_each_sid_came_from(tmp_path: Path):
    """Spec §8 resolves an alert's source "from the snapshot manifest", and per-source counts
    cannot do that: `eve.json` carries a signature id and no source.

    Kept as a hashed file rather than a field on `SourceAdmission`, because step 8 copies that
    struct into every `labels.json` and 21,221 integers per source do not belong in every
    output file.
    """
    manifest = write_snapshot(
        tmp_path,
        {"et/open": [rule(2000001), rule(2000002)], "pawpatrules": [rule(3300303)]},
        [admission("et/open", 2), admission("pawpatrules", 1)],
        created_at=CREATED_AT,
    )
    directory = tmp_path / manifest.snapshot_id

    assert json.loads((directory / SID_INDEX_NAME).read_text(encoding="utf-8")) == {
        "schema": 1,
        "sources": {"et/open": [2000001, 2000002], "pawpatrules": [3300303]},
    }
    assert load_sid_index(directory) == {
        2000001: "et/open",
        2000002: "et/open",
        3300303: "pawpatrules",
    }


def test_the_sid_index_is_inside_the_snapshot_id(tmp_path: Path):
    """Otherwise the file every label's `source` resolves through is unhashed and editable.

    Deriving the source from `raw/*.rules` filenames instead would be exactly that: attribution
    resting on a directory listing nothing verifies.
    """
    directory, manifest = one_source(tmp_path, created_at=CREATED_AT)

    index = json.loads((directory / SID_INDEX_NAME).read_text(encoding="utf-8"))
    index["sources"] = {"attacker/feed": index["sources"]["a/one"]}
    (directory / SID_INDEX_NAME).write_text(json.dumps(index), encoding="utf-8")

    with pytest.raises(SnapshotError, match="modified"):
        load_snapshot(tmp_path, manifest.snapshot_id)


def test_a_sid_claimed_by_two_sources_is_a_hard_failure(tmp_path: Path):
    """Suricata keeps one rule and drops the other silently, so a label would name the source
    that did not fire.

    Measured 2026-08-12: 116,208 distinct sids across all nine live feeds, zero collisions —
    so this costs nothing today and catches the day a feed renumbers.
    """
    with pytest.raises(SnapshotError, match="claimed by more than one source"):
        write_snapshot(
            tmp_path,
            {"a/one": [rule(4242)], "b/two": [rule(4242)]},
            [admission("a/one", 1), admission("b/two", 1)],
            created_at=CREATED_AT,
        )


def test_one_source_repeating_a_sid_is_a_hard_failure(tmp_path: Path):
    """`rules_admitted` would otherwise overstate the ruleset Suricata actually loaded."""
    variants = [rule(7), rule(7).replace("rev:1", "rev:2")]

    with pytest.raises(SnapshotError, match="more than once"):
        write_snapshot(
            tmp_path, {"a/one": variants}, [admission("a/one", 2)], created_at=CREATED_AT
        )


def test_a_rule_with_no_sid_is_refused(tmp_path: Path):
    """It could not be attributed to a source in a label, and Suricata will not load it."""
    with pytest.raises(SnapshotError, match="no `sid`"):
        write_snapshot(
            tmp_path,
            {"a/one": ['alert ip any any -> any any (msg:"no sid";)']},
            [admission("a/one", 1)],
            created_at=CREATED_AT,
        )


def test_the_sid_index_is_sorted_so_it_cannot_depend_on_fetch_order():
    forward = render_sid_index({"a/one": [rule(9), rule(1)]})
    backward = render_sid_index({"a/one": [rule(1), rule(9)]})

    assert forward == backward
    assert json.loads(forward)["sources"]["a/one"] == [1, 9]


@pytest.mark.parametrize(
    "document",
    [
        {"sources": {"a/one": [1]}},
        {"schema": 2, "sources": {"a/one": [1]}},
        {"schema": 1},
        {"schema": 1, "sources": {"a/one": "1"}},
        {"schema": 1, "sources": {"a/one": [True]}},
        {"schema": 1, "sources": {"a/one": [1], "b/two": [1]}},
    ],
    ids=["no-schema", "future-schema", "no-sources", "not-a-list", "bool-not-int", "collision"],
)
def test_an_unusable_sid_index_is_a_hard_failure(tmp_path: Path, document: dict):
    directory, _ = one_source(tmp_path, created_at=CREATED_AT)
    (directory / SID_INDEX_NAME).write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SnapshotError):
        load_sid_index(directory)


def test_a_snapshot_without_a_sid_index_cannot_attribute_anything(tmp_path: Path):
    directory, _ = one_source(tmp_path, created_at=CREATED_AT)
    (directory / SID_INDEX_NAME).unlink()

    with pytest.raises(SnapshotError, match=SID_INDEX_NAME):
        load_sid_index(directory)


# --- companion data files --------------------------------------------------------------------


def test_companion_data_files_are_written_and_hashed(tmp_path: Path):
    """Craig's call: `snapshot_id` covers the rules *and* the data they read.

    `pawpatrules` ships 18 `.lst` files that 26 of its rules read with `dataset:`. A snapshot
    whose data file changed underneath it matches different traffic while its rule text is
    byte-identical, so a snapshot id that ignored them would promise reproducibility it cannot
    deliver.
    """
    data = {"pawpatrules": {"pawpatrules_tor.lst": b"ZXhhbXBsZS5pbnZhbGlk\n"}}
    first = write_snapshot(
        tmp_path / "a",
        {"pawpatrules": [rule(3300303)]},
        [admission("pawpatrules", 1)],
        data=data,
        created_at=CREATED_AT,
    )
    written = tmp_path / "a" / first.snapshot_id / DATA_DIR / "pawpatrules" / "pawpatrules_tor.lst"
    assert written.read_bytes() == b"ZXhhbXBsZS5pbnZhbGlk\n"

    changed = write_snapshot(
        tmp_path / "b",
        {"pawpatrules": [rule(3300303)]},
        [admission("pawpatrules", 1)],
        data={"pawpatrules": {"pawpatrules_tor.lst": b"ZGlmZmVyZW50\n"}},
        created_at=CREATED_AT,
    )
    assert changed.snapshot_id != first.snapshot_id

    without = write_snapshot(
        tmp_path / "c",
        {"pawpatrules": [rule(3300303)]},
        [admission("pawpatrules", 1)],
        created_at=CREATED_AT,
    )
    assert without.snapshot_id not in (first.snapshot_id, changed.snapshot_id)


def test_renaming_a_data_file_changes_the_id(tmp_path: Path):
    """Which file a `dataset:` option loads is decided by its *name*, so the name is hashed.

    Content-only hashing would let `tor.lst` and `nrd.lst` swap places — changing what every
    rule reading them matches — without the id moving.
    """
    content = b"example.invalid\n"
    left = write_snapshot(
        tmp_path / "a",
        {"pawpatrules": [rule(1)]},
        [admission("pawpatrules", 1)],
        data={"pawpatrules": {"tor.lst": content}},
        created_at=CREATED_AT,
    )
    right = write_snapshot(
        tmp_path / "b",
        {"pawpatrules": [rule(1)]},
        [admission("pawpatrules", 1)],
        data={"pawpatrules": {"nrd.lst": content}},
        created_at=CREATED_AT,
    )

    assert left.snapshot_id != right.snapshot_id


def test_editing_a_data_file_in_place_is_detected_on_load(tmp_path: Path):
    manifest = write_snapshot(
        tmp_path,
        {"pawpatrules": [rule(1)]},
        [admission("pawpatrules", 1)],
        data={"pawpatrules": {"tor.lst": b"example.invalid\n"}},
        created_at=CREATED_AT,
    )
    edited = tmp_path / manifest.snapshot_id / DATA_DIR / "pawpatrules" / "tor.lst"
    edited.write_bytes(b"attacker.invalid\n")

    with pytest.raises(SnapshotError, match="modified"):
        load_snapshot(tmp_path, manifest.snapshot_id)


@pytest.mark.parametrize(
    "name",
    ["../escape.lst", "sub/dir.lst", ".hidden", "", "a b.lst"],
    ids=["traversal", "separator", "dotfile", "empty", "space"],
)
def test_a_data_file_name_that_is_not_a_plain_name_is_refused(tmp_path: Path, name: str):
    """Names come from a third-party archive and become path components under `data/`."""
    with pytest.raises(SnapshotError, match="plain file name"):
        write_snapshot(
            tmp_path,
            {"a/one": [rule(1)]},
            [admission("a/one", 1)],
            data={"a/one": {name: b"x"}},
            created_at=CREATED_AT,
        )


def test_data_for_a_source_with_no_rules_is_refused(tmp_path: Path):
    with pytest.raises(SnapshotError, match="contributes no rules"):
        write_snapshot(
            tmp_path,
            {"a/one": [rule(1)]},
            [admission("a/one", 1)],
            data={"b/two": {"x.lst": b"x"}},
            created_at=CREATED_AT,
        )


def test_the_manifest_is_canonical_json_that_round_trips(tmp_path: Path):
    directory, manifest = one_source(tmp_path, created_at=CREATED_AT)
    text = (directory / MANIFEST_NAME).read_text(encoding="utf-8")

    assert text.endswith("\n")
    assert text.index('"created_at"') < text.index('"flabel_version"')  # sort_keys
    document = json.loads(text)
    assert document["snapshot_id"] == manifest.snapshot_id
    assert document["flabel_version"] == flabel.__version__
    assert document["created_at"] == CREATED_AT
    assert document["manifest_version"] == MANIFEST_VERSION


def test_the_manifest_carries_a_format_version_so_a_field_can_ever_be_added(tmp_path: Path):
    """`_read_manifest` refuses a key it does not recognise — right for provenance, but it means
    the format could never change without every existing snapshot becoming unreadable garbage
    rather than "written by an older flabel". The version is what makes that distinguishable."""
    directory, manifest = one_source(tmp_path, created_at=CREATED_AT)
    document = json.loads((directory / MANIFEST_NAME).read_text(encoding="utf-8"))
    document["manifest_version"] = MANIFEST_VERSION + 1
    (directory / MANIFEST_NAME).write_text(json.dumps(document), encoding="utf-8")

    with pytest.raises(SnapshotError, match="manifest_version"):
        load_snapshot(tmp_path, manifest.snapshot_id)


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


def test_two_rules_sharing_a_sid_across_sources_still_order_deterministically():
    """Every wholesale feed is third-party text, so the sort must be total even where the write
    path would refuse the input: sid is the second key and the rule text the third."""
    left = render_rules({"a/one": [rule(4)], "b/two": [rule(4)]})
    right = render_rules({"b/two": [rule(4)], "a/one": [rule(4)]})

    assert left == right


def test_render_rules_is_one_of_the_components_the_id_is_taken_over():
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


def test_one_damaged_snapshot_does_not_hide_the_healthy_ones(tmp_path: Path):
    """`rules list` and `load_snapshot(root, None)` must survive a corrupt sibling.

    Skipping is safe *because* nothing is silently substituted: asking for the damaged snapshot
    by id still fails hard, so it is never used — only omitted from a listing.
    """
    good = one_source(tmp_path, sids=(1, 2), created_at="2026-08-01T00:00:00.000000Z")[1]
    broken_directory, broken = one_source(
        tmp_path, sids=(3, 4), created_at="2026-08-11T00:00:00.000000Z"
    )
    (broken_directory / MANIFEST_NAME).write_text("{ truncated", encoding="utf-8")

    assert [entry.snapshot_id for entry in list_snapshots(tmp_path)] == [good.snapshot_id]
    _, newest = load_snapshot(tmp_path, None)
    assert newest.snapshot_id == good.snapshot_id

    with pytest.raises(SnapshotError):
        load_snapshot(tmp_path, broken.snapshot_id)


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
