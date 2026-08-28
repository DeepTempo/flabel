"""The `flabel-run` wrapper (tools/flabel-run).

**Why a shell script has tests at all.** Three bugs reached "it is running" on 2026-08-17 and
every one of them was in this wrapper, not in the Python: Zeek invisible because `/etc/profile.d`
is not read by `sudo`; a relative capture path resolved against the repo after the script `cd`s
there; and the config file overwriting environment variables the caller had set. The Python
caught its own problems through the architecture guard, the NOTICE check and CI. This layer had
no gate at all, so it became where the bugs lived.

Nothing here runs a replay, contacts a device, or needs root. `FLABEL_RUN_SUDO` is pointed at a
stub that records the command instead of executing it, which is what makes the interesting
assertion — *what would have been run* — available without running it.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

WRAPPER = Path(__file__).resolve().parents[1] / "tools" / "flabel-run"


@pytest.fixture
def lab(tmp_path: Path) -> dict[str, str]:
    """A fake replay box: a config file, a repo, and a `sudo` that only records."""
    conf = tmp_path / "flabel.env"
    conf.write_text(
        "export FLABEL_INLINE_HOST=10.10.0.2\n"
        "export FLABEL_INLINE_API_KEY_FILE=/dev/null\n"
        "export FLABEL_REPLAY_IF1=ens5\n"
        "export FLABEL_REPLAY_IF2=ens6\n"
        "export FLABEL_REPLAY_MULTIPLIER=1000\n"
        "export FLABEL_SETTLE_SECONDS=60\n"
    )
    repo = tmp_path / "repo"
    repo.mkdir()
    recorded = tmp_path / "recorded"

    # The `sudo` stub records the command and, when asked, fabricates the run directory that a
    # real labelling run would have left behind. Fabricating it is what makes the publish step
    # (#134) reachable without a replay: the interesting assertions are about which directory is
    # published and whether `labels.json` is in it, and neither needs flabel to have run.
    #
    # FAKE_EXIT lets a test drive a *failed* run, because "the exit code still survives the added
    # publish step" is only testable against a non-zero one.
    stub = tmp_path / "fake-sudo"
    stub.write_text(
        f"""#!/bin/bash
printf "%s\\n" "$@" > {recorded}
printf "CWD=%s\\n" "$PWD" >> {recorded}
if [ -n "${{FAKE_MAKE_RUN:-}}" ]; then
  # The run directory is created under the --output-dir this stub was ACTUALLY PASSED, taking the
  # last occurrence exactly as argparse does. Reading $FLABEL_RUN_RUNS instead made the stub
  # disagree with real flabel in the two cases that matter: a relative runs directory (the wrapper
  # passes it resolved, the env var is not) and an operator-supplied --output-dir (which wins).
  base=""
  prev=""
  for a in "$@"; do
    if [ "$prev" = "--output-dir" ]; then base="$a"; fi
    case "$a" in --output-dir=*) base="${{a#--output-dir=}}" ;; esac
    prev="$a"
  done
  : "${{base:=$FLABEL_RUN_RUNS}}"
  d="$base/$FAKE_MAKE_RUN"
  mkdir -p "$d/zeek"
  printf '%s' '{{"run":{{"mode":"replay"}}}}' > "$d/run.json"
  printf '%s' 'zeek log' > "$d/zeek/conn.log"
  if [ -n "${{FAKE_WRITE_LABELS:-}}" ]; then
    # FAKE_WRITE_LABELS=1 writes an EMPTY labels[]; any other value writes one label. Without the
    # second shape "a run that labelled nothing" was not a distinguishing condition anywhere in
    # this harness, and its test was a duplicate of the ordinary published-and-indexed one.
    if [ "$FAKE_WRITE_LABELS" = "1" ]; then
      printf '%s' '{{"labels":[]}}' > "$d/labels.json"
    else
      printf '%s' '{{"labels":[{{"best_tier":2}}]}}' > "$d/labels.json"
    fi
  fi
fi
if [ -n "${{FAKE_STRAY_FILE:-}}" ] && [ -n "${{base:-}}" ]; then
  printf '%s' 'not a run' > "$base/$FAKE_STRAY_FILE"
fi
if [ -n "${{FAKE_MAKE_SECOND_RUN:-}}" ]; then
  mkdir -p "$FLABEL_RUN_RUNS/$FAKE_MAKE_SECOND_RUN"
  printf '%s' '{{"labels":[]}}' > "$FLABEL_RUN_RUNS/$FAKE_MAKE_SECOND_RUN/labels.json"
fi
exit "${{FAKE_EXIT:-0}}"
"""
    )
    stub.chmod(0o755)

    # A `gcloud` that records instead of uploading, and a destination that is not a real bucket.
    # Both are set for EVERY test, not only the publishing ones: `FLABEL_RESULTS_URI` defaults to
    # the production bucket, so leaving it unset would make the suite's behaviour depend on whether
    # a test happened to create a run directory. Nothing here may contact GCS by accident.
    gcloud_log = tmp_path / "gcloud-calls"
    # ONE log both stubs append to, so "archive then index" (§7.5) is observable. The two separate
    # logs could not distinguish that ordering from its reverse — the step's headline invariant was
    # pinned only indirectly, by the declined-publish test, whose name is about something else.
    order_log = tmp_path / "order-log"
    ingest_marker = tmp_path / "ingest-child-state"
    gcloud = tmp_path / "fake-gcloud"
    gcloud.write_text(
        f"""#!/bin/bash
printf "%s\\n" "$*" >> {gcloud_log}
# A PUBLISH is a `cp` whose DESTINATION is the bucket. `stage_capture` also runs `storage cp`,
# downwards, and matching on "cp " alone counted that as a publish — correct only for as long as
# every test using `ordering()` happens to pass a local capture.
case "$*" in
  *"cp "*) case "${{@: -1}}" in
    gs://*) printf 'PUBLISH %s\\n' "$*" >> {order_log} ;;
  esac ;;
esac
# A staging fetch has to leave a file behind or the wrapper's existence check stops the run before
# anything interesting happens. Only for a LOCAL destination: an upload's destination is a gs:// URI
# and must not be created on disk.
dest="${{@: -1}}"
case "$dest" in
  gs://*) : ;;
  *) [ -n "$dest" ] && printf '%s' 'staged' > "$dest" ;;
esac
exit "${{FAKE_GCLOUD_EXIT:-0}}"
"""
    )
    gcloud.chmod(0o755)

    # A `flabel-ingest` stub: logs the URI it was handed and honours FAKE_INGEST_EXIT, so
    # "published but not indexed" (exit 5) is reachable without BigQuery.
    ingest_log = tmp_path / "ingest-log"
    # What the ingest actually SAW for the project, so "the environment wins" is observable.
    ingest_env = tmp_path / "ingest-project"
    ingest = tmp_path / "fake-ingest"
    ingest.write_text(
        f"""#!/bin/bash
printf 'INDEX %s\\n' "$*" >> {order_log}
printf '%s\\n' "${{GCP_PROJECT:-}}" > {ingest_env}
for a in "$@"; do case "$a" in gs://*) printf '%s\\n' "$a" >> {ingest_log};; esac; done
if [ -n "${{FAKE_INGEST_SLEEP:-}}" ]; then
  trap 'printf terminated > {ingest_marker}; exit 143' TERM
  printf started > {ingest_marker}
  for _ in $(seq 1 200); do sleep 0.1; done
  printf finished > {ingest_marker}
fi
exit "${{FAKE_INGEST_EXIT:-0}}"
"""
    )
    ingest.chmod(0o755)

    provisioned = tmp_path / "provisioned-marker"
    provisioned.write_text("")

    return {
        "FLABEL_RUN_INGEST": str(ingest),
        # Required by `flabel-ingest` and therefore by the indexing step (#171). The real box gets
        # it from flabel.env; the repo is public so the id is never committed.
        "GCP_PROJECT": "test-project",
        "_ingest_log": str(ingest_log),
        "_order_log": str(order_log),
        "_ingest_env": str(ingest_env),
        "_ingest_marker": str(ingest_marker),
        "FLABEL_RUN_CONF": str(conf),
        # Every existing test drives a box that IS provisioned. The marker is a real file rather
        # than a pointer at /dev/null so that the gate's absence case has something to remove.
        "FLABEL_RUN_PROVISIONED": str(provisioned),
        "FLABEL_RUN_CAPTURES": str(tmp_path / "captures"),
        "FLABEL_RUN_RUNS": str(tmp_path / "runs"),
        "FLABEL_RUN_REPO": str(repo),
        "FLABEL_RUN_SUDO": str(stub),
        "FLABEL_RUN_GCLOUD": str(gcloud),
        "FLABEL_RESULTS_URI": "gs://test-bucket/results",
        # Empty, so the stub gcloud runs directly. In production this defaults to $SUDO, because
        # only root's gcloud carries the instance service-account credential — see the wrapper.
        # `test_gcloud_runs_privileged_by_default` is what holds that default in place.
        "FLABEL_RUN_PUBLISH_SUDO": "",
        "_recorded": str(recorded),
        "_gcloud_log": str(gcloud_log),
        "_tmp": str(tmp_path),
    }


def invoke(
    lab: dict[str, str], *args: str, extra: dict[str, str] | None = None, cwd: str | None = None
) -> subprocess.CompletedProcess[str]:
    env = {**os.environ, **{k: v for k, v in lab.items() if not k.startswith("_")}}
    env.update(extra or {})
    # The sentinel exists because the fixture sets some variables to the EMPTY string on purpose —
    # `FLABEL_RESULTS_URI=""` means "do not publish" and `FLABEL_RUN_PUBLISH_SUDO=""` means "do not
    # elevate" — so a test that wants the wrapper's own default has to remove the name from the
    # environment entirely, which passing "" cannot express.
    for name, value in list(env.items()):
        if value == "__unset__":
            del env[name]
    return subprocess.run(
        [str(WRAPPER), *args],
        capture_output=True,
        text=True,
        env=env,
        cwd=cwd or lab["_tmp"],
        check=False,
    )


def recorded(lab: dict[str, str]) -> str:
    return Path(lab["_recorded"]).read_text()


def uploads(lab: dict[str, str]) -> list[str]:
    """Every `gcloud` invocation the wrapper made, one per line, or `[]` if it made none."""
    log = Path(lab["_gcloud_log"])
    return log.read_text().splitlines() if log.exists() else []


def ingests(lab: dict[str, str]) -> list[str]:
    """Every URI `flabel-ingest` was asked to index, or `[]` if it was never called."""
    log = Path(lab["_ingest_log"])
    return log.read_text().splitlines() if log.exists() else []


def wait_for_marker(marker: Path, value: str, *, tries: int = 300) -> str:
    """Poll a marker file until it holds `value`, and return what it holds.

    **On CONTENT, never on existence.** `printf x > f` truncates before it writes, so a poll that
    breaks on `f.exists()` can win the race at the zero-length instant and then assert `"" == "x"`.
    That is a flake in the test, not a defect in the wrapper, and it is exactly the shape that made
    a sibling test red in CI and green here.
    """
    import time

    for _ in range(tries):
        try:
            if marker.read_text() == value:
                return value
        except OSError:
            pass
        time.sleep(0.05)
    try:
        return marker.read_text()
    except OSError:
        return "<no marker>"


def ordering(lab: dict[str, str]) -> list[str]:
    """`PUBLISH` and `INDEX` in the order they actually happened — §7.5's invariant, observable."""
    log = Path(lab["_order_log"])
    if not log.exists():
        return []
    return [line.split(" ", 1)[0] for line in log.read_text().splitlines()]


def recording_sudo(tmp_path: Path) -> tuple[Path, Path]:
    """A `sudo` replacement that logs every privileged command AND fabricates the run directory.

    Both halves are needed: logging is the assertion, and the run directory is what makes the
    publish step reachable at all. The first version of this only logged, so the wrapper found no
    new directory, published nothing, and the test failed for a reason that had nothing to do with
    what it was checking.

    Returns `(stub, log)`.
    """
    log = tmp_path / "privileged-calls"
    stub = tmp_path / "recording-sudo"
    stub.write_text(
        f"""#!/bin/bash
printf "%s\\n" "$*" >> {log}
if [ -n "${{FAKE_MAKE_RUN:-}}" ] && [ -n "${{FLABEL_RUN_RUNS:-}}" ]; then
  d="$FLABEL_RUN_RUNS/$FAKE_MAKE_RUN"
  mkdir -p "$d"
  printf '%s' '{{"labels":[]}}' > "$d/labels.json"
fi
"""
    )
    stub.chmod(0o755)
    return stub, log


def passthrough_sudo(tmp_path: Path) -> tuple[Path, Path]:
    """A privilege stub that logs the command and then actually runs it. Returns `(stub, log)`.

    Safe here in a way it would not be for `$SUDO`: `$PUBLISH_SUDO` only ever wraps `gcloud`, never
    the labelling command, so executing its arguments runs the stub gcloud rather than a real
    replay. That is what lets a test assert the fetch was privileged *and* let the fetch succeed.
    """
    log = tmp_path / "privileged-calls"
    stub = tmp_path / "passthrough-sudo"
    stub.write_text(f'#!/bin/bash\nprintf "%s\\n" "$*" >> {log}\nexec "$@"\n')
    stub.chmod(0o755)
    return stub, log


def capture(tmp_path: Path, name: str = "some.pcap") -> Path:
    """A file that passes the wrapper's existence check. Never read — the run is stubbed."""
    path = tmp_path / name
    path.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)
    return path


def test_a_relative_capture_path_is_resolved_before_the_script_changes_directory(lab, tmp_path):
    """The bug that could have labelled the wrong file.

    The existence check runs in the caller's directory and the command runs in the repo. Passing
    the relative string through meant it resolved against the repo — an error if nothing was
    there, and silently the WRONG CAPTURE if something was.
    """
    here = tmp_path / "work"
    here.mkdir()
    (here / "some.pcap").write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 20)

    result = invoke(lab, "./some.pcap", cwd=str(here))

    assert result.returncode == 0, result.stderr
    assert str(here / "some.pcap") in recorded(lab)
    assert "./some.pcap" not in recorded(lab).replace(str(here / "some.pcap"), "")


def test_the_wrong_capture_cannot_be_picked_up_from_the_repo(lab, tmp_path):
    """A same-named file in the repo must not win. This is the dangerous half of the bug."""
    here = tmp_path / "work"
    here.mkdir()
    (here / "trap.pcap").write_bytes(b"REAL")
    decoy = Path(lab["FLABEL_RUN_REPO"]) / "trap.pcap"
    decoy.write_bytes(b"DECOY")

    invoke(lab, "./trap.pcap", cwd=str(here))

    assert str(here / "trap.pcap") in recorded(lab)
    assert str(decoy) not in recorded(lab)


def test_an_environment_variable_beats_the_config_file(lab, tmp_path):
    """`FLABEL_SETTLE_SECONDS=15 flabel-run x.pcap` settled for 60 and said nothing.

    `set -a; . "$CONF"` overwrites, so the file won. That is backwards for an environment
    variable, and the silence is what made it a bug rather than a preference.
    """
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture), extra={"FLABEL_SETTLE_SECONDS": "15"})

    assert "FLABEL_SETTLE_SECONDS=15" in recorded(lab)
    assert "FLABEL_SETTLE_SECONDS=60" not in recorded(lab)


def test_the_config_file_still_supplies_everything_the_caller_did_not_set(lab, tmp_path):
    """Precedence, not replacement: overriding one value must not blank the rest."""
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture), extra={"FLABEL_SETTLE_SECONDS": "15"})

    text = recorded(lab)
    assert "FLABEL_INLINE_HOST=10.10.0.2" in text
    assert "FLABEL_REPLAY_IF1=ens5" in text


def test_the_run_happens_in_the_repo_so_the_venv_and_snapshot_resolve(lab, tmp_path):
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture))

    assert f"CWD={lab['FLABEL_RUN_REPO']}" in recorded(lab)


def test_zeeks_directory_is_on_the_path_handed_to_the_run(lab, tmp_path):
    """Zeek is symlinked into /usr/local/bin because sudo does not read /etc/profile.d.

    The first full tier-1 run died at the Zeek stage after spending a replay and a 60s settle.
    """
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture))

    path_line = [line for line in recorded(lab).splitlines() if line.startswith("PATH=")]
    assert path_line and "/usr/local/bin" in path_line[0]


def test_extra_arguments_are_forwarded_to_flabel(lab, tmp_path):
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture), "--offline")

    assert "--offline" in recorded(lab).splitlines()


def test_output_goes_to_the_runs_directory_not_beside_the_capture(lab, tmp_path):
    """Labelling a capture in a home directory must not scatter run directories there."""
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    invoke(lab, str(capture))

    assert lab["FLABEL_RUN_RUNS"] in recorded(lab)


def test_a_missing_capture_fails_before_anything_is_run(lab):
    result = invoke(lab, "/nowhere/absent.pcap")

    assert result.returncode == 1
    assert "no such capture" in result.stderr
    assert not Path(lab["_recorded"]).exists()


def test_no_argument_prints_usage_to_stderr_and_exits_two(lab):
    result = invoke(lab)

    assert result.returncode == 2
    assert "usage:" in result.stderr
    assert result.stdout == ""


@pytest.mark.parametrize("flag", ["-h", "--help", "help"])
def test_help_goes_to_stdout_and_succeeds(lab, flag):
    """Asking is not the same event as being told.

    `--help` on stderr with a failing status cannot be piped into a pager, which is the one
    thing an operator does with it.
    """
    result = invoke(lab, flag)

    assert result.returncode == 0
    assert result.stderr == ""
    assert "usage:" in result.stdout


def test_help_documents_the_knobs_that_change_what_a_label_means(lab):
    """--topspeed and the settle are not cosmetic, so help has to say what they cost."""
    text = invoke(lab, "--help").stdout
    for knob in (
        "FLABEL_REPLAY_MULTIPLIER",
        "FLABEL_REPLAY_TOPSPEED",
        "FLABEL_SETTLE_SECONDS",
        "FLABEL_PLAIN_PROGRESS",
        "--offline",
    ):
        assert knob in text, f"help does not mention {knob}"
    assert "unmatched rather than" in text, "help must say what --topspeed costs"


def test_help_works_without_a_config_file(lab, tmp_path):
    """An operator whose config is missing still needs to be able to read the help."""
    result = invoke(lab, "--help", extra={"FLABEL_RUN_CONF": str(tmp_path / "absent.env")})

    assert result.returncode == 0
    assert "usage:" in result.stdout


def test_a_missing_config_file_says_where_it_should_be(lab, tmp_path):
    capture = tmp_path / "c.pcap"
    capture.write_bytes(b"\xd4\xc3\xb2\xa1")

    result = invoke(lab, str(capture), extra={"FLABEL_RUN_CONF": str(tmp_path / "absent.env")})

    assert result.returncode == 1
    assert "device settings live there" in result.stderr


# --- publishing a finished run (#134) --------------------------------------------------------
#
# The destination is a stub `gcloud` and a `gs://test-bucket` that does not exist. What is asserted
# is *what would have been uploaded*, which is the same trick `FLABEL_RUN_SUDO` plays on the replay
# itself — and for the same reason: the interesting behaviour is the decision, not the transfer.

RUN_NAME = "LABELED_some_20260819T120000.000000Z"

#: `flabel succeeded and the result was not published`. Distinct from spec §12's exit 1 ("no
#: labels.json"), because reusing 1 told a batch caller to discard a capture whose labels are
#: intact on the box (review of #134).
EXIT_NOT_PUBLISHED = 4


def test_a_successful_run_is_published_under_the_run_directory_name(lab, tmp_path):
    """The whole feature: labels on the box become a tarball in the bucket, named to match."""
    capture(tmp_path)

    result = invoke(lab, "some.pcap", extra={"FAKE_MAKE_RUN": RUN_NAME, "FAKE_WRITE_LABELS": "1"})

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, f"expected exactly one upload, got {calls}"
    assert calls[0].startswith("storage cp "), calls[0]
    assert calls[0].endswith(f"gs://test-bucket/results/{RUN_NAME}.tar.gz"), calls[0]


def test_the_published_tarball_unpacks_to_one_directory_of_that_name(lab, tmp_path):
    """`tar -C $RUNS <name>` rather than an absolute path, so it cannot unpack to `var/lib/...`.

    Asserted by unpacking the real archive: the stub `gcloud` is handed a genuine tarball, so the
    bytes are checkable even though nothing is transferred. A test on the *command* alone would
    pass with an archive rooted at an absolute path.
    """
    import tarfile

    capture(tmp_path)
    staged = tmp_path / "staged.tar.gz"
    # A `gcloud` that keeps the file it was asked to upload, instead of only recording the call.
    keeper = tmp_path / "keeping-gcloud"
    keeper.write_text(f'#!/bin/bash\nshift 2\ncp "$1" {staged}\n')
    keeper.chmod(0o755)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_GCLOUD": str(keeper),
        },
    )

    assert result.returncode == 0, result.stderr
    assert staged.exists(), "the wrapper never handed gcloud a file"
    with tarfile.open(staged) as archive:
        names = archive.getnames()
    tops = {name.split("/")[0] for name in names}
    assert tops == {RUN_NAME}, f"archive has more than one root: {tops}"
    assert f"{RUN_NAME}/labels.json" in names
    assert f"{RUN_NAME}/run.json" in names
    assert f"{RUN_NAME}/zeek/conn.log" in names


def test_a_run_with_no_labels_is_not_published(lab, tmp_path):
    """Craig, 2026-08-19: `results/` is trustworthy by construction or it is not worth having.

    Decided on the ARTIFACT, not the exit code. Issue #23 makes the presence of `labels.json` the
    definition of a completed run, so the directory's contents and a consumer's conclusion cannot
    disagree — where an exit code is a second record of the same fact.
    """
    capture(tmp_path)

    result = invoke(lab, "some.pcap", extra={"FAKE_MAKE_RUN": RUN_NAME})

    assert uploads(lab) == [], "a run that wrote no labels must publish nothing"
    assert "wrote no labels.json" in result.stderr
    assert (Path(lab["FLABEL_RUN_RUNS"]) / RUN_NAME / "run.json").exists(), (
        "the local run must be left alone — it is the diagnosis"
    )


def test_a_failed_run_still_exits_with_flabels_code(lab, tmp_path):
    """`exec` had to go so publishing could happen after the run; the exit code must survive it.

    This is the regression the refactor most plausibly introduces: dropping `exec` makes the exit
    status something the script now has to carry by hand, and `set -e` would otherwise kill it
    before it could report.
    """
    capture(tmp_path)

    result = invoke(lab, "some.pcap", extra={"FAKE_MAKE_RUN": RUN_NAME, "FAKE_EXIT": "1"})

    assert result.returncode == 1, result.stderr
    assert uploads(lab) == []


def test_a_usage_exit_code_of_two_is_not_flattened_to_one(lab, tmp_path):
    """Exit 2 means "the invocation was wrong" (spec §12) and must not become a generic failure."""
    capture(tmp_path)

    result = invoke(lab, "some.pcap", extra={"FAKE_EXIT": "2"})

    assert result.returncode == 2, result.stderr


def test_a_failed_upload_does_not_report_success(lab, tmp_path):
    """The worst available outcome is a silent one: labels on the box, operator believes otherwise.

    The local run must survive untouched — the upload failing is not a reason to lose the result.
    """
    capture(tmp_path)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FAKE_GCLOUD_EXIT": "1",
        },
    )

    assert result.returncode == EXIT_NOT_PUBLISHED, (
        "a failed publish must not exit 0, and must not claim the run failed either"
    )
    assert "FAILED to publish" in result.stderr
    assert "labels are intact" in result.stderr
    assert (Path(lab["FLABEL_RUN_RUNS"]) / RUN_NAME / "labels.json").exists()


def test_publishing_can_be_switched_off_with_an_empty_destination(lab, tmp_path):
    """So this wrapper stays the one way to run flabel even where there is no bucket.

    An empty value rather than a second flag or a second script: a "run but do not publish" code
    path is a second thing to keep correct, and the one that gets exercised less is the one that
    rots.
    """
    capture(tmp_path)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RESULTS_URI": "",
        },
    )

    assert result.returncode == 0, result.stderr
    assert uploads(lab) == []


def test_two_new_directories_are_refused_rather_than_guessed_between(lab, tmp_path):
    """Publishing the wrong directory puts one capture's labels in the bucket under another's name.

    Reachable in the field: a concurrent run, or a stale directory appearing under `$RUNS` between
    the before and after listings. Nothing is published and the operator is told how to do it by
    hand, because a wrong publish is worse than no publish.
    """
    capture(tmp_path)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FAKE_MAKE_SECOND_RUN": "LABELED_other_20260819T120001.000000Z",
        },
    )

    assert uploads(lab) == [], "with two candidates, nothing may be published"
    assert "cannot tell which is this" in result.stderr
    assert result.returncode == EXIT_NOT_PUBLISHED, (
        "the run itself succeeded, so this is not spec §12's exit 1"
    )


def test_a_run_that_created_no_directory_publishes_nothing_and_says_so(lab, tmp_path):
    """A rejected capture leaves no run directory at all (spec §12) — normal, and worth one line."""
    capture(tmp_path)

    result = invoke(lab, "some.pcap")

    assert uploads(lab) == []
    assert "nothing to publish" in result.stderr


def test_a_pre_existing_run_directory_is_not_republished(lab, tmp_path):
    """Only what THIS invocation created. Spec §13 forbids modifying a previous run; republishing
    one is the same mistake pointed at the bucket — and with `objectCreator` the overwrite would
    be refused anyway, so the operator would get a 403 about a run they did not just make.
    """
    capture(tmp_path)
    stale = Path(lab["FLABEL_RUN_RUNS"]) / "LABELED_older_20260818T120000.000000Z"
    stale.mkdir(parents=True)
    (stale / "labels.json").write_text("{}")

    result = invoke(lab, "some.pcap", extra={"FAKE_MAKE_RUN": RUN_NAME, "FAKE_WRITE_LABELS": "1"})

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, calls
    # The DESTINATION only. Asserting `"older" not in calls[0]` matched the pytest temp path,
    # which on macOS contains ".../var/folders/..." — and "folders" contains "older". A substring
    # check over a whole command line is a check over whatever the environment put in it.
    destination = calls[0].split()[-1]
    assert destination == f"gs://test-bucket/results/{RUN_NAME}.tar.gz", destination


def test_the_tarball_is_not_left_inside_the_runs_directory(lab, tmp_path):
    """A `.tar.gz` beside the run directories is picked up as one by anything that lists them —
    including this wrapper's own before/after comparison on the very next run."""
    capture(tmp_path)

    invoke(lab, "some.pcap", extra={"FAKE_MAKE_RUN": RUN_NAME, "FAKE_WRITE_LABELS": "1"})

    leftovers = list(Path(lab["FLABEL_RUN_RUNS"]).glob("*.tar.gz"))
    assert leftovers == [], f"tarball left in the runs directory: {leftovers}"


def test_gcloud_runs_privileged_by_default(lab, tmp_path):
    """Only root's gcloud has the instance service-account credential (measured 2026-08-19).

    The bug this pins: the publish step first ran gcloud as the invoking user, whose active
    account on `fl-replay` was a human one with no valid token — so every upload failed with
    "select an already authenticated account", while `sudo gcloud` worked as the service account
    IAM had actually been granted to.

    Every other test in this file sets `FLABEL_RUN_PUBLISH_SUDO=""` so the stub gcloud runs
    directly, which means none of them exercise the default. This one unsets it and asserts the
    privilege wrapper is invoked with the gcloud command — the production wiring, checked without
    needing root.
    """
    capture(tmp_path)
    recorder, privileged = recording_sudo(tmp_path)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            # Unset, so the wrapper's own default applies.
            "FLABEL_RUN_PUBLISH_SUDO": "__unset__",
            "FLABEL_RUN_SUDO": str(recorder),
        },
    )

    assert result.returncode == 0, result.stderr
    calls = privileged.read_text().splitlines() if privileged.exists() else []
    uploaded = [call for call in calls if "storage cp" in call]
    assert uploaded, f"gcloud was not run through the privilege wrapper; calls were {calls}"
    assert uploaded[0].endswith(f"gs://test-bucket/results/{RUN_NAME}.tar.gz"), uploaded[0]


def test_tar_is_deliberately_not_privileged(lab, tmp_path):
    """Run directories are root-owned but 0755, so `tar` reads them unprivileged (measured).

    Stated as a test because "run gcloud as root" invites "run everything as root", and the two
    have different reasons: gcloud needs root for its *identity*, tar would only need it for file
    access it does not lack. Building the archive as root would also leave it root-owned in a
    temporary directory this script then has to clean up.
    """
    capture(tmp_path)
    recorder, privileged = recording_sudo(tmp_path)

    invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_PUBLISH_SUDO": "__unset__",
            "FLABEL_RUN_SUDO": str(recorder),
        },
    )

    calls = privileged.read_text().splitlines() if privileged.exists() else []
    assert not [call for call in calls if call.startswith("tar ") or " tar " in call], (
        f"tar was run privileged, which it does not need: {calls}"
    )


# --- staging a gs:// capture (pre-existing path, privilege fixed in #134) ----------------------


def test_a_gs_capture_is_staged_through_the_privilege_wrapper(lab, tmp_path):
    """The same credential bug as the publish, in code that predates it.

    `gcloud storage cp` to stage a `gs://` capture ran as the invoking user, whose gcloud on
    `fl-replay` had no usable credential — so staging would have failed exactly as the first
    version of the upload did. Nothing covered this path at all, which is why the sabotage that
    reverted it passed while every other one went red.
    """
    stub, privileged = passthrough_sudo(tmp_path)

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_PUBLISH_SUDO": str(stub),
        },
    )

    assert result.returncode == 0, result.stderr
    calls = privileged.read_text().splitlines() if privileged.exists() else []
    fetches = [call for call in calls if "gs://some-bucket/remote.pcap" in call]
    assert fetches, f"the staging fetch was not privileged; calls were {calls}"
    staged = Path(lab["FLABEL_RUN_CAPTURES"]) / "remote.pcap"
    assert staged.exists(), "the capture was not staged locally"
    assert str(staged) in recorded(lab), "flabel was not pointed at the staged copy"


def test_an_already_staged_capture_is_not_fetched_again(lab, tmp_path):
    """The wrapper's documented reuse, and the complement of the test above.

    Worth holding: re-downloading inside the timed part of a run widens the gap between the replay
    and the device's log query, which is the window the threat logs are selected by.
    """
    stub, privileged = passthrough_sudo(tmp_path)
    staged_dir = Path(lab["FLABEL_RUN_CAPTURES"])
    staged_dir.mkdir(parents=True, exist_ok=True)
    (staged_dir / "remote.pcap").write_bytes(b"already here")

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_PUBLISH_SUDO": str(stub),
        },
    )

    assert result.returncode == 0, result.stderr
    assert "already staged" in result.stdout + result.stderr
    calls = privileged.read_text().splitlines() if privileged.exists() else []
    assert not [call for call in calls if "gs://some-bucket/remote.pcap" in call], (
        f"a staged capture was fetched again: {calls}"
    )
    assert (staged_dir / "remote.pcap").read_bytes() == b"already here", (
        "the staged copy was replaced"
    )


# --- what the review of #134 found ------------------------------------------------------------


def test_the_config_file_can_set_the_publishing_destination(lab, tmp_path):
    """It could not, and the comment claimed it was the whole point of the override.

    `RESULTS_URI` was resolved at the top of the script and `$CONF` is sourced ~100 lines later, so
    a `FLABEL_RESULTS_URI` written into /var/lib/flabel/flabel.env was read and thrown away — and a
    second lab publishing to its own bucket silently published to the first lab's, or 403'd against
    it. The config file is exactly where a per-lab override belongs.
    """
    capture(tmp_path)
    conf = Path(lab["FLABEL_RUN_CONF"])
    conf.write_text(conf.read_text() + "export FLABEL_RESULTS_URI=gs://second-lab/results\n")

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            # Unset, so the config file's value is what decides.
            "FLABEL_RESULTS_URI": "__unset__",
        },
    )

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, calls
    assert calls[0].endswith(f"gs://second-lab/results/{RUN_NAME}.tar.gz"), calls[0]


def test_the_caller_environment_still_beats_the_config_file_for_the_destination(lab, tmp_path):
    """Moving the resolution must not invert the precedence the rest of the script guarantees."""
    capture(tmp_path)
    conf = Path(lab["FLABEL_RUN_CONF"])
    conf.write_text(conf.read_text() + "export FLABEL_RESULTS_URI=gs://from-config/results\n")

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RESULTS_URI": "gs://from-caller/results",
        },
    )

    assert result.returncode == 0, result.stderr
    assert uploads(lab)[0].endswith(f"gs://from-caller/results/{RUN_NAME}.tar.gz")


def test_publishing_can_be_switched_off_from_the_config_file(lab, tmp_path):
    """The other half of the ordering bug: an empty value in the config did not switch it off."""
    capture(tmp_path)
    conf = Path(lab["FLABEL_RUN_CONF"])
    conf.write_text(conf.read_text() + "export FLABEL_RESULTS_URI=\n")

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RESULTS_URI": "__unset__",
        },
    )

    assert result.returncode == 0, result.stderr
    assert uploads(lab) == []


def test_a_trailing_slash_does_not_produce_a_double_slash_in_the_object_name(lab, tmp_path):
    """`gs://bucket/results/` is the natural way to write a prefix, and GCS accepts `results//x`.

    It creates an object no `results/` listing or download script matches, so it is lost rather
    than wrong.
    """
    capture(tmp_path)

    invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RESULTS_URI": "gs://test-bucket/results/",
        },
    )

    assert uploads(lab)[0].endswith(f"gs://test-bucket/results/{RUN_NAME}.tar.gz")
    assert "//LABELED" not in uploads(lab)[0]


def test_a_relative_runs_directory_survives_the_change_into_the_repo(lab, tmp_path):
    """The same bug this script already fixed for the capture path, one variable over.

    `$RUNS` was listed in the caller's directory and then written to under `$REPO`, so a run looked
    like it had created several directories, published none of them, and failed.
    """
    work = tmp_path / "work"
    work.mkdir()
    capture(work)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FLABEL_RUN_RUNS": "relruns",
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
        },
        cwd=str(work),
    )

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, f"a relative runs directory broke publishing: {result.stderr}"
    assert calls[0].endswith(f"{RUN_NAME}.tar.gz")


def test_an_operator_supplied_output_dir_is_still_published_from(lab, tmp_path):
    """The help lists `--output-dir` as supported AND promises a publish; both must be true.

    argparse takes the last `--output-dir`, and the wrapper passes its own first — so the
    operator's wins, the run lands elsewhere, and watching `$RUNS` saw nothing.
    """
    capture(tmp_path)
    elsewhere = tmp_path / "elsewhere"

    result = invoke(
        lab,
        "some.pcap",
        "--output-dir",
        str(elsewhere),
        extra={"FAKE_MAKE_RUN": RUN_NAME, "FAKE_WRITE_LABELS": "1"},
    )

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, f"an overridden output dir was not published from: {result.stderr}"
    assert calls[0].endswith(f"{RUN_NAME}.tar.gz")


def test_a_stray_file_in_the_output_directory_is_not_mistaken_for_a_run(lab, tmp_path):
    """It used to satisfy the count, fail the `-d` test, and print "1 new directories"."""
    capture(tmp_path)
    runs = Path(lab["FLABEL_RUN_RUNS"])
    runs.mkdir(parents=True, exist_ok=True)

    result = invoke(
        lab,
        "some.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FAKE_STRAY_FILE": "notes.txt",
        },
    )

    assert result.returncode == 0, result.stderr
    calls = uploads(lab)
    assert len(calls) == 1, f"a stray file confused run selection: {result.stderr}"
    assert calls[0].endswith(f"{RUN_NAME}.tar.gz")


def test_a_terminating_signal_is_forwarded_to_the_run(lab, tmp_path):
    """`exec` forwarded signals for free; dropping it orphaned a root-privileged replay.

    Without this, a SIGTERM — from `timeout`, systemd, or an operator — killed only the wrapper
    while `tcpreplay` kept injecting into the firewall as root, after the operator believed the run
    had stopped. Asserted by making the stubbed run sleep, terminating the wrapper, and checking
    the child recorded a TERM rather than running to completion.
    """
    import signal
    import time

    capture(tmp_path)
    marker = tmp_path / "child-state"
    sleeper = tmp_path / "sleeping-sudo"
    sleeper.write_text(
        f"#!/bin/bash\ntrap 'printf terminated > {marker}; exit 143' TERM\n"
        f"printf started > {marker}\nfor _ in $(seq 1 100); do sleep 0.1; done\n"
        f"printf finished > {marker}\n"
    )
    sleeper.chmod(0o755)

    env = {**os.environ, **{k: v for k, v in lab.items() if not k.startswith("_")}}
    env["FLABEL_RUN_SUDO"] = str(sleeper)
    process = subprocess.Popen(
        [str(WRAPPER), "some.pcap"],
        env=env,
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    for _ in range(100):
        if marker.exists():
            break
        time.sleep(0.05)
    assert marker.read_text() == "started", "the stubbed run never started"

    process.send_signal(signal.SIGTERM)
    process.wait(timeout=20)

    for _ in range(100):
        if marker.read_text() != "started":
            break
        time.sleep(0.05)
    assert marker.read_text() == "terminated", (
        "the run was orphaned: the wrapper died and left it running"
    )


# --- staging with either identity (#136) -------------------------------------------------------


def two_identity_gcloud(tmp_path: Path, *, root_ok: bool, caller_ok: bool) -> tuple[Path, Path]:
    """A `gcloud` that succeeds or fails depending on whether it was invoked through sudo.

    The privilege stub exports `VIA_SUDO=1` before exec'ing, which is how this tells the two apart
    without needing root. Returns `(gcloud, log)`.
    """
    log = tmp_path / "identity-calls"
    gcloud = tmp_path / "two-identity-gcloud"
    # The identity rule applies to DOWNLOADS only. Uploads always succeed, because the publish is
    # service-account-only by design and a stub that failed it too would make every fallback test
    # exit 4 for a reason that has nothing to do with staging — which is exactly what the first
    # version of this did.
    gcloud.write_text(
        f"""#!/bin/bash
who=caller
[ -n "${{VIA_SUDO:-}}" ] && who=root
printf '%s %s\\n' "$who" "$*" >> {log}
dest="${{@: -1}}"
case "$dest" in
  gs://*)
    exit 0
    ;;
esac
ok=0
if [ "$who" = root ]; then ok={1 if root_ok else 0}; else ok={1 if caller_ok else 0}; fi
if [ "$ok" = "1" ]; then
  [ -n "$dest" ] && printf '%s' 'staged' > "$dest"
  exit 0
fi
echo "HTTPError 403: $who cannot read it" >&2
exit 1
"""
    )
    gcloud.chmod(0o755)
    return gcloud, log


def sudo_marking_gcloud(tmp_path: Path) -> Path:
    """A privilege stub that marks the environment and runs the command, so `gcloud` can tell."""
    stub = tmp_path / "marking-sudo"
    stub.write_text('#!/bin/bash\nexport VIA_SUDO=1\nexec "$@"\n')
    stub.chmod(0o755)
    return stub


def test_the_service_account_is_tried_first_and_the_caller_is_not_needed(lab, tmp_path):
    """The ordinary path is ONE attempt, so a scheduled run behaves like an interactive one."""
    gcloud, log = two_identity_gcloud(tmp_path, root_ok=True, caller_ok=False)

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_GCLOUD": str(gcloud),
            "FLABEL_RUN_PUBLISH_SUDO": str(sudo_marking_gcloud(tmp_path)),
        },
    )

    assert result.returncode == 0, result.stderr
    fetches = [c for c in log.read_text().splitlines() if "remote.pcap" in c]
    assert len(fetches) == 1, f"the fetch should have taken one attempt: {fetches}"
    assert fetches[0].startswith("root "), fetches[0]


def test_the_caller_is_the_fallback_when_the_service_account_cannot_read_it(lab, tmp_path):
    """An object the operator can reach and the box has not been granted still works (#136).

    Safe because this is a read: `run.input.sha256` records the capture, not who fetched it.
    """
    gcloud, log = two_identity_gcloud(tmp_path, root_ok=False, caller_ok=True)

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FAKE_MAKE_RUN": RUN_NAME,
            "FAKE_WRITE_LABELS": "1",
            "FLABEL_RUN_GCLOUD": str(gcloud),
            "FLABEL_RUN_PUBLISH_SUDO": str(sudo_marking_gcloud(tmp_path)),
        },
    )

    assert result.returncode == 0, result.stderr
    fetches = [c for c in log.read_text().splitlines() if "remote.pcap" in c]
    assert [c.split()[0] for c in fetches] == ["root", "caller"], fetches
    assert "the service account could not read it" in result.stderr
    assert (Path(lab["FLABEL_RUN_CAPTURES"]) / "remote.pcap").exists()


def test_when_neither_identity_can_read_it_both_failures_are_reported(lab, tmp_path):
    """The bug report that started #136 showed one 403 and named one principal.

    Both identities had failed, for different reasons, and the message made a two-part access
    problem look like a one-part one. The remedies are printed because a 403 tells an operator what
    was refused and never what to do about it.
    """
    gcloud, log = two_identity_gcloud(tmp_path, root_ok=False, caller_ok=False)

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FLABEL_RUN_GCLOUD": str(gcloud),
            "FLABEL_RUN_PUBLISH_SUDO": str(sudo_marking_gcloud(tmp_path)),
        },
    )

    assert result.returncode != 0
    assert "NEITHER identity" in result.stderr
    assert "root cannot read it" in result.stderr, "the service account's own error must appear"
    assert "caller cannot read it" in result.stderr, "the caller's own error must appear"
    assert "objectViewer" in result.stderr, "the remedy must be named, not just the refusal"
    assert uploads(lab) == [], "a run that never started publishes nothing"
    fetches = [c for c in log.read_text().splitlines() if "remote.pcap" in c]
    assert [c.split()[0] for c in fetches] == ["root", "caller"], fetches


def test_a_failed_stage_stops_immediately_and_says_only_the_real_reason(lab, tmp_path):
    """The capture is fetched before the run for exactly this reason — fail before the 60s settle.

    Two properties, and only the second is unique to `stage_capture`. That no replay starts is also
    held by the `[ -f "$TARGET" ]` check further down, so a sabotage removing this function's
    failure propagation still leaves the run un-started — belt and braces, and worth knowing.

    What *is* unique here: the failure has to be fatal AT THE FETCH, so the operator reads the
    both-identities diagnosis and nothing else. Letting it fall through produces a second,
    misleading "no such capture: /var/lib/flabel/captures/remote.pcap" underneath the real
    explanation, which reads like a missing file rather than a denied one.
    """
    gcloud, _ = two_identity_gcloud(tmp_path, root_ok=False, caller_ok=False)

    result = invoke(
        lab,
        "gs://some-bucket/remote.pcap",
        extra={
            "FLABEL_RUN_GCLOUD": str(gcloud),
            "FLABEL_RUN_PUBLISH_SUDO": str(sudo_marking_gcloud(tmp_path)),
        },
    )

    assert result.returncode != 0
    assert not Path(lab["_recorded"]).exists(), "flabel was invoked despite having no capture"
    assert "NEITHER identity" in result.stderr
    assert "no such capture" not in result.stderr, (
        "a denied fetch must not also report a missing file — that is the wrong diagnosis"
    )


# --- LS-5: the origin URI, and indexing after the publish ---------------------------------------
#
# Two changes, and the first is the one the requirement actually rests on. `tools/flabel-run` stages
# a `gs://` object and then assigns `TARGET="$LOCAL"`, so `run.input.path` recorded the staged local
# path and the bucket URI was **discarded with the shell variable** — spec §6.1 is explicit that
# without `--source-uri` the requirement cannot be met at all, because no amount of reading a run
# directory afterwards recovers where the capture came from.


def flabel_args(lab: dict[str, str]) -> list[str]:
    """The arguments the wrapper handed to `flabel`, one per line as the sudo stub records them.

    Returned as a LIST and asserted on element-wise, never by substring over the joined command.
    #134's review found a check that passed because the pytest temp path happened to contain the
    string it was looking for — on macOS, runs live under `/var/folders/`, so "is the staged path
    absent?" was satisfied by an accident of the fixture rather than by the wrapper.
    """
    return recorded(lab).splitlines()


def test_a_gs_capture_passes_the_ORIGINAL_uri_and_not_the_staged_path(lab, tmp_path):
    args = flabel_args_after_gs_run(lab, tmp_path, "gs://bucket/dir/capture.pcap")

    assert "--source-uri" in args
    value = args[args.index("--source-uri") + 1]
    assert value == "gs://bucket/dir/capture.pcap"
    # And the staged path is not what was passed — checked as an ELEMENT, not a substring.
    #
    # A second line here used to filter `args` to elements *starting with* `--source-uri` and
    # assert `staged` was not among them. That can never be true — `staged` is an absolute
    # filesystem path — so it asserted nothing whatsoever.
    #
    # Strengthening it to `staged not in args` is also wrong, and the way it fails is the point:
    # the staged path SHOULD be in the command line, as the capture argument. The two facts
    # together are the actual contract, so both are asserted: flabel is handed the staged copy to
    # read, and told the gs:// origin it came from.
    # `os.path.realpath`, because the wrapper runs the capture through `readlink -f`. On macOS —
    # which this repo supports, and which `publish()`'s COPYFILE_DISABLE comment exists for —
    # tmp paths live under `/var/folders/…`, a symlink to `/private/var/folders/…`, so a literal
    # comparison fails on a developer's laptop while saying something untrue about the wrapper.
    staged = os.path.realpath(f"{lab['FLABEL_RUN_CAPTURES']}/capture.pcap")
    assert value != staged
    assert staged in args, f"the staged copy is not what flabel was asked to read: {args}"
    assert args.index(staged) < args.index("--source-uri"), (
        "the capture argument and the origin flag are the wrong way round"
    )


def flabel_args_after_gs_run(lab, tmp_path, uri: str) -> list[str]:
    result = invoke(lab, uri, extra={"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1"})
    assert result.returncode == 0, result.stderr
    return flabel_args(lab)


def test_a_local_capture_passes_NO_source_uri_so_uri_status_reads_local(lab, tmp_path):
    """§6.1: flabel writes `gs` or `local`, and `provenance` derives it as `"gs" if source_uri else
    "local"`. Passing the local path here would record it as a `gs` origin, which is false — and
    `--source-uri` validates as a gs:// object anyway, so it would exit 2 before the run."""
    path = capture(tmp_path)
    result = invoke(lab, str(path), extra={"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1"})

    assert result.returncode == 0, result.stderr
    assert "--source-uri" not in flabel_args(lab)


def test_the_source_uri_survives_extra_arguments(lab, tmp_path):
    """The wrapper appends `"$@"` after its own flags, so an operator flag must not displace it."""
    result = invoke(
        lab, "gs://bucket/c.pcap", "--both", extra={"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1"}
    )

    assert result.returncode == 0, result.stderr
    args = flabel_args(lab)
    assert args[args.index("--source-uri") + 1] == "gs://bucket/c.pcap"
    assert "--both" in args


# --- indexing, and exit 5 ------------------------------------------------------------------------


def test_a_published_run_is_then_indexed(lab, tmp_path):
    """§7.5: ordering is always archive-then-index. The tarball is the system of record and the
    store is a view over it, so a store write that preceded the publish could index a run that
    never reached the bucket."""
    path = capture(tmp_path)
    result = invoke(lab, str(path), extra={"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1"})

    assert result.returncode == 0, result.stderr
    assert ingests(lab), "nothing was indexed after a successful publish"
    assert ingests(lab)[0].startswith("gs://test-bucket/results/"), ingests(lab)


def test_an_unpublished_run_is_never_indexed(lab, tmp_path):
    """Publishing off means there is no tarball, and `flabel-ingest` reads the tarball (§7.2).
    Indexing anyway would ask the bucket for an object nobody wrote."""
    path = capture(tmp_path)
    result = invoke(
        lab,
        str(path),
        extra={"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1", "FLABEL_RESULTS_URI": ""},
    )

    assert result.returncode == 0, result.stderr
    assert ingests(lab) == []


def test_a_failed_run_is_neither_published_nor_indexed_and_still_exits_1(lab, tmp_path):
    path = capture(tmp_path)
    result = invoke(lab, str(path), extra={"FAKE_EXIT": "1"})

    assert result.returncode == 1
    assert uploads(lab) == []
    assert ingests(lab) == []


def test_an_ingest_failure_exits_5_with_the_labels_intact_and_the_tarball_published(lab, tmp_path):
    """**Exit 5: published, not indexed** (§7.5), on exit 4's reasoning from spec §12.

    Reusing 1 would tell a batch caller to discard a capture that SUCCEEDED — the labels are on the
    box and in the bucket, and only the index is behind. That is a different instruction from "this
    capture produced nothing".
    """
    path = capture(tmp_path)
    result = invoke(
        lab,
        str(path),
        extra={"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1", "FAKE_INGEST_EXIT": "1"},
    )

    assert result.returncode == 5, result.stderr
    assert uploads(lab), "the tarball was not published"
    # NOT `"5" in result.stderr`: stderr carries a pytest tmp path, which routinely contains a 5,
    # so that assertion passed on what the environment happened to put in the string — the exact
    # accident this file's docstring warns about, and #134's review found the same shape.
    assert "PUBLISHED BUT NOT INDEXED" in result.stderr, result.stderr


def test_exit_5_is_distinct_from_every_other_code_the_wrapper_uses(lab, tmp_path):
    """1 is a dead run, 2 is usage, 5 is published-not-indexed. A caller that cannot tell them
    apart cannot decide whether to re-run the capture or only re-index it."""
    path = capture(tmp_path)
    usage = invoke(lab)
    assert usage.returncode == 2
    dead = invoke(lab, str(path), extra={"FAKE_EXIT": "1"})
    assert dead.returncode == 1
    unindexed = invoke(
        lab,
        str(path),
        extra={"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1", "FAKE_INGEST_EXIT": "1"},
    )
    assert unindexed.returncode == 5


def test_a_run_that_labelled_nothing_is_still_published_and_still_indexed(lab, tmp_path):
    """`docs/spec.md` §13: an all-IPsec capture exits 0 with `labels[]` empty, and `_write_output`
    writes `labels.json` unconditionally on the success path. So a clean capture already publishes,
    and indexing it is how a previously authoritative tier gets cleared.

    Revision 1 wanted to change the publish condition to exit 0 for exactly this; the premise was
    false, and the behaviour it was reaching for is what this pins.
    """
    path = capture(tmp_path)
    result = invoke(lab, str(path), extra={"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1"})

    assert result.returncode == 0, result.stderr
    assert uploads(lab), "an empty-labels run was not published"
    assert ingests(lab), "an empty-labels run was not indexed, so a stale tier stays authoritative"


def test_a_run_with_no_labels_is_declined_by_publish_and_therefore_not_indexed(lab, tmp_path):
    """**Found while wiring the indexing step.** `publish` returns 0 in two different situations:
    it published, and it DECLINED because the run wrote no `labels.json` — a failed run's directory
    exists but is not a result. An `if publish; then index` cannot tell those apart, so the first
    version indexed a run whose tarball was never written, and `flabel-ingest` would have asked the
    bucket for an object that does not exist.

    The wrapper records what it actually published instead of reading the exit code.
    """
    path = capture(tmp_path)
    result = invoke(lab, str(path), extra={"FAKE_MAKE_RUN": "1"})  # no FAKE_WRITE_LABELS

    assert uploads(lab) == [], "a run with no labels.json was published"
    assert ingests(lab) == [], "a run that was never published was indexed"
    assert result.returncode == 0


# --- #171: the indexing seam, exercised as it is actually invoked -------------------------------


def test_the_default_ingest_command_is_reached_through_uv_run_and_not_from_PATH(lab, tmp_path):
    """**The bug #169 shipped, and the test whose absence let it through.**

    `flabel-ingest` is a console script of the optional `db` extra. It lives in the repo's
    uv-managed virtualenv, which is on nobody's `PATH` — measured on this box, `command -v
    flabel-ingest` finds nothing, and neither does `command -v flabel`, which is why the labelling
    call is `uv run flabel`. The wrapper defaulted `$INGEST` to the bare name `flabel-ingest`, so
    every successful run on the box would have exited 5 with `command not found` and left the store
    empty, forever.

    It was invisible because the `lab` fixture sets `FLABEL_RUN_INGEST` to an absolute stub path in
    **every** test: the one value that is wrong in production was the one value never exercised.
    So this test unsets it and puts a recording `uv` first on `PATH`, which is the only arrangement
    that can see the default at all. `test_gcloud_runs_privileged_by_default` already used the
    `__unset__` sentinel for exactly this purpose on another default.
    """
    path = capture(tmp_path)
    fakebin = tmp_path / "fakebin"
    fakebin.mkdir()
    uv_log = tmp_path / "uv-calls"
    fake_uv = fakebin / "uv"
    fake_uv.write_text(f'#!/bin/bash\nprintf "%s\\n" "$*" >> {uv_log}\nexit 0\n')
    fake_uv.chmod(0o755)

    # **`.venv/bin` is stripped, and that is what makes this test faithful.** `uv run pytest` puts
    # the project venv on PATH, so a bare `flabel-ingest` resolves *here* and does not on the box,
    # where the operator invokes the wrapper from a plain shell. Left in, this test would exercise
    # an environment the production one never has — and when the default was sabotaged back to the
    # bare name it ran the real ingest, which reached storage.googleapis.com for a 403. No test in
    # this repo may contact the network (CLAUDE.md), including a failing one.
    clean = [
        d
        for d in os.environ["PATH"].split(os.pathsep)
        if ".venv" not in d and d != os.path.dirname(sys.executable)
    ]
    result = invoke(
        lab,
        str(path),
        extra={
            "FLABEL_RUN_INGEST": "__unset__",
            "PATH": os.pathsep.join([str(fakebin), *clean]),
            "FAKE_MAKE_RUN": "1",
            "FAKE_WRITE_LABELS": "1",
        },
    )

    # Explicit, not incidental: if a bare `flabel-ingest` were still reachable, a regression here
    # would run the REAL ingest and reach storage.googleapis.com. No test may contact the network,
    # including a failing one, and relying on the PATH edit to guarantee that is relying on luck.
    assert shutil.which("flabel-ingest", path=os.pathsep.join(clean)) is None, (
        "flabel-ingest is still on PATH, so a regression here would run the real ingest"
    )

    assert result.returncode == 0, result.stderr
    calls = uv_log.read_text().splitlines() if uv_log.exists() else []
    assert calls, "the default never reached `uv` at all — it was looked up on PATH"
    # `--no-sync` is not decoration: a plain `uv run` re-resolves to the project's DEFAULT
    # dependencies, and `db` is an optional extra, so it would uninstall google-cloud-bigquery out
    # from under the command it is about to run.
    assert calls[0].startswith("run --no-sync flabel-ingest gs://"), calls


def test_the_ingest_override_may_carry_arguments_like_every_other_external_command(lab, tmp_path):
    """`$INGEST` is a COMMAND LINE, not a path, and is left unquoted at the call site exactly as
    `$SUDO`, `$GCLOUD` and `$PUBLISH_SUDO` are.

    The wrapper's own comment promises it is "overridable like every other external command here".
    Quoted, the natural override — `uv run --no-sync flabel-ingest --dataset flabel_scratch` — is
    looked up as one file with that entire absurd name.
    """
    path = capture(tmp_path)
    result = invoke(
        lab,
        str(path),
        extra={
            "FLABEL_RUN_INGEST": f"{lab['FLABEL_RUN_INGEST']} --dataset flabel_scratch",
            "FAKE_MAKE_RUN": "1",
            "FAKE_WRITE_LABELS": "1",
        },
    )

    assert result.returncode == 0, result.stderr
    assert ingests(lab), "an override carrying arguments was not run"


def test_a_missing_gcp_project_names_the_variable_instead_of_a_bare_exit_5(lab, tmp_path):
    """The second, independent cause of exit-5-forever: `flabeldb.client` reads `$GCP_PROJECT` and
    raises without it, and `docs/label-store-provision.md` records that the box does not export it.

    Collapsed into a bare exit 5, a nightly batch over 40 captures produces 40 identical failures
    and never names the one missing variable. The run still succeeded and is still published, so
    the code stays 5 — what changes is that the log says why.
    """
    path = capture(tmp_path)
    result = invoke(
        lab,
        str(path),
        extra={"GCP_PROJECT": "__unset__", "FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1"},
    )

    assert result.returncode == 5
    assert uploads(lab), "the run was not published, so this is not the published-not-indexed path"
    assert ingests(lab) == [], "the ingest was run without the project it requires"
    assert "GCP_PROJECT" in result.stderr, result.stderr


def test_the_ingests_own_exit_code_is_reported_because_the_recovery_differs_by_code(lab, tmp_path):
    """`flabel-ingest` distinguishes 1 (not ingested), 2 (the operator's environment) and 3 (a
    defect in ingest itself). Exit 5 stays ONE code — a batch caller needs one answer — but
    collapsing all three without echoing which told the operator "re-run the ingest" for two codes
    where re-running changes nothing at all.
    """
    path = capture(tmp_path)
    result = invoke(
        lab,
        str(path),
        extra={"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1", "FAKE_INGEST_EXIT": "2"},
    )

    assert result.returncode == 5
    assert "exited 2" in result.stderr, result.stderr
    assert "change NOTHING" in result.stderr, (
        "exit 2 was reported without saying that re-indexing will not help"
    )


def test_a_terminating_signal_reaches_the_indexing_child(lab, tmp_path):
    """**The trap is removed the moment the labelling child is reaped**, and everything the
    indexing step added runs after that. A foreground ingest — a GCS fetch plus several BigQuery
    load jobs — was therefore a child no signal could reach.

    `timeout 3600 flabel-run big.pcap` signals the wrapper PID alone, so the orphaned ingest went
    on to write the store's commit marker minutes after the operator believed the run had stopped.

    The pre-existing `test_a_terminating_signal_is_forwarded_to_the_run` does not cover this: the
    child it watches is the labelling run, and the indexing child does not exist in its timeline.
    "Still green" was true, and was not the same as "covered".
    """
    import signal

    path = capture(tmp_path)
    marker = Path(lab["_ingest_marker"])
    env = {**os.environ, **{k: v for k, v in lab.items() if not k.startswith("_")}}
    env.update({"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1", "FAKE_INGEST_SLEEP": "1"})

    process = subprocess.Popen(
        [str(WRAPPER), str(path)],
        env=env,
        cwd=str(tmp_path),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert wait_for_marker(marker, "started") == "started", "the indexing child never started"

    try:
        process.send_signal(signal.SIGTERM)
        process.wait(timeout=30)
    finally:
        if process.poll() is None:  # a hang must not leave a wrapper and a sleeper behind
            process.kill()
            process.wait(timeout=10)

    assert wait_for_marker(marker, "terminated") == "terminated", (
        "the indexing child was orphaned: the wrapper died and left it writing to the store"
    )

    # **And it must be reported as a signal, not as an exit status.** `wait` returns 128+N when it
    # is interrupted, and `flabel-ingest` only ever returns 0, 1, 2 or 3 — so "flabel-ingest exited
    # 143" sends the operator to file a bug against a tool that did nothing wrong. Found by
    # sabotaging the `-gt 128` branch and watching this test stay green.
    stderr = process.stderr.read() if process.stderr else ""
    assert "exited 143" not in stderr, (
        f"a signal was reported as an exit status flabel-ingest cannot return: {stderr}"
    )
    assert "TERMINATED by signal 15" in stderr, stderr


def test_the_publish_happens_before_the_index(lab, tmp_path):
    """§7.5's headline invariant — archive then index — asserted on ONE ordered log.

    It was previously pinned only indirectly. The publish and index stubs wrote to two separate
    files with no shared sequence, so nothing could distinguish this ordering from its reverse; the
    only thing standing in the way was a test about a declined publish, whose name is about
    something else entirely.
    """
    path = capture(tmp_path)
    result = invoke(lab, str(path), extra={"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1"})

    assert result.returncode == 0, result.stderr
    assert ordering(lab) == ["PUBLISH", "INDEX"], ordering(lab)


def test_a_run_that_failed_but_still_published_keeps_its_own_exit_code(lab, tmp_path):
    """The `[ "$STATUS" = "0" ]` guard inside the not-indexed path, which had no test.

    Not reachable in production today — `_write_output` returns success unconditionally and every
    failure path writes `run.json` and no `labels.json` — so this is a defensive guard rather than
    a live bug. It is worth pinning anyway: exit 1 says "the labelling run failed, discard this
    capture" and exit 5 says "it succeeded, just re-index". Letting 5 overwrite 1 would tell a
    batch caller the opposite of the truth about a run that died.
    """
    path = capture(tmp_path)
    result = invoke(
        lab,
        str(path),
        extra={
            "FAKE_EXIT": "1",
            "FAKE_MAKE_RUN": "1",
            "FAKE_WRITE_LABELS": "1",
            "FAKE_INGEST_EXIT": "1",
        },
    )

    assert result.returncode == 1, "exit 5 overwrote the failed run's own code"


def test_a_run_that_labelled_something_and_one_that_labelled_nothing_are_both_indexed(
    lab, tmp_path
):
    """The empty-`labels[]` case, now that the harness can tell the two apart.

    `FAKE_WRITE_LABELS=1` writes `{"labels":[]}` and any other value writes one label. Before that
    distinction existed, "a run that labelled nothing is still published and still indexed" passed
    exactly the same input as the ordinary published-and-indexed test — a duplicate that read as
    extra coverage.
    """
    empty = capture(tmp_path)
    result = invoke(lab, str(empty), extra={"FAKE_MAKE_RUN": "1", "FAKE_WRITE_LABELS": "1"})
    assert result.returncode == 0, result.stderr
    assert ingests(lab) and ordering(lab) == ["PUBLISH", "INDEX"]


def test_a_config_file_cannot_replace_the_recorded_origin(lab, tmp_path):
    """A line in `flabel.env` — a file the operator edits — must not be able to forge a capture's
    recorded origin. It lands in `run.input.uri`, and CLAUDE.md's top guardrail is that no verdict
    carries an origin that cannot be traced.

    **Renaming it `FLABEL_`-prefixed was the first attempt and it does not work.** The save is
    `export -p`, which lists only EXPORTED variables; a plain assignment is not one, so the name
    never entered the snapshot and never came back out of it. The rename moved the hazard to the
    new name rather than closing it.

    What closes it is deriving the origin *after* the sourcing and the restore, which puts it
    beyond `. "$CONF"` whatever it is called — and still before every reassignment of `$TARGET`,
    which is the property the origin depends on.
    """
    conf = Path(lab["FLABEL_RUN_CONF"])
    # **The name the wrapper actually reads.** The first version of this test wrote the OLD name,
    # `SOURCE_URI=`, which the wrapper had just stopped using — so it passed no matter what the
    # code did, including with the fix reverted. A test that cannot fail is not coverage, and
    # writing one an hour after recording that exact rule is why the review is a gate.
    conf.write_text(conf.read_text() + "FLABEL_RUN_SOURCE_URI=gs://somewhere-else/wrong.pcap\n")

    args = flabel_args_after_gs_run(lab, tmp_path, "gs://bucket/dir/capture.pcap")

    value = args[args.index("--source-uri") + 1]
    assert value == "gs://bucket/dir/capture.pcap", (
        "a line in flabel.env replaced the capture's recorded origin"
    )


def test_the_environment_beats_the_config_file_for_the_project_that_receives_labels(lab, tmp_path):
    """The usage block's heading is "anything you set here WINS over flabel.env", and the
    save/restore that makes it true filtered on `^FLABEL_` only — so it was false for
    `GCP_PROJECT`, the single variable deciding WHICH GCP PROJECT receives label data.

    A one-off run into a scratch project would have gone silently into production instead, which is
    the same bug the wrapper's own comment says the save/restore exists to prevent
    (`FLABEL_SETTLE_SECONDS=15` still settling for the file's 60, and giving no hint it had ignored
    you), reintroduced for the one variable where it is expensive.
    """
    conf = Path(lab["FLABEL_RUN_CONF"])
    conf.write_text(conf.read_text() + "export GCP_PROJECT=the-production-project\n")
    path = capture(tmp_path)

    result = invoke(
        lab,
        str(path),
        extra={
            "GCP_PROJECT": "my-scratch-project",
            "FAKE_MAKE_RUN": "1",
            "FAKE_WRITE_LABELS": "1",
        },
    )

    assert result.returncode == 0, result.stderr
    assert ingests(lab), "the run was never indexed, so this proves nothing about the project"
    assert Path(lab["_ingest_env"]).read_text().strip() == "my-scratch-project", (
        "the config file overrode the project given on the command line, so a scratch run would "
        "have written into production"
    )


def test_an_unprovisioned_box_refuses_to_label(lab, tmp_path):
    """The provisioning script's assertions are only worth what reads their marker.

    `docs/phase-2-replay-box-provision.sh` writes `/var/lib/flabel/.provisioned` last, after it has
    asserted that Suricata, Wireshark and the ja4 commit are all at their pins. Until 2026-08-28
    nothing read it, so every one of those assertions was advisory — a GCE startup script that
    exits 1 gets a log line and the instance boots and serves anyway. This test is the consumer
    that turns them into a gate.

    Exit 2, not 1: the operator's environment is wrong, not the capture (`docs/spec.md` §12). And
    it must refuse **before** doing any work, because the point is that a box with an unpinned
    toolchain must not publish labels at all.
    """
    pcap = capture(tmp_path)
    Path(lab["FLABEL_RUN_PROVISIONED"]).unlink()

    result = invoke(lab, str(pcap))

    assert result.returncode == 2, result.stderr
    assert "has not completed provisioning" in result.stderr
    # Above all: nothing was published and nothing was indexed.
    assert uploads(lab) == []
    assert ingests(lab) == []


def test_a_provisioned_box_is_not_refused(lab, tmp_path):
    """Guard the guard: the gate must be satisfiable, or it would fail every run on the real box.

    Without this, a typo in the marker path would refuse everything and the test above would still
    pass — it only ever removes the file.
    """
    result = invoke(lab, str(capture(tmp_path)))

    assert result.returncode == 0, result.stderr
    assert "has not completed provisioning" not in result.stderr
