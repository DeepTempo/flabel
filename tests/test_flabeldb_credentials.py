"""`client.credentials()` — the identity the store writes as.

**This function had no test of any kind.** Its body could be replaced with `google.auth.default()`
and all 1364 tests still passed, because every other test monkeypatches `client.client` wholesale
and never reaches it. It is spec-label-store invariant 7 and the whole of §7.1, and it is the most
security-relevant line in LS-3's diff, so it is the item to fix even if nothing else gets done.

The invariant, in one line: **the identity is NAMED, never DISCOVERED.** ADC resolves
`$GOOGLE_APPLICATION_CREDENTIALS`, then the user's `application_default_credentials.json`, then the
GCE metadata server. Measured on `fl-replay` 2026-08-20: that second file does not exist for the
invoking user, so `google.auth.default()` would reach the instance service account *today* — which
is exactly why the defect would not have shown up in use. The day anyone runs
`gcloud auth application-default login` on that box, ingestion silently changes identity and writes
rows attributable to a person rather than the instance, and every row already written becomes
ambiguous about who wrote it.

These tests are pure: they monkeypatch the two credential sources and assert which one was reached.
No network, no metadata server, so they run in CI — which is the point, because the live tests do
not. `test_flabeldb_live.py` carries the one that checks the real identity on the box.
"""

from __future__ import annotations

import pytest

needs_client = pytest.mark.skipif(
    __import__("importlib.util", fromlist=["util"]).find_spec("google.cloud.bigquery") is None,
    reason="the db extra is not installed — `uv sync --extra db` (spec-label-store §7.5)",
)


@pytest.fixture
def watched(monkeypatch):
    """Both credential sources, replaced by recorders. Neither touches a network."""
    import google.auth
    import google.auth.compute_engine

    calls: dict[str, int] = {"adc": 0, "instance": 0}
    adc_sentinel = object()

    def fake_default(*args, **kwargs):
        calls["adc"] += 1
        return adc_sentinel, "a-project"

    class FakeInstanceCredentials:
        def __init__(self, *args, **kwargs):
            calls["instance"] += 1

    monkeypatch.setattr(google.auth, "default", fake_default)
    monkeypatch.setattr(google.auth.compute_engine, "Credentials", FakeInstanceCredentials)
    return calls, adc_sentinel, FakeInstanceCredentials


@needs_client
def test_credentials_are_the_instance_identity_and_never_adc(watched):
    """Invariant 7. The defect this replaces was `google.auth.default()` passing every test."""
    from flabeldb import client

    calls, _adc, FakeInstance = watched
    found = client.credentials()

    assert isinstance(found, FakeInstance), "the instance identity was not what got constructed"
    assert calls["instance"] == 1
    assert calls["adc"] == 0, (
        "credentials() went through ADC. The identity must be NAMED, not discovered — ADC would "
        "silently switch to a human's credential the day someone runs "
        "`gcloud auth application-default login` on the box."
    )


@needs_client
def test_the_default_path_ignores_google_application_credentials(watched, monkeypatch, tmp_path):
    """The first thing ADC consults must have no effect on the default path.

    A key file on `$GOOGLE_APPLICATION_CREDENTIALS` is the easiest way to change the store's
    identity by accident, and it is first in ADC's order.
    """
    from flabeldb import client

    key = tmp_path / "someone-elses-key.json"
    key.write_text('{"type": "service_account"}', encoding="utf-8")
    monkeypatch.setenv("GOOGLE_APPLICATION_CREDENTIALS", str(key))

    calls, _adc, FakeInstance = watched
    assert isinstance(client.credentials(), FakeInstance)
    assert calls["adc"] == 0


@needs_client
def test_local_adc_is_the_documented_escape_and_is_the_only_way_to_reach_adc(watched):
    """A flag, not a fallback: a fallback would restore the ambiguity the flag exists to avoid."""
    from flabeldb import client

    calls, adc_sentinel, _FakeInstance = watched
    found = client.credentials(local_adc=True)

    assert found is adc_sentinel, "local_adc must return ADC's credential, not its (creds, project)"
    assert calls["adc"] == 1
    assert calls["instance"] == 0


@needs_client
def test_local_adc_must_be_asked_for_by_keyword():
    """So no positional call site can flip the store's identity by accident."""
    from flabeldb import client

    with pytest.raises(TypeError):
        client.credentials(True)


@needs_client
def test_a_missing_metadata_server_is_not_quietly_replaced_by_adc(monkeypatch):
    """There is no fallback. If the instance identity cannot be built, that must surface."""
    import google.auth
    import google.auth.compute_engine

    from flabeldb import client

    def boom(*args, **kwargs):
        raise RuntimeError("no metadata server")

    reached_adc = []
    monkeypatch.setattr(google.auth.compute_engine, "Credentials", boom)
    monkeypatch.setattr(
        google.auth, "default", lambda *a, **k: reached_adc.append(1) or (object(), "p")
    )

    with pytest.raises(RuntimeError, match="no metadata server"):
        client.credentials()
    assert reached_adc == [], "a failed instance identity fell back to ADC"


# --- and that the credential actually reaches the client ---------------------------------------


@needs_client
def test_the_client_is_built_with_those_credentials_and_the_pinned_location(watched, monkeypatch):
    """`location=LOCATION` could be deleted with the suite green, because the only test asserted
    the CONSTANT rather than that it reaches a client. So assert the call, not the constant."""
    from flabeldb import client

    recorded: dict = {}

    class FakeClient:
        def __init__(self, **kwargs):
            recorded.update(kwargs)

    monkeypatch.setattr(client, "_bigquery", lambda: type("Module", (), {"Client": FakeClient}))
    _calls, _adc, FakeInstance = watched

    client.client(project="a-project")

    assert recorded["project"] == "a-project"
    assert isinstance(recorded["credentials"], FakeInstance), (
        "the client was built with something other than the instance identity"
    )
    assert recorded["location"] == client.LOCATION == "us-central1", (
        "the dataset location must reach the client: the results bucket is US-CENTRAL1 regional, a "
        "load job needs a compatible dataset location, and job ids are namespaced by location"
    )


@needs_client
def test_local_adc_reaches_the_client_too(watched, monkeypatch):
    from flabeldb import client

    recorded: dict = {}
    monkeypatch.setattr(
        client,
        "_bigquery",
        lambda: type("Module", (), {"Client": lambda **kw: recorded.update(kw)}),
    )
    _calls, adc_sentinel, _FakeInstance = watched

    client.client(project="a-project", local_adc=True)
    assert recorded["credentials"] is adc_sentinel
