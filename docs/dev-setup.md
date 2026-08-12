# Development setup

flabel's tests invoke Zeek, Suricata and `editcap` **for real** — there are no mocks and no
golden-file substitutes, because a mock would encode our assumptions about tool behaviour,
which is exactly what needs verifying (`docs/spec.md` §2). So the toolchain is a hard test
dependency, not an optional extra.

## Python

```sh
uv sync --locked   # dev deps only — flabel itself has zero runtime dependencies
uv run pytest -q
uv run ruff check . && uv run ruff format .
```

## The toolchain

```sh
brew install zeek suricata wireshark
```

`wireshark` supplies `editcap` and `capinfos`. Verify:

```sh
zeek --version        # zeek version 8.0.x
suricata -V           # This is Suricata version 8.0.x RELEASE
editcap --version
```

**`suricata --version` does not exist** — it exits 1 with "unrecognized option". `-V` is the
flag. Worth knowing before you conclude the install is broken.

### The Zeek JA4 package

JA4 is computed by Zeek, and the JA4 value carried on a label is always the Zeek-computed
one, so Zeek is the single authority (`docs/prd.md` §9). That needs the `zeek/foxio/ja4`
package, installed with `zkg`.

Homebrew's `zkg` ships without its Python dependencies, and fails like this:

```
error: zkg failed to import one or more dependencies:
* GitPython  * semantic-version
```

Fix it, then install the package:

```sh
pipx install zkg                                  # see the note below on why not pip --user
zkg autoconfig
zkg install --version v0.18.8 zeek/foxio/ja4
zeek --parse-only -e '@load ja4'                  # should exit 0
zkg list                                          # should show "installed: v0.18.8"
```

`@load ja4` is the same check the tests use, deliberately: if it fails while the package
directory exists, the package is installed somewhere Zeek won't load it, which is the
problem worth knowing about.

**Why `pipx` and not `pip3 install --user`.** `zkg`'s shebang is `#!/usr/bin/env python3`,
which resolves through `PATH`. Under `uv run` the project virtualenv comes first, and a
virtualenv ignores the user site directory — so `pip3 install --user GitPython` fixes `zkg`
in your shell and leaves it broken when a test calls it. `pipx` gives `zkg` its own
interpreter with its own dependencies, immune to whatever `PATH` it is called through. The
CI image solves the same problem differently, by binding `zkg`'s shebang to `/usr/bin/python3`.

If `zkg` still isn't usable, `test_installed_ja4_version_matches_the_pin` skips locally and
says so. That is expected on a laptop; in CI the same condition fails.

> **Licence note.** `zeek/foxio/ja4` is **JA4+** under the **FoxIO License 1.1**
> (non-commercial). It is the approved default while Legal's review proceeds; restricting to
> plain JA4 (BSD 3-Clause) is the documented contingency if Legal declines
> (`docs/prd.md` §13 Q3). Do not treat it as an ordinary open-source dependency.

Until this is installed, `test_zeek_loads_ja4_package` **skips** locally. CI runs with
`--strict-toolchain`, where the same condition is a hard failure — so the container can
never quietly ship without it.

## What CI does differently

CI runs inside the digest-pinned image built by `Dockerfile.toolchain`, and adds two flags:

| Flag | Effect |
| :-- | :-- |
| `--require-tool-tests` | The run fails unless a `requires_tools` test actually ran **and passed**, and fails if any was deselected. An `xfail`ed or mid-body-skipped tool test does not count — a suite that skipped the integration layer must never look like a passing one. |
| `--strict-toolchain` | Tool versions must match `[tool.flabel.toolchain]` in `pyproject.toml` **exactly**, and the JA4 package must be present. |

Locally, neither flag is passed: versions are checked at major.minor only, so a `brew
upgrade` bumping a patch version doesn't turn your suite red.

### Reading a skip correctly

A legitimate local skip names the missing tool:

```
SKIPPED [1] tests/test_toolchain.py: toolchain not installed: suricata — see docs/dev-setup.md
```

If you see that in **CI**, something is wrong with the image, not with the test — CI's
`--require-tool-tests` should have turned it into a failure before it could be mistaken for
success.

## Reproducing CI locally

Take the digest from the `container:` line in `.github/workflows/ci.yml`:

```sh
docker run --rm -v "$PWD":/work -w /work \
  -e UV_PROJECT_ENVIRONMENT=/tmp/venv \
  ghcr.io/deeptempo/flabel-toolchain@sha256:<digest> \
  sh -c 'uv sync --locked --dev && uv run pytest -q --require-tool-tests --strict-toolchain'
```

Don't add `--lf`, `--ff`, or `-k` to that command: with `--require-tool-tests` they deselect
tool tests, and deselection fails the gate on purpose. Drop `--require-tool-tests` when you
want to narrow a run while debugging.

`UV_PROJECT_ENVIRONMENT` matters: without it, `uv sync` replaces your macOS/arm64 `.venv`
with a root-owned linux/amd64 one inside the bind mount, and your next host-side
`uv run pytest` fails confusingly. For the same reason, expect root-owned `__pycache__`
directories if you run this often — add `--user "$(id -u):$(id -g)"` to avoid them.

**The image is amd64-only**, because the openSUSE Build Service repo that packages Zeek
publishes no arm64 build. On Apple silicon it runs under emulation — correct but slow, so
it's for reproducing a CI failure, not for everyday work. Use the brew toolchain for that.

`docker run --rm <image> cat /etc/flabel-toolchain.json` prints the exact versions the image
was built with.

## Version pins

`[tool.flabel.toolchain]` in `pyproject.toml` is the single source of truth. It records what
`Dockerfile.toolchain` installs, which is the reproducibility contract for Goal 2 — identity
across unpinned tool versions means nothing.

To bump the toolchain:

1. Edit the `ARG` values in `Dockerfile.toolchain` — the exact apt versions
   (`SURICATA_PACKAGE_VERSION`, `WIRESHARK_PACKAGE_VERSION`, `ZEEK_PACKAGE_VERSION`) and, for
   JA4, both the tag and the commit it must resolve to.
2. Update `[tool.flabel.toolchain]` in the same commit. The `toolchain` workflow runs the
   suite inside the new image with `--strict-toolchain`, so a Dockerfile bump without a
   matching pin bump fails there rather than silently publishing.
3. Push; the workflow prints the new digest. Put it in `ci.yml`'s `container:` line.

The apt repositories serve only the newest patch of each release line, so an upstream patch
release eventually makes a pinned version unavailable and the **image build** fails. That is
intended: a toolchain change should be a visible, deliberate commit, never a silent drift.

### What pinning does and does not buy you

The pins now install exact versions rather than describing a past build, and the base image,
`uv`, and the JA4 commit are all pinned. But the apt repositories do not keep old patches, so
`Dockerfile.toolchain` will eventually stop being rebuildable, and the pinned environment
survives only as the GHCR image referenced by digest from `ci.yml`. Reproducing a labelling
run older than that image's retention means keeping the image, not rebuilding it. See
`docs/status.yaml` `known_gaps`.

### Why the GHCR package stays private

`ci.yml` pulls the image with `credentials:`, because the package is private. It contains
the JA4+ package, which is FoxIO License 1.1 (non-commercial), and republishing it in a
public image is not a call to make while Legal's review is open. Consequence: a pull request
from a **fork** cannot pull the image and its `test` job will fail. There are no external
contributors today; revisit if that changes.
