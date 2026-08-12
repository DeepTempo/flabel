# Development setup

flabel's tests invoke Zeek, Suricata and `editcap` **for real** — there are no mocks and no
golden-file substitutes, because a mock would encode our assumptions about tool behaviour,
which is exactly what needs verifying (`docs/spec.md` §2). So the toolchain is a hard test
dependency, not an optional extra.

## Python

```sh
uv sync            # dev deps only — flabel itself has zero runtime dependencies
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
pip3 install --user GitPython semantic-version    # or: pipx install zkg
zkg autoconfig
zkg install --version v0.18.8 zeek/foxio/ja4
zeek --parse-only -e '@load packages'             # should exit 0
```

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
| `--require-tool-tests` | The run fails unless at least one `requires_tools` test actually executed. A suite that skipped the whole integration layer must never look like a passing one. |
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
docker run --rm --platform linux/amd64 -v "$PWD":/work -w /work \
  ghcr.io/deeptempo/flabel-toolchain@sha256:<digest> \
  sh -c 'uv sync --dev && uv run pytest -q --require-tool-tests --strict-toolchain'
```

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

1. Edit the `ARG` values in `Dockerfile.toolchain` (or let the apt line move).
2. Push; the `toolchain` workflow builds and prints the new digest and versions.
3. Update `[tool.flabel.toolchain]` and the `container:` digest in `ci.yml` to match.

The apt repositories serve only the newest patch of each release line, so an upstream patch
release eventually breaks the exact pin and CI goes red. That is the intended behaviour: a
toolchain change should be a visible, deliberate commit, never a silent drift.
